package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

const maxDataExportSourceRecords = 1_000_000

// QueryDataExport reads one consistent repository snapshot. Filtering is
// performed over domain records so SQLite and PostgreSQL have identical range
// and null semantics.
func (r *Repository) QueryDataExport(ctx context.Context, filter domain.DataExportFilter) (domain.DataExportSnapshot, error) {
	var snapshot domain.DataExportSnapshot
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return snapshot, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, licenceSelect+` ORDER BY created_at,licence_id`)
	if err != nil {
		return snapshot, err
	}
	scope := make(map[string]struct{})
	for rows.Next() {
		licence, scanErr := scanLicence(rows)
		if scanErr != nil {
			rows.Close()
			return snapshot, scanErr
		}
		if !licenceMatchesScope(licence, filter) {
			continue
		}
		scope[licence.LicenceID] = struct{}{}
		if len(scope) > maxDataExportSourceRecords {
			rows.Close()
			return snapshot, fmt.Errorf("data export source exceeds %d records", maxDataExportSourceRecords)
		}
		if inExportRange(licence.CreatedAt, filter.From, filter.To) {
			snapshot.Licences = append(snapshot.Licences, licence)
		}
	}
	if err = rows.Close(); err != nil {
		return snapshot, err
	}

	activationIDs := make(map[string]struct{})
	codeIDs := make(map[string]struct{})
	rows, err = tx.QueryContext(ctx, activationSelect+` ORDER BY activated_at,activation_id`)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		record, scanErr := scanActivation(rows)
		if scanErr != nil {
			rows.Close()
			return snapshot, scanErr
		}
		if _, selected := scope[record.LicenceID]; !selected {
			continue
		}
		activationIDs[record.ActivationID] = struct{}{}
		codeIDs[record.ActivationCodeID] = struct{}{}
		if inExportRange(record.ActivatedAt, filter.From, filter.To) {
			snapshot.Activations = append(snapshot.Activations, record)
			if exportRecordCount(snapshot) > maxDataExportSourceRecords {
				rows.Close()
				return snapshot, fmt.Errorf("data export exceeds %d records", maxDataExportSourceRecords)
			}
		}
	}
	if err = rows.Close(); err != nil {
		return snapshot, err
	}

	rows, err = tx.QueryContext(ctx, `SELECT revocation_id,licence_id,reason_code,reason_text,revoked_at FROM revocations ORDER BY revoked_at,revocation_id`)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		var revocation domain.Revocation
		var reason sql.NullString
		var occurred string
		if err = rows.Scan(&revocation.RevocationID, &revocation.LicenceID, &revocation.ReasonCode, &reason, &occurred); err != nil {
			rows.Close()
			return snapshot, err
		}
		if _, selected := scope[revocation.LicenceID]; selected && inExportRange(parse(occurred), filter.From, filter.To) {
			revocation.ReasonText = reason.String
			revocation.RevokedAt = parse(occurred)
			snapshot.Revocations = append(snapshot.Revocations, revocation)
			if exportRecordCount(snapshot) > maxDataExportSourceRecords {
				rows.Close()
				return snapshot, fmt.Errorf("data export exceeds %d records", maxDataExportSourceRecords)
			}
		}
	}
	if err = rows.Close(); err != nil {
		return snapshot, err
	}

	order := "rowid"
	if r.db.dialect == dialectPostgres {
		order = "audit_sequence"
	}
	rows, err = tx.QueryContext(ctx, `SELECT event_id,occurred_at,actor_type,actor_ref,event_type,aggregate_type,aggregate_id,request_id,event_json,previous_event_hash,event_hash FROM audit_events ORDER BY `+order)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		event, scanErr := scanDataExportAudit(rows)
		if scanErr != nil {
			rows.Close()
			return snapshot, scanErr
		}
		if inExportRange(event.OccurredAt, filter.From, filter.To) && auditRelevant(event, scope, activationIDs, codeIDs) {
			snapshot.AuditEvents = append(snapshot.AuditEvents, event)
		}
		if exportRecordCount(snapshot) > maxDataExportSourceRecords {
			rows.Close()
			return snapshot, fmt.Errorf("data export exceeds %d records", maxDataExportSourceRecords)
		}
	}
	if err = rows.Close(); err != nil {
		return snapshot, err
	}
	if err = tx.Commit(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func exportRecordCount(snapshot domain.DataExportSnapshot) int {
	return len(snapshot.Licences) + len(snapshot.Activations) + len(snapshot.Revocations) + len(snapshot.AuditEvents)
}

func licenceMatchesScope(licence domain.LicenceRecord, filter domain.DataExportFilter) bool {
	return (filter.ProductID == "" || licence.ProductID == filter.ProductID) &&
		(filter.LicenceID == "" || licence.LicenceID == filter.LicenceID) &&
		(filter.CustomerRef == "" || licence.CustomerRef == filter.CustomerRef) &&
		(filter.Status == "" || licence.Status == filter.Status)
}

func inExportRange(value time.Time, from, to *time.Time) bool {
	return (from == nil || !value.Before(*from)) && (to == nil || value.Before(*to))
}

func scanDataExportAudit(s scanner) (domain.AuditEvent, error) {
	var event domain.AuditEvent
	var occurred, details string
	var actor, aggregateType, aggregateID, requestID sql.NullString
	err := s.Scan(&event.EventID, &occurred, &event.ActorType, &actor, &event.EventType, &aggregateType, &aggregateID, &requestID, &details, &event.PreviousHash, &event.Hash)
	if err != nil {
		return event, err
	}
	event.OccurredAt = parse(occurred)
	event.ActorRef = actor.String
	event.AggregateType = aggregateType.String
	event.AggregateID = aggregateID.String
	event.RequestID = requestID.String
	event.Event = json.RawMessage(details)
	return event, nil
}

func auditRelevant(event domain.AuditEvent, licences, activations, codes map[string]struct{}) bool {
	if _, ok := licences[event.AggregateID]; ok {
		return true
	}
	if _, ok := activations[event.AggregateID]; ok {
		return true
	}
	if _, ok := codes[event.AggregateID]; ok {
		return true
	}
	var details any
	if json.Unmarshal(event.Event, &details) != nil {
		return false
	}
	return containsSelectedLicence(details, licences)
}

func containsSelectedLicence(value any, selected map[string]struct{}) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if strings.EqualFold(key, "licence_id") {
				if id, ok := child.(string); ok {
					_, found := selected[id]
					if found {
						return true
					}
				}
			}
			if containsSelectedLicence(child, selected) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSelectedLicence(child, selected) {
				return true
			}
		}
	}
	return false
}
