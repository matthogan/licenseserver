package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/exportdata"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/failurepoint"
	"github.com/matthogan/licenceserver/internal/retention"
)

const exportProofMaxAge = 24 * time.Hour

type deletionSelection struct {
	licences    map[string]domain.LicenceRecord
	parents     map[string]domain.LicenceRecord
	activations map[string]domain.ActivationRecord
	policies    map[string]domain.RetentionPolicy
}

func (r *Repository) RecordDataExportProof(ctx context.Context, proof domain.DataExportProof, audit domain.AuditEvent) error {
	if len(proof.SHA256) != 64 || proof.CreatedAt.IsZero() || !json.Valid(proof.FilterJSON) || !json.Valid(proof.RecordCounts) {
		return domain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO data_export_proofs(sha256,created_at,filters_json,record_counts_json) VALUES(?,?,?,?) ON CONFLICT(sha256) DO NOTHING`, proof.SHA256, stamp(proof.CreatedAt), string(proof.FilterJSON), string(proof.RecordCounts)); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) SetRetentionPolicy(ctx context.Context, policy domain.RetentionPolicy, audit domain.AuditEvent) (domain.RetentionPolicy, error) {
	if retention.ValidatePolicy(policy) != nil {
		return domain.RetentionPolicy{}, domain.ErrInvalid
	}
	policy.SchemaVersion = domain.RetentionPolicySchemaVersion
	policy.Active = true
	policy.CreatedAt = policy.CreatedAt.UTC()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.RetentionPolicy{}, err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM retention_policies WHERE category=?`, policy.Category).Scan(&policy.Version); err != nil {
		return domain.RetentionPolicy{}, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE retention_policies SET is_current=0 WHERE category=? AND is_current=1`, policy.Category); err != nil {
		return domain.RetentionPolicy{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO retention_policies(category,version,schema_version,retain_for_seconds,require_export,is_current,created_at,created_by) VALUES(?,?,?,?,?,1,?,?)`, policy.Category, policy.Version, policy.SchemaVersion, policy.RetainForSeconds, boolInt(policy.RequireExport), stamp(policy.CreatedAt), policy.CreatedBy); err != nil {
		return domain.RetentionPolicy{}, classify(err)
	}
	var auditDetails map[string]any
	if json.Unmarshal(audit.Event, &auditDetails) == nil {
		auditDetails["schema_version"], auditDetails["policy_version"] = policy.SchemaVersion, policy.Version
		audit.Event, _ = json.Marshal(auditDetails)
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return domain.RetentionPolicy{}, err
	}
	if err = tx.Commit(); err != nil {
		return domain.RetentionPolicy{}, err
	}
	return policy, nil
}

func (r *Repository) ListRetentionPolicies(ctx context.Context) ([]domain.RetentionPolicy, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT category,version,schema_version,retain_for_seconds,require_export,is_current,created_at,created_by FROM retention_policies ORDER BY category,version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.RetentionPolicy
	for rows.Next() {
		var policy domain.RetentionPolicy
		var requireExport, active int
		var created string
		if err = rows.Scan(&policy.Category, &policy.Version, &policy.SchemaVersion, &policy.RetainForSeconds, &requireExport, &active, &created, &policy.CreatedBy); err != nil {
			return nil, err
		}
		policy.RequireExport = requireExport != 0
		policy.Active = active != 0
		policy.CreatedAt = parse(created)
		result = append(result, policy)
	}
	return result, rows.Err()
}

func (r *Repository) CreateLegalHold(ctx context.Context, hold domain.LegalHold, audit domain.AuditEvent) error {
	if hold.HoldID == "" || retention.ValidateScope(hold.Scope) != nil || strings.TrimSpace(hold.Reason) == "" || len(hold.Reason) > 512 || hold.CreatedAt.IsZero() || strings.TrimSpace(hold.CreatedBy) == "" {
		return domain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO legal_holds(hold_id,product_id,licence_id,customer_ref,reason,created_at,created_by) VALUES(?,?,?,?,?,?,?)`, hold.HoldID, nullString(hold.Scope.ProductID), nullString(hold.Scope.LicenceID), nullString(hold.Scope.CustomerRef), hold.Reason, stamp(hold.CreatedAt), hold.CreatedBy); err != nil {
		return classify(err)
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) ReleaseLegalHold(ctx context.Context, id, actor string, at time.Time, audit domain.AuditEvent) (domain.LegalHold, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.LegalHold{}, err
	}
	defer tx.Rollback()
	hold, err := scanLegalHold(tx.QueryRowContext(ctx, `SELECT hold_id,product_id,licence_id,customer_ref,reason,created_at,created_by,released_at,released_by FROM legal_holds WHERE hold_id=?`, id))
	if err != nil {
		return domain.LegalHold{}, classify(err)
	}
	if hold.ReleasedAt != nil {
		return domain.LegalHold{}, domain.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE legal_holds SET released_at=?,released_by=? WHERE hold_id=? AND released_at IS NULL`, stamp(at), actor, id); err != nil {
		return domain.LegalHold{}, err
	}
	hold.ReleasedAt, hold.ReleasedBy = &at, actor
	if err = appendAudit(ctx, tx, audit); err != nil {
		return domain.LegalHold{}, err
	}
	if err = tx.Commit(); err != nil {
		return domain.LegalHold{}, err
	}
	return hold, nil
}

func (r *Repository) ListLegalHolds(ctx context.Context, activeOnly bool) ([]domain.LegalHold, error) {
	query := `SELECT hold_id,product_id,licence_id,customer_ref,reason,created_at,created_by,released_at,released_by FROM legal_holds`
	if activeOnly {
		query += ` WHERE released_at IS NULL`
	}
	query += ` ORDER BY created_at,hold_id`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.LegalHold
	for rows.Next() {
		hold, scanErr := scanLegalHold(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		result = append(result, hold)
	}
	return result, rows.Err()
}

func scanLegalHold(row scanner) (domain.LegalHold, error) {
	var hold domain.LegalHold
	var product, licence, customer, releasedAt, releasedBy sql.NullString
	var created string
	err := row.Scan(&hold.HoldID, &product, &licence, &customer, &hold.Reason, &created, &hold.CreatedBy, &releasedAt, &releasedBy)
	hold.Scope = domain.DataScope{ProductID: product.String, LicenceID: licence.String, CustomerRef: customer.String}
	hold.CreatedAt = parse(created)
	if releasedAt.Valid {
		value := parse(releasedAt.String)
		hold.ReleasedAt = &value
	}
	hold.ReleasedBy = releasedBy.String
	return hold, err
}

func (r *Repository) PlanDataDeletion(ctx context.Context, request domain.DataDeletionRequest, now time.Time) (domain.DataDeletionPlan, error) {
	if retention.ValidateDeletion(request) != nil || now.IsZero() {
		return domain.DataDeletionPlan{}, domain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return domain.DataDeletionPlan{}, err
	}
	defer tx.Rollback()
	plan, _, err := r.buildDeletionPlan(ctx, tx, "manual", request.Scope, request.RequireExport, request.ExportSHA256, request.AcknowledgeImmutable, now)
	if err != nil {
		return plan, err
	}
	return plan, tx.Commit()
}

func (r *Repository) DeleteData(ctx context.Context, request domain.DataDeletionRequest, now time.Time, audit domain.AuditEvent) (domain.DataDeletionPlan, error) {
	if retention.ValidateDeletion(request) != nil || now.IsZero() {
		return domain.DataDeletionPlan{}, domain.ErrInvalid
	}
	return r.executeDeletion(ctx, "manual", request.Scope, request.RequireExport, request.ExportSHA256, request.AcknowledgeImmutable, request.Reason, now, audit)
}

func (r *Repository) PlanRetention(ctx context.Context, request domain.RetentionApplyRequest, now time.Time) (domain.DataDeletionPlan, error) {
	if now.IsZero() || !retention.ValidExportSHA256(request.ExportSHA256) {
		return domain.DataDeletionPlan{}, domain.ErrInvalid
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return domain.DataDeletionPlan{}, err
	}
	defer tx.Rollback()
	plan, _, err := r.buildDeletionPlan(ctx, tx, "retention", domain.DataScope{}, false, request.ExportSHA256, request.AcknowledgeImmutable, now)
	if err != nil {
		return plan, err
	}
	return plan, tx.Commit()
}

func (r *Repository) ApplyRetention(ctx context.Context, request domain.RetentionApplyRequest, now time.Time, audit domain.AuditEvent) (domain.DataDeletionPlan, error) {
	if strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 512 || now.IsZero() || !retention.ValidExportSHA256(request.ExportSHA256) {
		return domain.DataDeletionPlan{}, domain.ErrInvalid
	}
	return r.executeDeletion(ctx, "retention", domain.DataScope{}, false, request.ExportSHA256, request.AcknowledgeImmutable, request.Reason, now, audit)
}

func (r *Repository) executeDeletion(ctx context.Context, mode string, scope domain.DataScope, requireExport bool, exportSHA string, acknowledge bool, reason string, now time.Time, audit domain.AuditEvent) (domain.DataDeletionPlan, error) {
	if err := failurepoint.Check(ctx, failurepoint.BeforeDBTransaction); err != nil {
		return domain.DataDeletionPlan{}, err
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return domain.DataDeletionPlan{}, err
	}
	defer tx.Rollback()
	plan, selection, err := r.buildDeletionPlan(ctx, tx, mode, scope, requireExport, exportSHA, acknowledge, now)
	if err != nil {
		return plan, err
	}
	if !plan.Executable {
		return plan, domain.ErrRetentionBlocked
	}
	if err = r.deleteSelection(ctx, tx, &plan, selection, reason, now); err != nil {
		return plan, err
	}
	audit.Event = auditDeletionDetails(audit.Event, plan, reason)
	if err = appendAudit(ctx, tx, audit); err != nil {
		return plan, err
	}
	if err = tx.Commit(); err != nil {
		return plan, err
	}
	if err = failurepoint.Check(ctx, failurepoint.AfterDBCommit); err != nil {
		return plan, err
	}
	return plan, nil
}

func (r *Repository) buildDeletionPlan(ctx context.Context, tx *transaction, mode string, scope domain.DataScope, requireExport bool, exportSHA string, acknowledge bool, now time.Time) (domain.DataDeletionPlan, deletionSelection, error) {
	plan := domain.DataDeletionPlan{SchemaVersion: 1, GeneratedAt: now.UTC(), Mode: mode, Scope: scope, PolicyVersions: map[string]int{}, ImmutableResidue: []string{"tamper-evident audit chain", "immutable licence archive objects", "historical Litestream/S3 backup generations"}, ImmutableAcknowledged: acknowledge, ExportProofSHA256: exportSHA}
	selection := deletionSelection{licences: map[string]domain.LicenceRecord{}, parents: map[string]domain.LicenceRecord{}, activations: map[string]domain.ActivationRecord{}, policies: map[string]domain.RetentionPolicy{}}
	policies, err := activePoliciesTx(ctx, tx)
	if err != nil {
		return plan, selection, err
	}
	for _, policy := range policies {
		selection.policies[policy.Category] = policy
		plan.Categories = append(plan.Categories, policy.Category)
		plan.PolicyVersions[policy.Category] = policy.Version
		if mode == "retention" && policy.RequireExport {
			requireExport = true
		}
	}
	if mode == "retention" && len(policies) == 0 {
		plan.Blockers = append(plan.Blockers, domain.DeletionBlocker{Code: "no_active_policy", Detail: "no active retention policies are configured"})
	}
	revokedAt, err := revocationTimes(ctx, tx)
	if err != nil {
		return plan, selection, err
	}
	rows, err := tx.QueryContext(ctx, licenceSelect+` ORDER BY created_at,licence_id`)
	if err != nil {
		return plan, selection, err
	}
	for rows.Next() {
		licence, scanErr := scanLicence(rows)
		if scanErr != nil {
			rows.Close()
			return plan, selection, scanErr
		}
		selected := false
		if mode == "manual" {
			selected = scopeMatchesLicence(scope, licence)
			if selected && !safeManualLicence(licence, now) {
				plan.Blockers = append(plan.Blockers, domain.DeletionBlocker{Code: "active_licence", Detail: "licence " + licence.LicenceID + " is active or an unexpired trial"})
			}
		} else {
			selected = retainedLicenceEligible(licence, revokedAt[licence.LicenceID], policies, now)
		}
		if selected {
			selection.licences[licence.LicenceID] = licence
		}
		selection.parents[licence.LicenceID] = licence
	}
	if err = rows.Close(); err != nil {
		return plan, selection, err
	}
	rows, err = tx.QueryContext(ctx, activationSelect+` ORDER BY activated_at,activation_id`)
	if err != nil {
		return plan, selection, err
	}
	for rows.Next() {
		activation, scanErr := scanActivation(rows)
		if scanErr != nil {
			rows.Close()
			return plan, selection, scanErr
		}
		if _, licenceSelected := selection.licences[activation.LicenceID]; licenceSelected {
			selection.activations[activation.ActivationID] = activation
			continue
		}
		if mode == "retention" && activation.RevokedAt != nil {
			if policy, ok := selection.policies[domain.RetentionRevokedActivations]; ok && !activation.RevokedAt.After(now.Add(-time.Duration(policy.RetainForSeconds)*time.Second)) {
				selection.activations[activation.ActivationID] = activation
			}
		}
	}
	if err = rows.Close(); err != nil {
		return plan, selection, err
	}
	if len(selection.licences) == 0 && len(selection.activations) == 0 && len(plan.Blockers) == 0 {
		plan.Blockers = append(plan.Blockers, domain.DeletionBlocker{Code: "no_matching_records", Detail: "no records are eligible for deletion"})
	}
	if err = r.addLegalHoldBlockers(ctx, tx, &plan, selection); err != nil {
		return plan, selection, err
	}
	if len(selection.licences)+len(selection.activations) > 0 && !acknowledge {
		plan.Blockers = append(plan.Blockers, domain.DeletionBlocker{Code: "immutable_residue_not_acknowledged", Detail: "audit, archive and backup copies remain until their independent policies expire"})
	}
	if requireExport && !r.exportProofCovers(ctx, tx, exportSHA, selection, now) {
		plan.Blockers = append(plan.Blockers, domain.DeletionBlocker{Code: "verified_export_required", Detail: "a matching server-verified export from the previous 24 hours is required"})
	}
	if err = r.populateCounts(ctx, tx, &plan, selection); err != nil {
		return plan, selection, err
	}
	for id := range selection.licences {
		if len(plan.CandidateLicences) < 100 {
			plan.CandidateLicences = append(plan.CandidateLicences, id)
		}
	}
	sort.Strings(plan.CandidateLicences)
	sort.Strings(plan.Categories)
	plan.Executable = len(plan.Blockers) == 0
	return plan, selection, nil
}

func activePoliciesTx(ctx context.Context, tx *transaction) ([]domain.RetentionPolicy, error) {
	rows, err := tx.QueryContext(ctx, `SELECT category,version,schema_version,retain_for_seconds,require_export,created_at,created_by FROM retention_policies WHERE is_current=1 ORDER BY category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.RetentionPolicy
	for rows.Next() {
		var policy domain.RetentionPolicy
		var required int
		var created string
		if err = rows.Scan(&policy.Category, &policy.Version, &policy.SchemaVersion, &policy.RetainForSeconds, &required, &created, &policy.CreatedBy); err != nil {
			return nil, err
		}
		policy.RequireExport, policy.CreatedAt = required != 0, parse(created)
		policy.Active = true
		result = append(result, policy)
	}
	return result, rows.Err()
}

func revocationTimes(ctx context.Context, tx *transaction) (map[string]time.Time, error) {
	rows, err := tx.QueryContext(ctx, `SELECT licence_id,revoked_at FROM revocations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]time.Time{}
	for rows.Next() {
		var id, at string
		if err = rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		result[id] = parse(at)
	}
	return result, rows.Err()
}

func retainedLicenceEligible(licence domain.LicenceRecord, revoked time.Time, policies []domain.RetentionPolicy, now time.Time) bool {
	for _, policy := range policies {
		cutoff := now.Add(-time.Duration(policy.RetainForSeconds) * time.Second)
		switch policy.Category {
		case domain.RetentionExpiredTrials:
			if licence.LicenceType == "trial" && licence.ExpiresAt != nil && !licence.ExpiresAt.After(cutoff) {
				return true
			}
		case domain.RetentionRevokedLicences:
			if licence.LicenceType != "trial" && licence.Status == "revoked" && !revoked.IsZero() && !revoked.After(cutoff) {
				return true
			}
		}
	}
	return false
}

func safeManualLicence(licence domain.LicenceRecord, now time.Time) bool {
	return licence.Status == "revoked" || licence.LicenceType == "trial" && licence.ExpiresAt != nil && !licence.ExpiresAt.After(now)
}

func scopeMatchesLicence(scope domain.DataScope, licence domain.LicenceRecord) bool {
	return (scope.ProductID == "" || scope.ProductID == licence.ProductID) && (scope.LicenceID == "" || scope.LicenceID == licence.LicenceID) && (scope.CustomerRef == "" || scope.CustomerRef == licence.CustomerRef)
}

func (r *Repository) addLegalHoldBlockers(ctx context.Context, tx *transaction, plan *domain.DataDeletionPlan, selection deletionSelection) error {
	rows, err := tx.QueryContext(ctx, `SELECT hold_id,product_id,licence_id,customer_ref,reason,created_at,created_by,released_at,released_by FROM legal_holds WHERE released_at IS NULL ORDER BY created_at,hold_id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		hold, scanErr := scanLegalHold(rows)
		if scanErr != nil {
			return scanErr
		}
		matched := false
		for _, licence := range selection.licences {
			if scopeMatchesLicence(hold.Scope, licence) {
				matched = true
				break
			}
		}
		if !matched {
			for _, activation := range selection.activations {
				if licence, exists := selection.parents[activation.LicenceID]; exists && scopeMatchesLicence(hold.Scope, licence) {
					matched = true
					break
				}
			}
		}
		if matched {
			plan.Blockers = append(plan.Blockers, domain.DeletionBlocker{Code: "legal_hold", Detail: "an active legal hold covers selected records", HoldID: hold.HoldID})
		}
	}
	return rows.Err()
}

func (r *Repository) exportProofCovers(ctx context.Context, tx *transaction, sha string, selection deletionSelection, now time.Time) bool {
	if sha == "" {
		return false
	}
	var created, filters string
	if err := tx.QueryRowContext(ctx, `SELECT created_at,filters_json FROM data_export_proofs WHERE sha256=?`, sha).Scan(&created, &filters); err != nil || parse(created).Before(now.Add(-exportProofMaxAge)) || parse(created).After(now.Add(time.Minute)) {
		return false
	}
	var filter exportdata.Filter
	if json.Unmarshal([]byte(filters), &filter) != nil || filter.From != nil || filter.To != nil {
		return false
	}
	for _, licence := range selection.licences {
		if filter.ProductID != "" && filter.ProductID != licence.ProductID || filter.LicenceID != "" && filter.LicenceID != licence.LicenceID || filter.CustomerRef != "" && filter.CustomerRef != licence.CustomerRef || filter.Status != "" && filter.Status != licence.Status {
			return false
		}
	}
	for _, activation := range selection.activations {
		licence, exists := selection.parents[activation.LicenceID]
		if !exists || filter.ProductID != "" && filter.ProductID != licence.ProductID || filter.LicenceID != "" && filter.LicenceID != licence.LicenceID || filter.CustomerRef != "" && filter.CustomerRef != licence.CustomerRef || filter.Status != "" && filter.Status != licence.Status {
			return false
		}
	}
	return true
}

func (r *Repository) populateCounts(ctx context.Context, tx *transaction, plan *domain.DataDeletionPlan, selection deletionSelection) error {
	plan.Counts.Licences = len(selection.licences)
	plan.Counts.Activations = len(selection.activations)
	for id := range selection.licences {
		for query, destination := range map[string]*int{
			`SELECT COUNT(*) FROM trials WHERE licence_id=?`:           &plan.Counts.Trials,
			`SELECT COUNT(*) FROM activation_codes WHERE licence_id=?`: &plan.Counts.ActivationCodes,
			`SELECT COUNT(*) FROM revocations WHERE licence_id=?`:      &plan.Counts.Revocations,
		} {
			var count int
			if err := tx.QueryRowContext(ctx, query, id).Scan(&count); err != nil {
				return err
			}
			*destination += count
		}
	}
	plan.Counts.Tombstones = len(selection.licences)
	for _, activation := range selection.activations {
		if _, parentDeleted := selection.licences[activation.LicenceID]; !parentDeleted {
			plan.Counts.Tombstones++
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_json FROM archive_outbox`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var payload string
		if err = rows.Scan(&payload); err != nil {
			rows.Close()
			return err
		}
		var event domain.ArchiveEvent
		if json.Unmarshal([]byte(payload), &event) == nil {
			if _, selected := selection.licences[event.LicenceID]; selected {
				plan.Counts.OutboxEvents++
			}
		}
	}
	if err = rows.Close(); err != nil {
		return err
	}
	return nil
}

func (r *Repository) deleteSelection(ctx context.Context, tx *transaction, plan *domain.DataDeletionPlan, selection deletionSelection, reason string, now time.Time) error {
	activationIDs := make([]string, 0, len(selection.activations))
	for id := range selection.activations {
		activationIDs = append(activationIDs, id)
	}
	licenceIDs := make([]string, 0, len(selection.licences))
	for id := range selection.licences {
		licenceIDs = append(licenceIDs, id)
	}
	sort.Strings(activationIDs)
	sort.Strings(licenceIDs)
	reasonCode := "manual_deletion"
	if plan.Mode == "retention" {
		reasonCode = "retention_policy"
	}
	for _, id := range activationIDs {
		if _, licenceSelected := selection.licences[selection.activations[id].LicenceID]; licenceSelected {
			continue
		}
		policyVersion := 0
		if plan.Mode == "retention" {
			policyVersion = plan.PolicyVersions[domain.RetentionRevokedActivations]
		}
		tombstone := domain.SuppressionTombstone{SchemaVersion: 1, SubjectType: "activation", SubjectDigest: retention.Digest("activation", id), DeletedAt: now, ReasonCode: reasonCode, PolicyVersion: policyVersion}
		if err := insertTombstoneAndOutbox(ctx, tx, tombstone); err != nil {
			return err
		}
		if err := failurepoint.Check(ctx, failurepoint.DuringDBTransaction); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM activation_records WHERE activation_id=?`, id); err != nil {
			return err
		}
	}
	for _, id := range licenceIDs {
		policyVersion := 0
		if plan.Mode == "retention" {
			category := domain.RetentionRevokedLicences
			if selection.licences[id].LicenceType == "trial" {
				category = domain.RetentionExpiredTrials
			}
			policyVersion = plan.PolicyVersions[category]
		}
		tombstone := domain.SuppressionTombstone{SchemaVersion: 1, SubjectType: "licence", SubjectDigest: retention.Digest("licence", id), DeletedAt: now, ReasonCode: reasonCode, PolicyVersion: policyVersion}
		if err := insertTombstoneAndOutbox(ctx, tx, tombstone); err != nil {
			return err
		}
		if err := failurepoint.Check(ctx, failurepoint.DuringDBTransaction); err != nil {
			return err
		}
		for _, query := range []string{`DELETE FROM activation_records WHERE licence_id=?`, `DELETE FROM activation_codes WHERE licence_id=?`, `DELETE FROM trials WHERE licence_id=?`, `DELETE FROM revocations WHERE licence_id=?`} {
			if _, err := tx.ExecContext(ctx, query, id); err != nil {
				return err
			}
		}
		if _, err := deleteRelatedOutbox(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM licences WHERE licence_id=?`, id); err != nil {
			return err
		}
	}
	_ = reason // free-form reasons belong only in the audit chain, never tombstones.
	return nil
}

func insertTombstoneAndOutbox(ctx context.Context, tx *transaction, tombstone domain.SuppressionTombstone) error {
	if _, err := tx.ExecContext(ctx, `INSERT INTO suppression_tombstones(subject_type,subject_digest,schema_version,deleted_at,reason_code,policy_version) VALUES(?,?,?,?,?,?) ON CONFLICT(subject_type,subject_digest) DO NOTHING`, tombstone.SubjectType, tombstone.SubjectDigest, tombstone.SchemaVersion, stamp(tombstone.DeletedAt), tombstone.ReasonCode, tombstone.PolicyVersion); err != nil {
		return err
	}
	event := domain.ArchiveEvent{SchemaVersion: 1, EventID: "suppress_" + tombstone.SubjectDigest[:32], EventType: "data.suppressed", OccurredAt: tombstone.DeletedAt, Suppression: &tombstone}
	payload, _ := json.Marshal(event)
	_, err := tx.ExecContext(ctx, `INSERT INTO archive_outbox(event_id,event_type,event_json,created_at,archived_at) VALUES(?,?,?,?,NULL) ON CONFLICT(event_id) DO NOTHING`, event.EventID, event.EventType, string(payload), stamp(event.OccurredAt))
	return err
}

func deleteRelatedOutbox(ctx context.Context, tx *transaction, licenceID string) (int, error) {
	rows, err := tx.QueryContext(ctx, `SELECT event_id,event_json FROM archive_outbox`)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id, payload string
		if err = rows.Scan(&id, &payload); err != nil {
			rows.Close()
			return 0, err
		}
		var event domain.ArchiveEvent
		if json.Unmarshal([]byte(payload), &event) == nil && event.LicenceID == licenceID {
			ids = append(ids, id)
		}
	}
	if err = rows.Close(); err != nil {
		return 0, err
	}
	deleted := 0
	for _, id := range ids {
		result, deleteErr := tx.ExecContext(ctx, `DELETE FROM archive_outbox WHERE event_id=?`, id)
		if deleteErr != nil {
			return deleted, deleteErr
		}
		if count, _ := result.RowsAffected(); count > 0 {
			deleted += int(count)
		}
	}
	return deleted, nil
}

func auditDeletionDetails(raw json.RawMessage, plan domain.DataDeletionPlan, reason string) json.RawMessage {
	var details map[string]any
	if json.Unmarshal(raw, &details) != nil {
		details = map[string]any{}
	}
	details["result"], details["reason"], details["mode"], details["counts"] = "success", reason, plan.Mode, plan.Counts
	details["policy_versions"], details["immutable_residue"] = plan.PolicyVersions, plan.ImmutableResidue
	details["immutable_residue_acknowledged"] = plan.ImmutableAcknowledged
	encoded, _ := json.Marshal(details)
	return encoded
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (r *Repository) ListSuppressionTombstones(ctx context.Context) ([]domain.SuppressionTombstone, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT subject_type,subject_digest,schema_version,deleted_at,reason_code,policy_version FROM suppression_tombstones ORDER BY subject_type,subject_digest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []domain.SuppressionTombstone
	for rows.Next() {
		var tombstone domain.SuppressionTombstone
		var deleted string
		if err = rows.Scan(&tombstone.SubjectType, &tombstone.SubjectDigest, &tombstone.SchemaVersion, &deleted, &tombstone.ReasonCode, &tombstone.PolicyVersion); err != nil {
			return nil, err
		}
		tombstone.DeletedAt = parse(deleted)
		result = append(result, tombstone)
	}
	return result, rows.Err()
}

func (r *Repository) ApplySuppressionTombstones(ctx context.Context, tombstones []domain.SuppressionTombstone, now time.Time, audit domain.AuditEvent) (domain.DeletionCounts, error) {
	var counts domain.DeletionCounts
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return counts, err
	}
	defer tx.Rollback()
	licenceDigests, activationDigests := map[string]domain.SuppressionTombstone{}, map[string]domain.SuppressionTombstone{}
	for _, tombstone := range tombstones {
		if retention.ValidateTombstone(tombstone) != nil {
			return counts, domain.ErrInvalid
		}
		switch tombstone.SubjectType {
		case "licence":
			licenceDigests[tombstone.SubjectDigest] = tombstone
		case "activation":
			activationDigests[tombstone.SubjectDigest] = tombstone
		default:
			return counts, domain.ErrInvalid
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO suppression_tombstones(subject_type,subject_digest,schema_version,deleted_at,reason_code,policy_version) VALUES(?,?,?,?,?,?) ON CONFLICT(subject_type,subject_digest) DO NOTHING`, tombstone.SubjectType, tombstone.SubjectDigest, tombstone.SchemaVersion, stamp(tombstone.DeletedAt), tombstone.ReasonCode, tombstone.PolicyVersion); err != nil {
			return counts, err
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT licence_id FROM licences`)
	if err != nil {
		return counts, err
	}
	var licenceIDs []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return counts, err
		}
		if _, suppressed := licenceDigests[retention.Digest("licence", id)]; suppressed {
			licenceIDs = append(licenceIDs, id)
		}
	}
	if err = rows.Close(); err != nil {
		return counts, err
	}
	for _, id := range licenceIDs {
		for query, counter := range map[string]*int{`DELETE FROM activation_records WHERE licence_id=?`: &counts.Activations, `DELETE FROM activation_codes WHERE licence_id=?`: &counts.ActivationCodes, `DELETE FROM trials WHERE licence_id=?`: &counts.Trials, `DELETE FROM revocations WHERE licence_id=?`: &counts.Revocations} {
			result, execErr := tx.ExecContext(ctx, query, id)
			if execErr != nil {
				return counts, execErr
			}
			n, _ := result.RowsAffected()
			*counter += int(n)
		}
		deletedOutbox, deleteErr := deleteRelatedOutbox(ctx, tx, id)
		if deleteErr != nil {
			return counts, deleteErr
		}
		counts.OutboxEvents += deletedOutbox
		if result, execErr := tx.ExecContext(ctx, `DELETE FROM licences WHERE licence_id=?`, id); execErr != nil {
			return counts, execErr
		} else if n, _ := result.RowsAffected(); n > 0 {
			counts.Licences += int(n)
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT activation_id FROM activation_records`)
	if err != nil {
		return counts, err
	}
	var activationIDs []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return counts, err
		}
		if _, suppressed := activationDigests[retention.Digest("activation", id)]; suppressed {
			activationIDs = append(activationIDs, id)
		}
	}
	if err = rows.Close(); err != nil {
		return counts, err
	}
	for _, id := range activationIDs {
		if result, execErr := tx.ExecContext(ctx, `DELETE FROM activation_records WHERE activation_id=?`, id); execErr != nil {
			return counts, execErr
		} else if n, _ := result.RowsAffected(); n > 0 {
			counts.Activations += int(n)
		}
	}
	counts.Tombstones = len(tombstones)
	audit.Event = auditDeletionDetails(audit.Event, domain.DataDeletionPlan{Mode: "restore_suppression", Counts: counts, ImmutableResidue: []string{"historical source retained"}}, "restore suppression")
	if err = appendAudit(ctx, tx, audit); err != nil {
		return counts, err
	}
	if err = tx.Commit(); err != nil {
		return counts, err
	}
	_ = now
	return counts, nil
}
