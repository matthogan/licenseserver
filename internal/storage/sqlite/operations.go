package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/matthogan/licenceserver/internal/domain"
)

func (r *Repository) RecordBackupVerification(ctx context.Context, verification domain.BackupVerification, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO backup_verifications(verification_id,location,sha256,size_bytes,verified_at) VALUES(?,?,?,?,?)`, verification.VerificationID, verification.Location, verification.SHA256, verification.SizeBytes, stamp(verification.VerifiedAt)); err != nil {
		return classify(err)
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) LatestBackupVerification(ctx context.Context) (domain.BackupVerification, error) {
	var out domain.BackupVerification
	var verifiedAt string
	err := r.db.QueryRowContext(ctx, `SELECT verification_id,location,sha256,size_bytes,verified_at FROM backup_verifications ORDER BY verified_at DESC LIMIT 1`).Scan(&out.VerificationID, &out.Location, &out.SHA256, &out.SizeBytes, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, domain.ErrNotFound
	}
	if err != nil {
		return out, err
	}
	out.VerifiedAt = parse(verifiedAt)
	return out, nil
}

func (r *Repository) GetMaintenance(ctx context.Context) (domain.MaintenanceState, error) {
	var out domain.MaintenanceState
	var enabled int
	var changedAt string
	err := r.db.QueryRowContext(ctx, `SELECT enabled,reason,changed_at,changed_by FROM maintenance_state WHERE state_id=1`).Scan(&enabled, &out.Reason, &changedAt, &out.ChangedBy)
	if err != nil {
		return out, classify(err)
	}
	out.Enabled = enabled != 0
	out.ChangedAt = parse(changedAt)
	return out, nil
}

func (r *Repository) SetMaintenance(ctx context.Context, state domain.MaintenanceState, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled := 0
	if state.Enabled {
		enabled = 1
	}
	if _, err = tx.ExecContext(ctx, `UPDATE maintenance_state SET enabled=?,reason=?,changed_at=?,changed_by=? WHERE state_id=1`, enabled, state.Reason, stamp(state.ChangedAt), state.ChangedBy); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) QueueArchiveEvent(ctx context.Context, event domain.OutboxEvent, audit domain.AuditEvent) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO archive_outbox(event_id,event_type,event_json,created_at,archived_at) VALUES(?,?,?,?,NULL) ON CONFLICT(event_id) DO NOTHING`, event.EventID, event.EventType, string(event.Event), stamp(event.CreatedAt))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
