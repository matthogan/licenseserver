package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

const activationCodeSelect = `SELECT activation_id,code_hash,hash_version,licence_id,max_uses,use_count,expires_at,revoked_at,revocation_reason,created_at FROM activation_codes`
const activationSelect = `SELECT activation_id,activation_code_id,licence_id,instance_ref_hash,request_ref_hash,activated_at,last_retrieved_at,revoked_at,revocation_reason,metadata_json FROM activation_records`

func (r *Repository) CreateActivationCode(ctx context.Context, code domain.ActivationCode, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO activation_codes(activation_id,code_hash,licence_id,max_uses,use_count,expires_at,revoked_at,created_at,hash_version,revocation_reason) VALUES(?,?,?,?,?,?,NULL,?,?,NULL)`, code.ActivationCodeID, code.CodeHash, code.LicenceID, code.MaxUses, 0, nullTime(code.ExpiresAt), stamp(code.CreatedAt), code.HashVersion)
	if err != nil {
		return classify(err)
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) RedeemActivationCode(ctx context.Context, hashes []domain.ActivationCodeHash, record domain.ActivationRecord, now time.Time, redeemedAudit, retriedAudit domain.AuditEvent) (domain.LicenceRecord, domain.ActivationRecord, bool, error) {
	r.activationMu.Lock()
	defer r.activationMu.Unlock()
	var emptyLicence domain.LicenceRecord
	var emptyActivation domain.ActivationRecord
	if len(hashes) == 0 || len(hashes) > 4 {
		return emptyLicence, emptyActivation, false, domain.ErrActivationInvalid
	}
	where := make([]string, len(hashes))
	args := make([]any, 0, len(hashes)*2)
	for i, candidate := range hashes {
		where[i] = `(code_hash=? AND hash_version=?)`
		args = append(args, candidate.Hash, candidate.Version)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return emptyLicence, emptyActivation, false, err
	}
	defer tx.Rollback()
	code, err := scanActivationCode(tx.QueryRowContext(ctx, activationCodeSelect+` WHERE `+strings.Join(where, ` OR `), args...))
	if errors.Is(err, domain.ErrNotFound) {
		return emptyLicence, emptyActivation, false, domain.ErrActivationInvalid
	}
	if err != nil {
		return emptyLicence, emptyActivation, false, err
	}

	existing, findErr := scanActivation(tx.QueryRowContext(ctx, activationSelect+` WHERE request_ref_hash=?`, record.RequestRefHash))
	sameRequest := findErr == nil
	if errors.Is(findErr, domain.ErrNotFound) {
		existing, findErr = scanActivation(tx.QueryRowContext(ctx, activationSelect+` WHERE activation_code_id=? AND instance_ref_hash=?`, code.ActivationCodeID, record.InstanceRefHash))
	}
	if findErr == nil {
		if sameRequest && (existing.ActivationCodeID != code.ActivationCodeID || !bytes.Equal(existing.InstanceRefHash, record.InstanceRefHash) || !bytes.Equal(existing.Metadata, record.Metadata)) {
			return emptyLicence, emptyActivation, false, domain.ErrIdempotencyConflict
		}
		if existing.RevokedAt != nil {
			return emptyLicence, emptyActivation, false, domain.ErrActivationRevoked
		}
		licence, loadErr := scanLicence(tx.QueryRowContext(ctx, licenceSelect+` WHERE licence_id=? AND status='active'`, existing.LicenceID))
		if errors.Is(loadErr, domain.ErrNotFound) {
			return emptyLicence, emptyActivation, false, domain.ErrActivationInvalid
		}
		if loadErr != nil {
			return emptyLicence, emptyActivation, false, loadErr
		}
		if _, err = tx.ExecContext(ctx, `UPDATE activation_records SET last_retrieved_at=? WHERE activation_id=?`, stamp(now), existing.ActivationID); err != nil {
			return emptyLicence, emptyActivation, false, err
		}
		existing.LastRetrievedAt = now
		retriedAudit.AggregateID = existing.ActivationID
		if err = appendAudit(ctx, tx, retriedAudit); err != nil {
			return emptyLicence, emptyActivation, false, err
		}
		if err = tx.Commit(); err != nil {
			return emptyLicence, emptyActivation, false, err
		}
		return licence, existing, true, nil
	}
	if !errors.Is(findErr, domain.ErrNotFound) {
		return emptyLicence, emptyActivation, false, findErr
	}
	if code.RevokedAt != nil {
		return emptyLicence, emptyActivation, false, domain.ErrActivationRevoked
	}
	if code.UseCount >= code.MaxUses {
		return emptyLicence, emptyActivation, false, domain.ErrActivationExhausted
	}
	if code.ExpiresAt != nil && !now.Before(*code.ExpiresAt) {
		return emptyLicence, emptyActivation, false, domain.ErrActivationExpired
	}
	licence, err := scanLicence(tx.QueryRowContext(ctx, licenceSelect+` WHERE licence_id=? AND status='active'`, code.LicenceID))
	if errors.Is(err, domain.ErrNotFound) {
		return emptyLicence, emptyActivation, false, domain.ErrActivationInvalid
	}
	if err != nil {
		return emptyLicence, emptyActivation, false, err
	}
	record.ActivationCodeID = code.ActivationCodeID
	record.LicenceID = code.LicenceID
	_, err = tx.ExecContext(ctx, `INSERT INTO activation_records(activation_id,activation_code_id,licence_id,instance_ref_hash,request_ref_hash,activated_at,last_retrieved_at,revoked_at,revocation_reason,metadata_json) VALUES(?,?,?,?,?,?,?,NULL,NULL,?)`, record.ActivationID, record.ActivationCodeID, record.LicenceID, record.InstanceRefHash, record.RequestRefHash, stamp(record.ActivatedAt), stamp(record.LastRetrievedAt), nullJSON(record.Metadata))
	if err != nil {
		return emptyLicence, emptyActivation, false, classify(err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE activation_codes SET use_count=use_count+1 WHERE activation_id=? AND revoked_at IS NULL AND use_count<max_uses AND (expires_at IS NULL OR julianday(expires_at)>julianday(?))`, code.ActivationCodeID, stamp(now))
	if err != nil {
		return emptyLicence, emptyActivation, false, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return emptyLicence, emptyActivation, false, domain.ErrActivationExhausted
	}
	redeemedAudit.AggregateID = record.ActivationID
	if err = appendAudit(ctx, tx, redeemedAudit); err != nil {
		return emptyLicence, emptyActivation, false, err
	}
	if err = tx.Commit(); err != nil {
		return emptyLicence, emptyActivation, false, err
	}
	return licence, record, false, nil
}

func (r *Repository) ListActivationCodes(ctx context.Context, licenceID string, limit int) ([]domain.ActivationCode, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := activationCodeSelect
	args := []any{}
	if licenceID != "" {
		query += ` WHERE licence_id=?`
		args = append(args, licenceID)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ActivationCode
	for rows.Next() {
		code, scanErr := scanActivationCode(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, code)
	}
	return out, rows.Err()
}

func (r *Repository) GetActivationCode(ctx context.Context, id string) (domain.ActivationCode, error) {
	return scanActivationCode(r.db.QueryRowContext(ctx, activationCodeSelect+` WHERE activation_id=?`, id))
}

func (r *Repository) RevokeActivationCode(ctx context.Context, id, reason string, now time.Time, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE activation_codes SET revoked_at=?,revocation_reason=? WHERE activation_id=? AND revoked_at IS NULL`, stamp(now), reason, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		var exists int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM activation_codes WHERE activation_id=?`, id).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return domain.ErrNotFound
		}
		return domain.ErrConflict
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) ListActivations(ctx context.Context, licenceID, codeID string, limit int) ([]domain.ActivationRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := activationSelect
	conditions := []string{}
	args := []any{}
	if licenceID != "" {
		conditions = append(conditions, `licence_id=?`)
		args = append(args, licenceID)
	}
	if codeID != "" {
		conditions = append(conditions, `activation_code_id=?`)
		args = append(args, codeID)
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY activated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ActivationRecord
	for rows.Next() {
		record, scanErr := scanActivation(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (r *Repository) GetActivation(ctx context.Context, id string) (domain.ActivationRecord, error) {
	return scanActivation(r.db.QueryRowContext(ctx, activationSelect+` WHERE activation_id=?`, id))
}

func (r *Repository) RevokeActivation(ctx context.Context, id, reason string, now time.Time, audit domain.AuditEvent) error {
	r.activationMu.Lock()
	defer r.activationMu.Unlock()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var codeID string
	var revoked sql.NullString
	if err = tx.QueryRowContext(ctx, `SELECT activation_code_id,revoked_at FROM activation_records WHERE activation_id=?`, id).Scan(&codeID, &revoked); err != nil {
		return classify(err)
	}
	if revoked.Valid {
		return domain.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE activation_records SET revoked_at=?,revocation_reason=? WHERE activation_id=?`, stamp(now), reason, id); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE activation_codes SET use_count=CASE WHEN use_count>0 THEN use_count-1 ELSE 0 END WHERE activation_id=?`, codeID); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func scanActivationCode(s scanner) (domain.ActivationCode, error) {
	var code domain.ActivationCode
	var expires, revoked, reason sql.NullString
	var created string
	err := s.Scan(&code.ActivationCodeID, &code.CodeHash, &code.HashVersion, &code.LicenceID, &code.MaxUses, &code.UseCount, &expires, &revoked, &reason, &created)
	if err != nil {
		return code, classify(err)
	}
	if expires.Valid {
		t := parse(expires.String)
		code.ExpiresAt = &t
	}
	if revoked.Valid {
		t := parse(revoked.String)
		code.RevokedAt = &t
	}
	code.RevocationReason = reason.String
	code.CreatedAt = parse(created)
	return code, nil
}

func scanActivation(s scanner) (domain.ActivationRecord, error) {
	var record domain.ActivationRecord
	var activated, retrieved string
	var revoked, reason, metadata sql.NullString
	err := s.Scan(&record.ActivationID, &record.ActivationCodeID, &record.LicenceID, &record.InstanceRefHash, &record.RequestRefHash, &activated, &retrieved, &revoked, &reason, &metadata)
	if err != nil {
		return record, classify(err)
	}
	record.ActivatedAt = parse(activated)
	record.LastRetrievedAt = parse(retrieved)
	if revoked.Valid {
		t := parse(revoked.String)
		record.RevokedAt = &t
	}
	record.RevocationReason = reason.String
	if metadata.Valid {
		record.Metadata = json.RawMessage(metadata.String)
	}
	return record, nil
}
