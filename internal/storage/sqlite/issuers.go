package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

const issuerSelect = `SELECT issuer_key_id,algorithm,public_key,issuer_certificate,authority_not_before,authority_not_after,products_json,status,private_key_ref,registered_at,activated_at,retired_at,state_reason FROM signing_keys`

func (r *Repository) RegisterIssuer(ctx context.Context, key domain.IssuerKey, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = insertIssuer(ctx, tx, key); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) RotateIssuer(ctx context.Context, key domain.IssuerKey, replaces string, audits []domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if replaces != "" {
		var status string
		if err = tx.QueryRowContext(ctx, `SELECT status FROM signing_keys WHERE issuer_key_id=?`, replaces).Scan(&status); err != nil {
			return classify(err)
		}
		if status != domain.IssuerStatusLost && status != domain.IssuerStatusCompromised {
			return fmt.Errorf("%w: replacement issuer must be lost or compromised", domain.ErrInvalid)
		}
		var active int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM signing_keys WHERE status='active'`).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return fmt.Errorf("%w: recovery requires no active issuer", domain.ErrConflict)
		}
	}
	if err = insertIssuer(ctx, tx, key); err != nil {
		return err
	}
	now := key.RegisteredAt
	if replaces == "" {
		if _, err = tx.ExecContext(ctx, `UPDATE signing_keys SET status='retired',retired_at=?,state_reason='superseded by rotation' WHERE status='active' AND issuer_key_id<>?`, stamp(now), key.IssuerKeyID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE signing_keys SET status='active',activated_at=?,retired_at=NULL,state_reason=NULL WHERE issuer_key_id=?`, stamp(now), key.IssuerKeyID); err != nil {
		return classify(err)
	}
	for _, audit := range audits {
		if err = appendAudit(ctx, tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) ActivateIssuer(ctx context.Context, id string, audits []domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM signing_keys WHERE issuer_key_id=?`, id).Scan(&status); err != nil {
		return classify(err)
	}
	if status == domain.IssuerStatusLost || status == domain.IssuerStatusCompromised {
		return fmt.Errorf("%w: a %s issuer cannot be activated", domain.ErrInvalid, status)
	}
	if status == domain.IssuerStatusActive {
		return domain.ErrConflict
	}
	now := time.Now().UTC()
	if len(audits) > 0 {
		now = audits[len(audits)-1].OccurredAt
	}
	if _, err = tx.ExecContext(ctx, `UPDATE signing_keys SET status='retired',retired_at=?,state_reason='superseded by activation' WHERE status='active'`, stamp(now)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE signing_keys SET status='active',activated_at=?,retired_at=NULL,state_reason=NULL WHERE issuer_key_id=?`, stamp(now), id); err != nil {
		return classify(err)
	}
	for _, audit := range audits {
		if err = appendAudit(ctx, tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) SetIssuerStatus(ctx context.Context, id, status, reason string, allowNoActive bool, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM signing_keys WHERE issuer_key_id=?`, id).Scan(&current); err != nil {
		return classify(err)
	}
	if current == status {
		return domain.ErrConflict
	}
	if current == domain.IssuerStatusActive && status == domain.IssuerStatusRetired && !allowNoActive {
		return fmt.Errorf("%w: retiring the active issuer requires explicit allow_no_active", domain.ErrInvalid)
	}
	if current == domain.IssuerStatusCompromised {
		return fmt.Errorf("%w: compromised status is terminal", domain.ErrInvalid)
	}
	if current == domain.IssuerStatusLost && status != domain.IssuerStatusCompromised {
		return fmt.Errorf("%w: lost status can only advance to compromised", domain.ErrInvalid)
	}
	retiredAt := any(nil)
	if status == domain.IssuerStatusRetired || status == domain.IssuerStatusLost || status == domain.IssuerStatusCompromised {
		retiredAt = stamp(audit.OccurredAt)
	}
	result, err := tx.ExecContext(ctx, `UPDATE signing_keys SET status=?,retired_at=?,state_reason=? WHERE issuer_key_id=?`, status, retiredAt, nullString(reason), id)
	if err != nil {
		return classify(err)
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return domain.ErrNotFound
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) ListIssuers(ctx context.Context) ([]domain.IssuerKey, error) {
	rows, err := r.db.QueryContext(ctx, issuerSelect+` ORDER BY registered_at DESC,issuer_key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []domain.IssuerKey
	for rows.Next() {
		key, scanErr := scanIssuer(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *Repository) GetIssuer(ctx context.Context, id string) (domain.IssuerKey, error) {
	return scanIssuer(r.db.QueryRowContext(ctx, issuerSelect+` WHERE issuer_key_id=?`, id))
}

func (r *Repository) GetActiveIssuer(ctx context.Context) (domain.IssuerKey, error) {
	return scanIssuer(r.db.QueryRowContext(ctx, issuerSelect+` WHERE status='active'`))
}

func insertIssuer(ctx context.Context, tx *transaction, key domain.IssuerKey) error {
	products, err := json.Marshal(key.Products)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO signing_keys(issuer_key_id,algorithm,public_key,issuer_certificate,authority_not_before,authority_not_after,products_json,status,private_key_ref,registered_at,activated_at,retired_at,state_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, key.IssuerKeyID, key.Algorithm, key.PublicKey, key.IssuerCertificate, stamp(key.AuthorityNotBefore), stamp(key.AuthorityNotAfter), string(products), key.Status, key.PrivateKeyRef, stamp(key.RegisteredAt), nullTime(key.ActivatedAt), nullTime(key.RetiredAt), nullString(key.StateReason))
	return classify(err)
}

func scanIssuer(s scanner) (domain.IssuerKey, error) {
	var key domain.IssuerKey
	var notBefore, notAfter, registered string
	var products []byte
	var activated, retired, reason sql.NullString
	err := s.Scan(&key.IssuerKeyID, &key.Algorithm, &key.PublicKey, &key.IssuerCertificate, &notBefore, &notAfter, &products, &key.Status, &key.PrivateKeyRef, &registered, &activated, &retired, &reason)
	if err != nil {
		return key, classify(err)
	}
	if err = json.Unmarshal(products, &key.Products); err != nil {
		return key, err
	}
	key.AuthorityNotBefore = parse(notBefore)
	key.AuthorityNotAfter = parse(notAfter)
	key.RegisteredAt = parse(registered)
	if activated.Valid {
		t := parse(activated.String)
		key.ActivatedAt = &t
	}
	if retired.Valid {
		t := parse(retired.String)
		key.RetiredAt = &t
	}
	key.StateReason = reason.String
	return key, nil
}
