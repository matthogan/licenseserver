package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

const rootSelect = `SELECT root_key_id,algorithm,public_key,fingerprint,status,accept_certificates_not_before,accept_certificates_before,source_transition_id,registered_at,activated_at,retired_at,state_reason FROM root_keys`
const rootTransitionSelect = `SELECT transition_id,old_root_key_id,new_root_key_id,artifact,created_at,not_before,overlap_until,expires_at,status,activated_at,retired_at,state_reason FROM root_transitions`

func (r *Repository) EnsureRootKey(ctx context.Context, key domain.RootKey, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := scanRoot(tx.QueryRowContext(ctx, rootSelect+` WHERE root_key_id=?`, key.RootKeyID))
	if err == nil {
		if existing.Algorithm != key.Algorithm || !bytes.Equal(existing.PublicKey, key.PublicKey) {
			return fmt.Errorf("%w: root key ID collision", domain.ErrConflict)
		}
		return tx.Commit()
	}
	if err != domain.ErrNotFound {
		return err
	}
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM root_keys`).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("%w: configured root is not part of the persisted keyring", domain.ErrInvalid)
	}
	if err = insertRoot(ctx, tx, key); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) ActivateRootTransition(ctx context.Context, transition domain.RootTransition, next domain.RootKey, audits []domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	active, err := scanRoot(tx.QueryRowContext(ctx, rootSelect+` WHERE status='active'`))
	if err != nil {
		return err
	}
	if active.RootKeyID != transition.OldRootKeyID {
		return fmt.Errorf("%w: transition old root is not active", domain.ErrConflict)
	}
	var existing int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM root_transitions WHERE transition_id=? OR status='active'`, transition.TransitionID).Scan(&existing); err != nil {
		return err
	}
	if existing != 0 {
		return fmt.Errorf("%w: a transition with this ID or another active transition exists", domain.ErrConflict)
	}
	if err = insertRoot(ctx, tx, next); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE root_keys SET accept_certificates_before=?,state_reason=? WHERE root_key_id=?`, stamp(transition.OverlapUntil), "transition "+transition.TransitionID+" active", transition.OldRootKeyID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return domain.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO root_transitions(transition_id,old_root_key_id,new_root_key_id,artifact,created_at,not_before,overlap_until,expires_at,status,activated_at,retired_at,state_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, transition.TransitionID, transition.OldRootKeyID, transition.NewRootKeyID, transition.Artifact, stamp(transition.CreatedAt), stamp(transition.NotBefore), stamp(transition.OverlapUntil), stamp(transition.ExpiresAt), transition.Status, stamp(transition.ActivatedAt), nil, nil); err != nil {
		return classify(err)
	}
	for _, audit := range audits {
		if err = appendAudit(ctx, tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) RetireRootTransition(ctx context.Context, id string, compromiseOld bool, reason string, now time.Time, audits []domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	transition, err := scanRootTransition(tx.QueryRowContext(ctx, rootTransitionSelect+` WHERE transition_id=?`, id))
	if err != nil {
		return err
	}
	if transition.Status != domain.RootTransitionStatusActive {
		return fmt.Errorf("%w: transition is not active", domain.ErrConflict)
	}
	oldStatus := domain.RootStatusLegacy
	if compromiseOld {
		oldStatus = domain.RootStatusCompromised
	}
	result, err := tx.ExecContext(ctx, `UPDATE root_keys SET status=?,retired_at=?,state_reason=? WHERE root_key_id=?`, oldStatus, stamp(now), reason, transition.OldRootKeyID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return domain.ErrConflict
	}
	result, err = tx.ExecContext(ctx, `UPDATE root_keys SET status='active',activated_at=?,state_reason=NULL WHERE root_key_id=? AND status='overlap'`, stamp(now), transition.NewRootKeyID)
	if err != nil {
		return classify(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return domain.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE root_transitions SET status='retired',retired_at=?,state_reason=? WHERE transition_id=?`, stamp(now), reason, id); err != nil {
		return err
	}
	for _, audit := range audits {
		if err = appendAudit(ctx, tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) RollbackRootTransition(ctx context.Context, id string, compromiseNew bool, reason string, now time.Time, audits []domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	transition, err := scanRootTransition(tx.QueryRowContext(ctx, rootTransitionSelect+` WHERE transition_id=?`, id))
	if err != nil {
		return err
	}
	if transition.Status != domain.RootTransitionStatusActive {
		return fmt.Errorf("%w: transition is not active", domain.ErrConflict)
	}
	newStatus := domain.RootStatusRetired
	if compromiseNew {
		newStatus = domain.RootStatusCompromised
	}
	result, err := tx.ExecContext(ctx, `UPDATE root_keys SET status=?,retired_at=?,state_reason=? WHERE root_key_id=?`, newStatus, stamp(now), reason, transition.NewRootKeyID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return domain.ErrConflict
	}
	result, err = tx.ExecContext(ctx, `UPDATE root_keys SET status='active',activated_at=?,accept_certificates_before=NULL,retired_at=NULL,state_reason=NULL WHERE root_key_id=?`, stamp(now), transition.OldRootKeyID)
	if err != nil {
		return classify(err)
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return domain.ErrConflict
	}
	if _, err = tx.ExecContext(ctx, `UPDATE root_transitions SET status='rolled_back',retired_at=?,state_reason=? WHERE transition_id=?`, stamp(now), reason, id); err != nil {
		return err
	}
	for _, audit := range audits {
		if err = appendAudit(ctx, tx, audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Repository) ListRootKeys(ctx context.Context) ([]domain.RootKey, error) {
	rows, err := r.db.QueryContext(ctx, rootSelect+` ORDER BY registered_at,root_key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roots []domain.RootKey
	for rows.Next() {
		root, scanErr := scanRoot(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		roots = append(roots, root)
	}
	return roots, rows.Err()
}

func (r *Repository) GetRootKey(ctx context.Context, id string) (domain.RootKey, error) {
	return scanRoot(r.db.QueryRowContext(ctx, rootSelect+` WHERE root_key_id=?`, id))
}

func (r *Repository) GetActiveRootKey(ctx context.Context) (domain.RootKey, error) {
	return scanRoot(r.db.QueryRowContext(ctx, rootSelect+` WHERE status='active'`))
}

func (r *Repository) ListRootTransitions(ctx context.Context) ([]domain.RootTransition, error) {
	rows, err := r.db.QueryContext(ctx, rootTransitionSelect+` ORDER BY activated_at DESC,transition_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var transitions []domain.RootTransition
	for rows.Next() {
		transition, scanErr := scanRootTransition(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		transitions = append(transitions, transition)
	}
	return transitions, rows.Err()
}

func (r *Repository) GetRootTransition(ctx context.Context, id string) (domain.RootTransition, error) {
	return scanRootTransition(r.db.QueryRowContext(ctx, rootTransitionSelect+` WHERE transition_id=?`, id))
}

func insertRoot(ctx context.Context, tx *transaction, key domain.RootKey) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO root_keys(root_key_id,algorithm,public_key,fingerprint,status,accept_certificates_not_before,accept_certificates_before,source_transition_id,registered_at,activated_at,retired_at,state_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, key.RootKeyID, key.Algorithm, key.PublicKey, key.Fingerprint, key.Status, nullTime(key.AcceptCertificatesNotBefore), nullTime(key.AcceptCertificatesBefore), nullString(key.SourceTransitionID), stamp(key.RegisteredAt), nullTime(key.ActivatedAt), nullTime(key.RetiredAt), nullString(key.StateReason))
	return classify(err)
}

func scanRoot(s scanner) (domain.RootKey, error) {
	var root domain.RootKey
	var registered string
	var acceptNotBefore, acceptBefore, source, activated, retired, reason sql.NullString
	err := s.Scan(&root.RootKeyID, &root.Algorithm, &root.PublicKey, &root.Fingerprint, &root.Status, &acceptNotBefore, &acceptBefore, &source, &registered, &activated, &retired, &reason)
	if err != nil {
		return root, classify(err)
	}
	root.RegisteredAt = parse(registered)
	root.SourceTransitionID = source.String
	root.StateReason = reason.String
	root.AcceptCertificatesNotBefore = parseOptional(acceptNotBefore)
	root.AcceptCertificatesBefore = parseOptional(acceptBefore)
	root.ActivatedAt = parseOptional(activated)
	root.RetiredAt = parseOptional(retired)
	return root, nil
}

func scanRootTransition(s scanner) (domain.RootTransition, error) {
	var transition domain.RootTransition
	var created, notBefore, overlapUntil, expires, activated string
	var retired, reason sql.NullString
	err := s.Scan(&transition.TransitionID, &transition.OldRootKeyID, &transition.NewRootKeyID, &transition.Artifact, &created, &notBefore, &overlapUntil, &expires, &transition.Status, &activated, &retired, &reason)
	if err != nil {
		return transition, classify(err)
	}
	transition.CreatedAt = parse(created)
	transition.NotBefore = parse(notBefore)
	transition.OverlapUntil = parse(overlapUntil)
	transition.ExpiresAt = parse(expires)
	transition.ActivatedAt = parse(activated)
	transition.RetiredAt = parseOptional(retired)
	transition.StateReason = reason.String
	return transition, nil
}

func parseOptional(value sql.NullString) *time.Time {
	if !value.Valid {
		return nil
	}
	parsed := parse(value.String)
	return &parsed
}
