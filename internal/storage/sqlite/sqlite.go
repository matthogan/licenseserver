package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/failurepoint"
	_ "modernc.org/sqlite"
)

type Repository struct {
	db           *database
	activationMu sync.Mutex
}

func Open(c config.Config) (*Repository, error) {
	path := c.Database.DSN
	if path == "" {
		return nil, errors.New("empty database path")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode("+safePragma(c.Database.SQLite.JournalMode, "WAL", []string{"WAL", "DELETE"})+")")
	q.Add("_pragma", "synchronous("+safePragma(c.Database.SQLite.Synchronous, "FULL", []string{"FULL", "NORMAL", "EXTRA"})+")")
	if c.Database.SQLite.ForeignKeys {
		q.Add("_pragma", "foreign_keys(ON)")
	}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", c.Database.SQLite.BusyTimeout.Milliseconds()))
	dsn := path
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + filepath.ToSlash(dsn)
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)
	r := &Repository{db: &database{DB: db, dialect: dialectSQLite}}
	if err := r.Ping(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return r, nil
}

func safePragma(value, fallback string, allowedValues []string) string {
	v := strings.ToUpper(value)
	for _, allowed := range allowedValues {
		if v == allowed {
			return v
		}
	}
	return fallback
}

func (r *Repository) Close() error                   { return r.db.Close() }
func (r *Repository) Ping(ctx context.Context) error { return r.db.PingContext(ctx) }

func (r *Repository) SchemaStatus(ctx context.Context) (domain.SchemaStatus, error) {
	status := domain.SchemaStatus{Supported: len(migrations)}
	var count int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&count, &status.Current); err != nil {
		return status, err
	}
	if count != status.Current {
		return status, fmt.Errorf("schema migration history is not contiguous: count=%d maximum=%d", count, status.Current)
	}
	status.Compatible = status.Current == status.Supported
	return status, nil
}

func (r *Repository) DatabaseStats() domain.DatabaseStats {
	stats := r.db.Stats()
	return domain.DatabaseStats{OpenConnections: stats.OpenConnections, InUseConnections: stats.InUse, IdleConnections: stats.Idle, WaitCount: stats.WaitCount, WaitDuration: stats.WaitDuration}
}

func (r *Repository) Migrate(ctx context.Context) error {
	return r.MigrateWithOptions(ctx, MigrationOptions{})
}

const defaultMigrationBackupMaxAge = 24 * time.Hour

type MigrationOptions struct {
	AllowDestructive   bool
	ForceWithoutBackup bool
	BackupMaxAge       time.Duration
	Now                time.Time
}

type MigrationPlanItem struct {
	Version int            `json:"version"`
	Name    string         `json:"name"`
	Class   MigrationClass `json:"class"`
}

func (r *Repository) MigrationPlan(ctx context.Context) ([]MigrationPlanItem, error) {
	current, err := r.currentSchemaVersion(ctx)
	if err != nil {
		return nil, err
	}
	if current > len(migrations) {
		return nil, fmt.Errorf("database schema version %d is newer than supported version %d", current, len(migrations))
	}
	plan := make([]MigrationPlanItem, 0, len(migrations)-current)
	for version := current; version < len(migrations); version++ {
		m := migrations[version]
		plan = append(plan, MigrationPlanItem{Version: version + 1, Name: m.Name, Class: m.Class})
	}
	return plan, nil
}

func (r *Repository) MigrateWithOptions(ctx context.Context, opts MigrationOptions) error {
	initialVersion, err := r.currentSchemaVersion(ctx)
	if err != nil {
		return err
	}
	if initialVersion > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than supported version %d", initialVersion, len(migrations))
	}
	if opts.BackupMaxAge <= 0 {
		opts.BackupMaxAge = defaultMigrationBackupMaxAge
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	changed := false
	for version, migration := range migrations {
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
			tx.Rollback()
			return err
		}
		var exists int
		err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version=?`, version+1).Scan(&exists)
		if err != nil {
			tx.Rollback()
			return err
		}
		if exists == 0 {
			if migration.Class == MigrationDestructive && initialVersion > 0 {
				tx.Rollback()
				if !opts.AllowDestructive {
					return fmt.Errorf("destructive migration %d (%s) requires explicit `licctl db migrate`", version+1, migration.Name)
				}
				if !opts.ForceWithoutBackup {
					if err = r.requireRecentVerifiedBackup(ctx, opts.Now, opts.BackupMaxAge); err != nil {
						return fmt.Errorf("destructive migration %d (%s): %w; verify a backup or explicitly use --force-without-backup", version+1, migration.Name, err)
					}
				}
				tx, err = r.db.BeginTx(ctx, nil)
				if err != nil {
					return err
				}
			}
			if err = executeMigration(ctx, tx, migration.SQL, r.db.dialect); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration %d: %w", version+1, err)
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, version+1, stamp(time.Now())); err != nil {
				tx.Rollback()
				return err
			}
			changed = true
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	if changed {
		return r.Verify(ctx, true)
	}
	return nil
}

func (r *Repository) currentSchemaVersion(ctx context.Context) (int, error) {
	var current, count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&count, &current)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "no such table") || strings.Contains(message, "does not exist") {
			return 0, nil
		}
	}
	if err == nil && count != current {
		return 0, fmt.Errorf("schema migration history is not contiguous: count=%d maximum=%d", count, current)
	}
	return current, err
}

func (r *Repository) requireRecentVerifiedBackup(ctx context.Context, now time.Time, maxAge time.Duration) error {
	verification, err := r.LatestBackupVerification(ctx)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return errors.New("no verified backup is recorded")
		}
		return err
	}
	if verification.VerifiedAt.After(now.Add(time.Minute)) {
		return errors.New("latest backup verification is in the future")
	}
	if now.Sub(verification.VerifiedAt) > maxAge {
		return fmt.Errorf("latest verified backup is older than %s", maxAge)
	}
	f, err := os.Open(verification.Location)
	if err != nil {
		return fmt.Errorf("open verified backup evidence: %w", err)
	}
	h := sha256.New()
	size, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("hash verified backup evidence: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close verified backup evidence: %w", closeErr)
	}
	if size != verification.SizeBytes || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), verification.SHA256) {
		return errors.New("verified backup evidence has changed since verification")
	}
	if err = r.VerifyAudit(ctx); err != nil {
		return fmt.Errorf("backup-verification audit chain is invalid: %w", err)
	}
	return nil
}

func (r *Repository) Verify(ctx context.Context, deep bool) error {
	if r.db.dialect == dialectPostgres {
		if err := r.db.PingContext(ctx); err != nil {
			return err
		}
		var invalid int
		if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_constraint WHERE convalidated=false`).Scan(&invalid); err != nil {
			return err
		}
		if invalid != 0 {
			return fmt.Errorf("PostgreSQL has %d unvalidated constraints", invalid)
		}
		return r.VerifyAudit(ctx)
	}
	check := "quick_check"
	if deep {
		check = "integrity_check"
	}
	rows, err := r.db.QueryContext(ctx, "PRAGMA "+check)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return err
		}
		if result != "ok" {
			return fmt.Errorf("database integrity: %s", result)
		}
	}
	if err = rows.Err(); err != nil || !deep {
		return err
	}
	foreignKeys, err := r.db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return err
	}
	defer foreignKeys.Close()
	if foreignKeys.Next() {
		return errors.New("database foreign-key integrity check failed")
	}
	return foreignKeys.Err()
}

func executeMigration(ctx context.Context, tx *transaction, migration, dialect string) error {
	if dialect != dialectPostgres {
		_, err := tx.ExecContext(ctx, migration)
		return err
	}
	postgresSQL := strings.ReplaceAll(migration, " BLOB", " BYTEA")
	postgresSQL = strings.ReplaceAll(postgresSQL, "active INTEGER NOT NULL", "active BOOLEAN NOT NULL")
	postgresSQL = strings.Replace(postgresSQL, "CREATE TABLE audit_events (", "CREATE TABLE audit_events (audit_sequence BIGSERIAL UNIQUE,", 1)
	for _, statement := range strings.Split(postgresSQL, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) CreateProduct(ctx context.Context, p domain.Product, audit domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO products(product_id,display_name,default_trial_seconds,active,created_at) VALUES(?,?,?,?,?)`, p.ProductID, p.DisplayName, p.DefaultTrialSeconds, p.Active, stamp(p.CreatedAt)); err != nil {
		return classify(err)
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) UpdateProduct(ctx context.Context, id string, update domain.ProductUpdate, audit domain.AuditEvent) (domain.Product, error) {
	var out domain.Product
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var created string
	if err = tx.QueryRowContext(ctx, `SELECT product_id,display_name,default_trial_seconds,active,created_at FROM products WHERE product_id=?`, id).Scan(&out.ProductID, &out.DisplayName, &out.DefaultTrialSeconds, &out.Active, &created); err != nil {
		return out, classify(err)
	}
	out.CreatedAt = parse(created)
	if update.DisplayName != nil {
		out.DisplayName = *update.DisplayName
	}
	if update.DefaultTrialSeconds != nil {
		out.DefaultTrialSeconds = *update.DefaultTrialSeconds
	}
	if update.Active != nil {
		out.Active = *update.Active
	}
	if _, err = tx.ExecContext(ctx, `UPDATE products SET display_name=?,default_trial_seconds=?,active=? WHERE product_id=?`, out.DisplayName, out.DefaultTrialSeconds, out.Active, id); err != nil {
		return domain.Product{}, classify(err)
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return domain.Product{}, err
	}
	if err = tx.Commit(); err != nil {
		return domain.Product{}, err
	}
	return out, nil
}

func (r *Repository) ListProducts(ctx context.Context) ([]domain.Product, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT product_id,display_name,default_trial_seconds,active,created_at FROM products ORDER BY product_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Product
	for rows.Next() {
		var p domain.Product
		var at string
		if err := rows.Scan(&p.ProductID, &p.DisplayName, &p.DefaultTrialSeconds, &p.Active, &at); err != nil {
			return nil, err
		}
		p.CreatedAt = parse(at)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *Repository) GetProduct(ctx context.Context, id string) (domain.Product, error) {
	var p domain.Product
	var at string
	err := r.db.QueryRowContext(ctx, `SELECT product_id,display_name,default_trial_seconds,active,created_at FROM products WHERE product_id=?`, id).Scan(&p.ProductID, &p.DisplayName, &p.DefaultTrialSeconds, &p.Active, &at)
	p.CreatedAt = parse(at)
	return p, classify(err)
}

func (r *Repository) CreateLicence(ctx context.Context, rec domain.LicenceRecord, trial *domain.TrialRecord, audit domain.AuditEvent, outbox *domain.OutboxEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO licences(licence_id,product_id,licence_type,customer_ref,purchase_ref,issuer_key_id,issued_at,not_before,expires_at,status,payload_hash,signed_artifact,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, rec.LicenceID, rec.ProductID, rec.LicenceType, nullString(rec.CustomerRef), nullString(rec.PurchaseRef), rec.IssuerKeyID, stamp(rec.IssuedAt), stamp(rec.NotBefore), nullTime(rec.ExpiresAt), rec.Status, rec.PayloadHash, rec.SignedArtifact, nullJSON(rec.Metadata), stamp(rec.CreatedAt))
	if err != nil {
		return classify(err)
	}
	if err = failurepoint.Check(ctx, failurepoint.DuringDBTransaction); err != nil {
		return err
	}
	if trial != nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO trials(trial_id,product_id,subject_hash,licence_id,started_at,expires_at,created_at) VALUES(?,?,?,?,?,?,?)`, trial.TrialID, trial.ProductID, trial.SubjectHash, trial.LicenceID, stamp(trial.StartedAt), stamp(trial.ExpiresAt), stamp(trial.CreatedAt))
		if err != nil {
			return classify(err)
		}
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	if outbox != nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO archive_outbox(event_id,event_type,event_json,created_at,archived_at) VALUES(?,?,?,?,NULL)`, outbox.EventID, outbox.EventType, string(outbox.Event), stamp(outbox.CreatedAt))
		if err != nil {
			return classify(err)
		}
	}
	return tx.Commit()
}

func (r *Repository) GetLicence(ctx context.Context, id string) (domain.LicenceRecord, error) {
	return scanLicence(r.db.QueryRowContext(ctx, licenceSelect+` WHERE licence_id=?`, id))
}

func (r *Repository) FindLicenceByPurchaseRef(ctx context.Context, product, purchase string) (domain.LicenceRecord, error) {
	return scanLicence(r.db.QueryRowContext(ctx, licenceSelect+` WHERE product_id=? AND purchase_ref=?`, product, purchase))
}

func (r *Repository) FindTrial(ctx context.Context, product string, hash []byte) (domain.TrialRecord, domain.LicenceRecord, error) {
	var t domain.TrialRecord
	var started, expires, created string
	err := r.db.QueryRowContext(ctx, `SELECT trial_id,product_id,subject_hash,licence_id,started_at,expires_at,created_at FROM trials WHERE product_id=? AND subject_hash=?`, product, hash).Scan(&t.TrialID, &t.ProductID, &t.SubjectHash, &t.LicenceID, &started, &expires, &created)
	if err != nil {
		return t, domain.LicenceRecord{}, classify(err)
	}
	t.StartedAt = parse(started)
	t.ExpiresAt = parse(expires)
	t.CreatedAt = parse(created)
	l, err := r.GetLicence(ctx, t.LicenceID)
	return t, l, err
}

func (r *Repository) GetTrial(ctx context.Context, id string) (domain.TrialRecord, domain.LicenceRecord, error) {
	var t domain.TrialRecord
	var started, expires, created string
	err := r.db.QueryRowContext(ctx, `SELECT trial_id,product_id,subject_hash,licence_id,started_at,expires_at,created_at FROM trials WHERE trial_id=? OR licence_id=?`, id, id).Scan(&t.TrialID, &t.ProductID, &t.SubjectHash, &t.LicenceID, &started, &expires, &created)
	if err != nil {
		return t, domain.LicenceRecord{}, classify(err)
	}
	t.StartedAt = parse(started)
	t.ExpiresAt = parse(expires)
	t.CreatedAt = parse(created)
	l, err := r.GetLicence(ctx, t.LicenceID)
	return t, l, err
}

func (r *Repository) ListLicences(ctx context.Context, product string, limit int) ([]domain.LicenceRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := licenceSelect
	args := []any{}
	if product != "" {
		query += ` WHERE product_id=?`
		args = append(args, product)
	}
	query += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.LicenceRecord
	for rows.Next() {
		l, err := scanLicence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (r *Repository) ListPaidLicences(ctx context.Context) ([]domain.LicenceRecord, error) {
	rows, err := r.db.QueryContext(ctx, licenceSelect+` WHERE licence_type!='trial' ORDER BY created_at,licence_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.LicenceRecord
	for rows.Next() {
		licence, scanErr := scanLicence(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, licence)
	}
	return out, rows.Err()
}

func (r *Repository) RevokeLicence(ctx context.Context, rev domain.Revocation, audit domain.AuditEvent, outbox *domain.OutboxEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE licences SET status='revoked' WHERE licence_id=? AND status!='revoked'`, rev.LicenceID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO revocations(revocation_id,licence_id,reason_code,reason_text,revoked_at) VALUES(?,?,?,?,?)`, rev.RevocationID, rev.LicenceID, rev.ReasonCode, nullString(rev.ReasonText), stamp(rev.RevokedAt))
	if err != nil {
		return classify(err)
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	if outbox != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO archive_outbox(event_id,event_type,event_json,created_at,archived_at) VALUES(?,?,?,?,NULL)`, outbox.EventID, outbox.EventType, string(outbox.Event), stamp(outbox.CreatedAt)); err != nil {
			return classify(err)
		}
	}
	return tx.Commit()
}

func (r *Repository) ListRevocations(ctx context.Context) ([]domain.Revocation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT revocation_id,licence_id,reason_code,reason_text,revoked_at FROM revocations ORDER BY revoked_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Revocation
	for rows.Next() {
		var rev domain.Revocation
		var reason sql.NullString
		var revokedAt string
		if err = rows.Scan(&rev.RevocationID, &rev.LicenceID, &rev.ReasonCode, &reason, &revokedAt); err != nil {
			return nil, err
		}
		rev.ReasonText = reason.String
		rev.RevokedAt = parse(revokedAt)
		out = append(out, rev)
	}
	return out, rows.Err()
}

func (r *Repository) PendingOutbox(ctx context.Context, limit int) ([]domain.OutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, `SELECT event_id,event_type,event_json,created_at FROM archive_outbox WHERE archived_at IS NULL ORDER BY created_at LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.OutboxEvent
	for rows.Next() {
		var e domain.OutboxEvent
		var at string
		var event string
		if err = rows.Scan(&e.EventID, &e.EventType, &event, &at); err != nil {
			return nil, err
		}
		e.Event = json.RawMessage(event)
		e.CreatedAt = parse(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
func (r *Repository) MarkArchived(ctx context.Context, id string, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE archive_outbox SET archived_at=? WHERE event_id=?`, stamp(at), id)
	return err
}
func (r *Repository) ArchiveStatus(ctx context.Context) (int, *time.Time, error) {
	var n int
	var raw sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*),MIN(created_at) FROM archive_outbox WHERE archived_at IS NULL`).Scan(&n, &raw)
	if err != nil {
		return 0, nil, err
	}
	if !raw.Valid {
		return n, nil, nil
	}
	t := parse(raw.String)
	return n, &t, nil
}

func (r *Repository) VerifyAudit(ctx context.Context) error {
	order := "rowid"
	if r.db.dialect == dialectPostgres {
		order = "audit_sequence"
	}
	rows, err := r.db.QueryContext(ctx, `SELECT event_id,occurred_at,actor_type,actor_ref,event_type,aggregate_type,aggregate_id,request_id,event_json,previous_event_hash,event_hash FROM audit_events ORDER BY `+order)
	if err != nil {
		return err
	}
	defer rows.Close()
	var previous []byte
	for rows.Next() {
		var e domain.AuditEvent
		var at string
		var event string
		var actor, aggType, aggID, req sql.NullString
		if err = rows.Scan(&e.EventID, &at, &e.ActorType, &actor, &e.EventType, &aggType, &aggID, &req, &event, &e.PreviousHash, &e.Hash); err != nil {
			return err
		}
		e.Event = json.RawMessage(event)
		e.OccurredAt = parse(at)
		e.ActorRef = actor.String
		e.AggregateType = aggType.String
		e.AggregateID = aggID.String
		e.RequestID = req.String
		if !bytes.Equal(e.PreviousHash, previous) {
			return fmt.Errorf("audit chain broken at %s", e.EventID)
		}
		expected := auditHash(e)
		if !bytes.Equal(expected, e.Hash) {
			return fmt.Errorf("audit event hash invalid at %s", e.EventID)
		}
		previous = e.Hash
	}
	return rows.Err()
}

func (r *Repository) AppendAudit(ctx context.Context, event domain.AuditEvent) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = appendAudit(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

// ConsumeRateLimit atomically increments a fixed-window counter. The caller
// supplies only an opaque, keyed digest, so raw IP addresses and subjects are
// never persisted. SQLite's single-statement UPSERT coordinates independent
// licd processes sharing the same database.
func (r *Repository) ConsumeRateLimit(ctx context.Context, scopeKey string, windowStart, expiresAt time.Time, limit int) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
INSERT INTO rate_limit_counters(scope_key,window_start,expires_at,request_count)
VALUES(?,?,?,1)
ON CONFLICT(scope_key,window_start) DO UPDATE SET
  request_count=MIN(rate_limit_counters.request_count+1, ?),
  expires_at=excluded.expires_at
RETURNING request_count`, scopeKey, stamp(windowStart), stamp(expiresAt), limit+1).Scan(&count)
	if err != nil {
		return 0, err
	}
	// Bound storage without making cleanup part of the security decision.
	if count == 1 {
		_, _ = r.db.ExecContext(ctx, `DELETE FROM rate_limit_counters WHERE expires_at < ?`, stamp(time.Now().UTC()))
	}
	return count, nil
}

const licenceSelect = `SELECT licence_id,product_id,licence_type,customer_ref,purchase_ref,issuer_key_id,issued_at,not_before,expires_at,status,payload_hash,signed_artifact,metadata_json,created_at FROM licences`

type scanner interface{ Scan(...any) error }

func scanLicence(s scanner) (domain.LicenceRecord, error) {
	var l domain.LicenceRecord
	var customer, purchase, expiry, metadata sql.NullString
	var issued, notBefore, created string
	err := s.Scan(&l.LicenceID, &l.ProductID, &l.LicenceType, &customer, &purchase, &l.IssuerKeyID, &issued, &notBefore, &expiry, &l.Status, &l.PayloadHash, &l.SignedArtifact, &metadata, &created)
	if err != nil {
		return l, classify(err)
	}
	l.CustomerRef = customer.String
	l.PurchaseRef = purchase.String
	l.IssuedAt = parse(issued)
	l.NotBefore = parse(notBefore)
	if expiry.Valid {
		t := parse(expiry.String)
		l.ExpiresAt = &t
	}
	if metadata.Valid {
		l.Metadata = json.RawMessage(metadata.String)
	}
	l.CreatedAt = parse(created)
	return l, nil
}

func appendAudit(ctx context.Context, tx *transaction, e domain.AuditEvent) error {
	// Serialize chain-tip selection in SQLite and PostgreSQL. This prevents
	// concurrent transactions from branching from the same previous hash.
	if _, err := tx.ExecContext(ctx, `UPDATE audit_write_lock SET token=token WHERE lock_id=1`); err != nil {
		return err
	}
	var prev []byte
	order := "rowid"
	if tx.dialect == dialectPostgres {
		order = "audit_sequence"
	}
	err := tx.QueryRowContext(ctx, `SELECT event_hash FROM audit_events ORDER BY `+order+` DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e.PreviousHash = prev
	e.Hash = auditHash(e)
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events(event_id,occurred_at,actor_type,actor_ref,event_type,aggregate_type,aggregate_id,request_id,event_json,previous_event_hash,event_hash)VALUES(?,?,?,?,?,?,?,?,?,?,?)`, e.EventID, stamp(e.OccurredAt), e.ActorType, nullString(e.ActorRef), e.EventType, nullString(e.AggregateType), nullString(e.AggregateID), nullString(e.RequestID), string(e.Event), nullableBytes(e.PreviousHash), e.Hash)
	return err
}
func auditHash(e domain.AuditEvent) []byte {
	h := sha256.New()
	h.Write(e.PreviousHash)
	h.Write([]byte(e.EventID))
	h.Write([]byte("\n" + stamp(e.OccurredAt) + "\n" + e.ActorType + "\n" + e.ActorRef + "\n" + e.EventType + "\n" + e.AggregateType + "\n" + e.AggregateID + "\n" + e.RequestID + "\n"))
	h.Write(e.Event)
	return h.Sum(nil)
}
func classify(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
		return domain.ErrConflict
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return domain.ErrConflict
	}
	return err
}
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
func parse(s string) time.Time { t, _ := time.Parse(time.RFC3339Nano, s); return t }
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return stamp(*t)
}
func nullJSON(j json.RawMessage) any {
	if len(j) == 0 {
		return nil
	}
	return string(j)
}
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
