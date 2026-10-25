package sqlite

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (r *Repository) Backup(ctx context.Context, output string) error {
	if r.db.dialect == dialectPostgres {
		return errors.New("physical PostgreSQL backup must use pg_basebackup or the managed database backup facility")
	}
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("refusing to overwrite %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	abs, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return err
	}
	escaped := strings.ReplaceAll(filepath.ToSlash(abs), "'", "''")
	if _, err = r.db.ExecContext(ctx, "VACUUM INTO '"+escaped+"'"); err != nil {
		return err
	}
	return nil
}

func (r *Repository) ExportLogical(ctx context.Context, destination, appVersion string) error {
	return r.ExportLogicalWithOptions(ctx, destination, appVersion, true)
}

func (r *Repository) ExportLogicalWithOptions(ctx context.Context, destination, appVersion string, includeAudit bool) error {
	if err := os.Mkdir(destination, 0o750); err != nil {
		return fmt.Errorf("create export directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	tables := []struct{ name, file, query string }{
		{"products", "products.ndjson", "SELECT * FROM products"},
		{"licences", "licences.ndjson", "SELECT * FROM licences"},
		{"trials", "trials.ndjson", "SELECT * FROM trials"},
		{"activation_codes", "activation-codes.ndjson", "SELECT * FROM activation_codes"},
		{"activation_records", "activations.ndjson", "SELECT * FROM activation_records"},
		{"revocations", "revocations.ndjson", "SELECT * FROM revocations"},
		{"signing_keys", "signing-public-metadata.ndjson", "SELECT issuer_key_id,algorithm,public_key,issuer_certificate,authority_not_before,authority_not_after,products_json,status,registered_at,activated_at,retired_at,state_reason FROM signing_keys"},
		{"root_keys", "root-keyring.ndjson", "SELECT root_key_id,algorithm,public_key,fingerprint,status,accept_certificates_not_before,accept_certificates_before,source_transition_id,registered_at,activated_at,retired_at,state_reason FROM root_keys"},
		{"root_transitions", "root-transitions.ndjson", "SELECT * FROM root_transitions"},
	}
	if includeAudit {
		tables = append(tables, struct{ name, file, query string }{"audit_events", "audit-events.ndjson", "SELECT * FROM audit_events"})
	}
	counts := map[string]int{}
	files := make([]string, 0, len(tables)+1)
	for _, table := range tables {
		n, err := r.exportQuery(ctx, table.query, filepath.Join(destination, table.file))
		if err != nil {
			return err
		}
		counts[table.name] = n
		files = append(files, table.file)
	}
	var schema int
	if err := r.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&schema); err != nil {
		return err
	}
	manifest := map[string]any{"schema_version": 1, "created_at": time.Now().UTC(), "application_version": appVersion, "database_schema_version": schema, "record_counts": counts}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err = os.WriteFile(filepath.Join(destination, "manifest.json"), b, 0o640); err != nil {
		return err
	}
	files = append(files, "manifest.json")
	checksum, err := os.OpenFile(filepath.Join(destination, "checksums.sha256"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer checksum.Close()
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if _, err = fmt.Fprintf(checksum, "%s  %s\n", hex.EncodeToString(sum[:]), name); err != nil {
			return err
		}
	}
	if err = checksum.Sync(); err != nil {
		return err
	}
	ok = true
	return nil
}

// ExportAudit writes the complete chained audit stream as NDJSON without
// mutating or re-encoding individual event columns.
func (r *Repository) ExportAudit(ctx context.Context, destination string) error {
	if _, err := os.Stat(destination); err == nil {
		return fmt.Errorf("refusing to overwrite %s", destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
		return err
	}
	_, err := r.exportQuery(ctx, "SELECT * FROM audit_events", destination)
	return err
}

func (r *Repository) exportTable(ctx context.Context, table, path string) (int, error) {
	return r.exportQuery(ctx, "SELECT * FROM "+table, path)
}

func (r *Repository) exportQuery(ctx context.Context, query, path string) (int, error) {
	order := "rowid"
	if r.db.dialect == dialectPostgres {
		order = "1"
	}
	rows, err := r.db.QueryContext(ctx, query+" ORDER BY "+order)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	count := 0
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err = rows.Scan(ptrs...); err != nil {
			return count, err
		}
		record := make(map[string]any, len(cols))
		for i, col := range cols {
			record[col] = values[i]
		}
		b, err := json.Marshal(record)
		if err != nil {
			return count, err
		}
		if _, err = w.Write(append(b, '\n')); err != nil {
			return count, err
		}
		count++
	}
	if err = rows.Err(); err != nil {
		return count, err
	}
	if err = w.Flush(); err != nil {
		return count, err
	}
	if err = f.Sync(); err != nil {
		return count, err
	}
	return count, nil
}
