package sqlite

import (
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/config"
)

func TestActivationMigrationPreservesLegacyCodes(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(t.TempDir(), "legacy.db")
	repo, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if _, err = repo.db.ExecContext(ctx, `CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = repo.db.ExecContext(ctx, migrations[i].SQL); err != nil {
			t.Fatal(err)
		}
		if _, err = repo.db.ExecContext(ctx, `INSERT INTO schema_migrations(version,applied_at) VALUES(?,?)`, i+1, stamp(time.Now())); err != nil {
			t.Fatal(err)
		}
	}
	now := stamp(time.Now())
	if _, err = repo.db.ExecContext(ctx, `INSERT INTO products(product_id,display_name,default_trial_seconds,active,created_at) VALUES('product','Product',3600,1,?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.db.ExecContext(ctx, `INSERT INTO licences(licence_id,product_id,licence_type,issuer_key_id,issued_at,not_before,status,payload_hash,signed_artifact,created_at) VALUES('licence','product','perpetual','issuer',?,?,'active',X'00',X'00',?)`, now, now, now); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("LEGACYCODE"))
	if _, err = repo.db.ExecContext(ctx, `INSERT INTO activation_codes(activation_id,code_hash,licence_id,max_uses,use_count,created_at) VALUES('legacy',?,'licence',1,0,?)`, hash[:], now); err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	code, err := repo.GetActivationCode(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if code.HashVersion != "sha256-v1" || string(code.CodeHash) != string(hash[:]) {
		t.Fatalf("legacy code changed: %+v", code)
	}
	if _, err = repo.db.ExecContext(ctx, `SELECT 1 FROM activation_records LIMIT 1`); err != nil {
		t.Fatal(err)
	}
}
