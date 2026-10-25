package sqlite

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
)

func TestDatabaseWriteLockFailsWithoutPartialCommitAndRecovers(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(t.TempDir(), "locked.db")
	cfg.Database.SQLite.BusyTimeout = 20 * time.Millisecond
	repo, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	lock, err := repo.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lock.ExecContext(ctx, `UPDATE audit_write_lock SET token=token+1 WHERE lock_id=1`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	product := domain.Product{ProductID: "locked-product", DisplayName: "Locked", Active: true, DefaultTrialSeconds: 3600, CreatedAt: now}
	audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "test", EventType: "product.created", AggregateType: "product", AggregateID: product.ProductID, Event: json.RawMessage(`{"result":"success"}`)}
	writeCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if err = repo.CreateProduct(writeCtx, product, audit); err == nil {
		t.Fatal("write unexpectedly succeeded while database was locked")
	}
	if rollbackErr := lock.Rollback(); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
	if _, err = repo.GetProduct(ctx, product.ProductID); err == nil {
		t.Fatal("locked transaction left a partial product")
	}
	audit.EventID = uuid.NewString()
	if err = repo.CreateProduct(ctx, product, audit); err != nil {
		t.Fatalf("database did not recover after lock release: %v", err)
	}
}
