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

func TestMaintenanceStatePersistsAcrossRepositoryRestart(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(t.TempDir(), "maintenance.db")
	repo, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	state := domain.MaintenanceState{Enabled: true, Reason: "restart test", ChangedAt: now, ChangedBy: "administrator"}
	audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "administrator", ActorRef: "test", EventType: "maintenance.enabled", AggregateType: "service", AggregateID: "maintenance", Event: json.RawMessage(`{"result":"success"}`)}
	if err = repo.SetMaintenance(ctx, state, audit); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	loaded, err := repo.GetMaintenance(ctx)
	if err != nil || !loaded.Enabled || loaded.Reason != state.Reason || loaded.ChangedBy != state.ChangedBy || !loaded.ChangedAt.Equal(now) {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}
