package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
)

func TestDestructiveMigrationRequiresExplicitRecentVerifiedBackup(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(t.TempDir(), "migration.db")
	repo, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	original := migrations
	migrations = append(append([]migration(nil), migrations...), migration{Name: "remove-obsolete-rate-limits", Class: MigrationDestructive, SQL: `DROP TABLE rate_limit_counters;`})
	defer func() { migrations = original }()

	plan, err := repo.MigrationPlan(ctx)
	if err != nil || len(plan) != 1 || plan[0].Class != MigrationDestructive {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if err = repo.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "explicit `licctl db migrate`") {
		t.Fatalf("startup migration was not rejected: %v", err)
	}
	if err = repo.MigrateWithOptions(ctx, MigrationOptions{AllowDestructive: true}); err == nil || !strings.Contains(err.Error(), "no verified backup") {
		t.Fatalf("migration without backup was not rejected: %v", err)
	}

	now := time.Now().UTC()
	backupPath := filepath.Join(t.TempDir(), "verified.db")
	if err = repo.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	backupCfg := cfg
	backupCfg.Database.DSN = backupPath
	backupRepo, err := Open(backupCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = backupRepo.Verify(ctx, true); err != nil {
		backupRepo.Close()
		t.Fatal(err)
	}
	if err = backupRepo.Close(); err != nil {
		t.Fatal(err)
	}
	backupSum := sha256.Sum256(backupBytes)
	verification := domain.BackupVerification{VerificationID: uuid.NewString(), Location: backupPath, SHA256: fmt.Sprintf("%x", backupSum), SizeBytes: int64(len(backupBytes)), VerifiedAt: now}
	payload, _ := json.Marshal(map[string]any{"result": "success", "sha256": verification.SHA256})
	audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "administrator", ActorRef: "test", EventType: "backup.verified", AggregateType: "backup", AggregateID: "verified.db", Event: payload}
	if err = repo.RecordBackupVerification(ctx, verification, audit); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(backupPath, []byte("tampered backup bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = repo.MigrateWithOptions(ctx, MigrationOptions{AllowDestructive: true, BackupMaxAge: time.Hour, Now: now.Add(time.Minute)}); err == nil || !strings.Contains(err.Error(), "changed since verification") {
		t.Fatalf("changed backup evidence accepted: %v", err)
	}
	if err = os.WriteFile(backupPath, backupBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = repo.MigrateWithOptions(ctx, MigrationOptions{AllowDestructive: true, BackupMaxAge: time.Hour, Now: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.db.ExecContext(ctx, `SELECT 1 FROM rate_limit_counters LIMIT 1`); err == nil {
		t.Fatal("destructive migration did not run")
	}
}

func TestDestructiveMigrationEmergencyOverrideAndStaleBackup(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(t.TempDir(), "forced.db")
	repo, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	original := migrations
	migrations = append(append([]migration(nil), migrations...), migration{Name: "remove-rate-limits", Class: MigrationDestructive, SQL: `DROP TABLE rate_limit_counters;`})
	defer func() { migrations = original }()

	old := time.Now().UTC().Add(-48 * time.Hour)
	verification := domain.BackupVerification{VerificationID: uuid.NewString(), Location: "old.db", SHA256: strings.Repeat("b", 64), SizeBytes: 1, VerifiedAt: old}
	audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: old, ActorType: "administrator", EventType: "backup.verified", AggregateType: "backup", AggregateID: "old.db", Event: json.RawMessage(`{"result":"success"}`)}
	if err = repo.RecordBackupVerification(ctx, verification, audit); err != nil {
		t.Fatal(err)
	}
	if err = repo.MigrateWithOptions(ctx, MigrationOptions{AllowDestructive: true, BackupMaxAge: time.Hour}); err == nil || !strings.Contains(err.Error(), "older than") {
		t.Fatalf("stale backup accepted: %v", err)
	}
	if err = repo.MigrateWithOptions(ctx, MigrationOptions{AllowDestructive: true, ForceWithoutBackup: true}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(repo.VerifyAudit(ctx), nil) {
		t.Fatal("audit chain failed after forced migration")
	}
}
