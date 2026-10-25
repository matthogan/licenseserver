package recoverydrill

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	archivepkg "github.com/matthogan/licenceserver/internal/archive"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/continuousbackup"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/rootkey"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

func TestSimulationPersistsCompleteIsolatedReport(t *testing.T) {
	ctx := context.Background()
	manager, repo, cfg := newTestManager(t)
	defer repo.Close()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	report, err := manager.RunNow(ctx, Request{Mode: ModeSimulation, Trigger: "test"})
	if err != nil {
		t.Fatalf("run simulation: %v; report=%+v", err, report)
	}
	if report.Status != StatusPassed || report.RecoveryPointAt == nil || !report.Objectives.RPOMet || !report.Objectives.RTOMet {
		t.Fatalf("unexpected report status/objectives: %+v", report)
	}
	for _, required := range []string{"isolated_restore", "deletion_suppressions", "database_integrity", "audit_chain", "licence_signatures", "restored_service_restart", "archive_reconstruction", "database_archive_reconciliation", "artifact_checksums", "resource_limits"} {
		if !hasPassedCheck(report, required) {
			t.Fatalf("missing passed check %q in %+v", required, report.Checks)
		}
	}
	stored, err := manager.Get(ctx, report.DrillID)
	if err != nil || stored.Artifacts.RestoredDatabaseSHA256 == "" || stored.Artifacts.RebuiltDatabaseSHA256 == "" {
		t.Fatalf("stored report=%+v err=%v", stored, err)
	}
	if _, err = filepath.Abs(cfg.RecoveryDrill.ReportDirectory); err != nil {
		t.Fatal(err)
	}
}

func TestSimulationReappliesSuppressionTombstones(t *testing.T) {
	ctx := context.Background()
	manager, repo, _ := newTestManager(t)
	defer repo.Close()
	now := time.Now().UTC().Add(-time.Minute)
	tombstone := domain.SuppressionTombstone{SchemaVersion: 1, SubjectType: "licence", SubjectDigest: "d7f26c09f631e20ab57327d91f4d3f06af9d0a54055eb43cfc707e98a6af67c9", DeletedAt: now, ReasonCode: "customer_deletion", PolicyVersion: 1}
	payload, _ := json.Marshal(map[string]string{"result": "success"})
	audit := domain.AuditEvent{EventID: "suppression-test", OccurredAt: now, ActorType: "test", EventType: "data.suppressions_applied", Event: payload}
	if _, err := repo.ApplySuppressionTombstones(ctx, []domain.SuppressionTombstone{tombstone}, now, audit); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	report, err := manager.RunNow(ctx, Request{Mode: ModeSimulation, Trigger: "test"})
	if err != nil {
		t.Fatalf("run simulation: %v; report=%+v", err, report)
	}
	if report.DatabaseCounts.SuppressionTombstones != 1 || report.ArchiveCounts.Suppressions != 1 {
		t.Fatalf("suppression evidence missing: %+v", report)
	}
}

func TestStatusWarnsAndBlocksWhenRequiredReportIsOverdue(t *testing.T) {
	ctx := context.Background()
	manager, repo, cfg := newTestManager(t)
	defer repo.Close()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	report, err := manager.RunNow(ctx, Request{Mode: ModeSimulation, Trigger: "test"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.RecoveryDrill.Enabled = true
	cfg.RecoveryDrill.Required = true
	restarted := New(cfg, repo, archivepkg.Disabled{}, nil)
	if err = restarted.Start(ctx); err != nil {
		t.Fatal(err)
	}
	status := restarted.Status(report.CompletedAt.Add(cfg.RecoveryDrill.MaxReportAge + time.Second))
	if !status.Overdue || status.Readiness != "blocked" || restarted.Ready(report.CompletedAt.Add(cfg.RecoveryDrill.MaxReportAge+time.Second)) {
		t.Fatalf("overdue status=%+v", status)
	}
}

func TestResourceViolationProducesPersistentFailure(t *testing.T) {
	ctx := context.Background()
	manager, repo, _ := newTestManager(t)
	defer repo.Close()
	manager.cfg.RecoveryDrill.MaxMemoryBytes = 1
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	report, err := manager.RunNow(ctx, Request{Mode: ModeSimulation, Trigger: "test"})
	if err == nil || report.Status != StatusFailed || report.FailureCode != "resource_limit_exceeded" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	stored, getErr := manager.Get(ctx, report.DrillID)
	if getErr != nil || stored.FailureCode != report.FailureCode {
		t.Fatalf("stored=%+v err=%v", stored, getErr)
	}
	if status := manager.Status(time.Now().UTC()); status.Readiness != "warning" {
		t.Fatalf("failed drill readiness=%+v", status)
	}
}

func TestRestartEvidenceMustProveNewBoot(t *testing.T) {
	now := time.Now().UTC()
	if err := validateRestartEvidence(RestartEvidence{BeforeBootID: "same", AfterBootID: "same", RestartedAt: now}, now); err == nil {
		t.Fatal("accepted unchanged boot identity")
	}
	if err := validateRestartEvidence(RestartEvidence{BeforeBootID: "old", AfterBootID: "new", RestartedAt: now, ReadyAfterSeconds: 3}, now); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialedCoordinatorUsesRemoteRecoveryPointAndArchive(t *testing.T) {
	ctx := context.Background()
	manager, repo, _ := newTestManager(t)
	defer repo.Close()
	manager.archive = &memoryArchive{}
	recoveryPoint := time.Now().UTC().Add(-2 * time.Second)
	manager.restorePoints = func(context.Context, config.Config) ([]continuousbackup.RestorePoint, error) {
		return []continuousbackup.RestorePoint{{Level: 1, MinTXID: "1", MaxTXID: "2", Timestamp: recoveryPoint}}, nil
	}
	manager.restore = func(ctx context.Context, _ config.Config, output string, _ *time.Time, _ bool) (continuousbackup.RestoreResult, error) {
		if err := repo.Backup(ctx, output); err != nil {
			return continuousbackup.RestoreResult{}, err
		}
		return continuousbackup.RestoreResult{Status: "restored", Output: output}, nil
	}
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	report, err := manager.RunNow(ctx, Request{Mode: ModeCredentialed, Trigger: "test"})
	if err != nil {
		t.Fatalf("credentialed coordinator: %v report=%+v", err, report)
	}
	if report.Mode != ModeCredentialed || report.RecoveryPointAt == nil || !report.RecoveryPointAt.Equal(recoveryPoint) || report.Objectives.RPOSeconds < 2 {
		t.Fatalf("remote recovery evidence=%+v", report)
	}
}

func TestAsyncDrillAuditsAttemptAndResult(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, repo, cfg := newTestManager(t)
	defer repo.Close()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	id, err := manager.Trigger(Request{Mode: ModeSimulation, Trigger: "manual", Actor: "test-admin", RequestID: "req-drill"})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !manager.Status(time.Now().UTC()).Running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	report, err := manager.Get(ctx, id)
	if err != nil || report.Status != StatusPassed {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(cfg.Database.DSN))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE aggregate_id=? AND event_type IN ('recovery_drill.started','recovery_drill.completed')`, id).Scan(&count); err != nil || count != 2 {
		t.Fatalf("drill audit count=%d err=%v", count, err)
	}
}

func TestStartRemovesOnlyStaleOwnedTemporaryPaths(t *testing.T) {
	manager, repo, cfg := newTestManager(t)
	defer repo.Close()
	if err := os.MkdirAll(cfg.RecoveryDrill.ReportDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(cfg.RecoveryDrill.ReportDirectory, ".isolated-drill-stale")
	recent := filepath.Join(cfg.RecoveryDrill.ReportDirectory, ".isolated-drill-recent")
	unowned := filepath.Join(cfg.RecoveryDrill.ReportDirectory, "operator-data")
	for _, path := range []string{stale, recent, unowned} {
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-cfg.RecoveryDrill.Timeout - 2*time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	manager.cfg.RecoveryDrill.Enabled = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale drill directory remains: %v", err)
	}
	for _, path := range []string{recent, unowned} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("valid path %s removed: %v", path, err)
		}
	}
}

func TestSimulationExercisesConfiguredHTTPSReverseProxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/service-info" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		_ = json.NewEncoder(w).Encode(map[string]string{"api_version": "v1"})
	}))
	defer server.Close()
	manager, repo, _ := newTestManager(t)
	defer repo.Close()
	manager.cfg.RecoveryDrill.ReverseProxyURL = server.URL
	manager.cfg.RecoveryDrill.RequireReverseProxy = true
	manager.httpClient = server.Client()
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	report, err := manager.RunNow(context.Background(), Request{Mode: ModeSimulation, Trigger: "test"})
	if err != nil || !hasPassedCheck(report, "reverse_proxy") {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func newTestManager(t *testing.T) (*Manager, *sqliterepo.Repository, config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(dir, "primary.db")
	cfg.RecoveryDrill.ReportDirectory = filepath.Join(dir, "reports")
	cfg.RecoveryDrill.MaxMemoryBytes = ^uint64(0)
	cfg.RecoveryDrill.MaxTemporaryStorageBytes = 1 << 40
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(context.Background()); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	rootPublic, _, err := signing.GenerateKey()
	if err != nil {
		repo.Close()
		t.Fatal(err)
	}
	if err = rootkey.New(repo, nil).Initialize(context.Background(), rootPublic); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	return New(cfg, repo, archivepkg.Disabled{}, nil), repo, cfg
}

func hasPassedCheck(report Report, name string) bool {
	for _, check := range report.Checks {
		if check.Name == name && check.Status == "passed" {
			return true
		}
	}
	return false
}
