// Package recoverydrill coordinates isolated recovery verification without
// ever promoting a drill database into the live service path.
package recoverydrill

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/continuousbackup"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/recovery"
	"github.com/matthogan/licenceserver/internal/rootkey"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

const (
	ReportSchemaVersion    = 1
	ModeSimulation         = "simulation"
	ModeCredentialed       = "credentialed"
	StatusPassed           = "passed"
	StatusFailed           = "failed"
	StatusObjectivesMissed = "objectives_missed"
	maxReportBytes         = 2 * 1024 * 1024
)

var ErrAlreadyRunning = errors.New("a recovery drill is already running")

type RestartEvidence struct {
	BeforeBootID      string    `json:"before_boot_id"`
	AfterBootID       string    `json:"after_boot_id"`
	RestartedAt       time.Time `json:"restarted_at"`
	ReadyAfterSeconds float64   `json:"ready_after_seconds"`
}

type Request struct {
	Mode            string           `json:"mode,omitempty"`
	Trigger         string           `json:"trigger,omitempty"`
	Actor           string           `json:"-"`
	RequestID       string           `json:"-"`
	RestartEvidence *RestartEvidence `json:"restart_evidence,omitempty"`
}

type Check struct {
	Name            string  `json:"name"`
	Status          string  `json:"status"`
	ReasonCode      string  `json:"reason_code,omitempty"`
	Detail          string  `json:"detail,omitempty"`
	DurationSeconds float64 `json:"duration_seconds"`
}

type RecordCounts struct {
	Products              int `json:"products"`
	Licences              int `json:"licences"`
	PaidLicences          int `json:"paid_licences"`
	Activations           int `json:"activations"`
	Revocations           int `json:"revocations"`
	RelevantAuditRecords  int `json:"relevant_audit_records"`
	IssuerKeys            int `json:"issuer_keys"`
	RootKeys              int `json:"root_keys"`
	RootTransitions       int `json:"root_transitions"`
	SuppressionTombstones int `json:"suppression_tombstones"`
}

type ArchiveCounts struct {
	Events       int `json:"events"`
	Issued       int `json:"issued"`
	Revoked      int `json:"revoked"`
	Suppressions int `json:"suppressions"`
	Rebuilt      int `json:"rebuilt_licences"`
}

type Objectives struct {
	RPOSeconds       float64 `json:"rpo_seconds"`
	RPOObjectiveSecs float64 `json:"rpo_objective_seconds"`
	RPOMet           bool    `json:"rpo_met"`
	RTOSeconds       float64 `json:"rto_seconds"`
	RTOObjectiveSecs float64 `json:"rto_objective_seconds"`
	RTOMet           bool    `json:"rto_met"`
}

type ResourceUsage struct {
	MemoryBytes         uint64 `json:"memory_bytes"`
	MemoryLimitBytes    uint64 `json:"memory_limit_bytes"`
	Goroutines          int    `json:"goroutines"`
	GoroutineLimit      int    `json:"goroutine_limit"`
	TemporaryBytes      int64  `json:"temporary_bytes"`
	TemporaryLimitBytes int64  `json:"temporary_limit_bytes"`
}

type ArtifactEvidence struct {
	RestoredDatabaseSHA256 string `json:"restored_database_sha256,omitempty"`
	RestoredDatabaseBytes  int64  `json:"restored_database_bytes,omitempty"`
	RebuiltDatabaseSHA256  string `json:"rebuilt_database_sha256,omitempty"`
	RebuiltDatabaseBytes   int64  `json:"rebuilt_database_bytes,omitempty"`
}

type Report struct {
	SchemaVersion   int                   `json:"schema_version"`
	DrillID         string                `json:"drill_id"`
	Mode            string                `json:"mode"`
	Trigger         string                `json:"trigger"`
	Status          string                `json:"status"`
	StartedAt       time.Time             `json:"started_at"`
	CompletedAt     time.Time             `json:"completed_at"`
	RecoveryPointAt *time.Time            `json:"recovery_point_at,omitempty"`
	Objectives      Objectives            `json:"objectives"`
	DatabaseCounts  RecordCounts          `json:"database_counts"`
	ArchiveCounts   ArchiveCounts         `json:"archive_counts"`
	Suppressions    domain.DeletionCounts `json:"suppressions_applied"`
	Resources       ResourceUsage         `json:"resources"`
	Artifacts       ArtifactEvidence      `json:"artifacts"`
	Checks          []Check               `json:"checks"`
	Alerts          []string              `json:"alerts,omitempty"`
	FailureCode     string                `json:"failure_code,omitempty"`
	FailureDetail   string                `json:"failure_detail,omitempty"`
}

type Status struct {
	Enabled          bool       `json:"enabled"`
	Required         bool       `json:"required"`
	ConfiguredMode   string     `json:"configured_mode"`
	Running          bool       `json:"running"`
	RunningDrillID   string     `json:"running_drill_id,omitempty"`
	Latest           *Report    `json:"latest_report,omitempty"`
	LastSuccessfulAt *time.Time `json:"last_successful_at,omitempty"`
	NextScheduledAt  *time.Time `json:"next_scheduled_at,omitempty"`
	Overdue          bool       `json:"overdue"`
	Readiness        string     `json:"readiness"`
	Alerts           []string   `json:"alerts,omitempty"`
}

type Metrics struct {
	Runs          uint64
	Failures      uint64
	Running       bool
	Overdue       bool
	LastSuccess   *time.Time
	LastRPO       float64
	LastRTO       float64
	ObjectivesMet bool
}

type Manager struct {
	cfg     config.Config
	repo    domain.Repository
	archive domain.ArchiveStore
	logger  *slog.Logger
	now     func() time.Time

	mu               sync.RWMutex
	runningID        string
	latest           *Report
	lastSuccessfulAt *time.Time
	ctx              context.Context
	runs             atomic.Uint64
	failures         atomic.Uint64
	restorePoints    func(context.Context, config.Config) ([]continuousbackup.RestorePoint, error)
	restore          func(context.Context, config.Config, string, *time.Time, bool) (continuousbackup.RestoreResult, error)
	httpClient       *http.Client
}

func New(cfg config.Config, repo domain.Repository, archive domain.ArchiveStore, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Manager{cfg: cfg, repo: repo, archive: archive, logger: logger, now: func() time.Time { return time.Now().UTC() }, restorePoints: continuousbackup.RestorePoints, restore: continuousbackup.Restore, httpClient: client}
}

func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
	if !m.cfg.RecoveryDrill.Enabled {
		if _, err := os.Stat(m.cfg.RecoveryDrill.ReportDirectory); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
	} else if err := os.MkdirAll(m.cfg.RecoveryDrill.ReportDirectory, 0o750); err != nil {
		return fmt.Errorf("create recovery drill report directory: %w", err)
	}
	if err := m.cleanupReports(m.now()); err != nil {
		return err
	}
	if err := m.cleanupStaleTemporary(m.now()); err != nil {
		return err
	}
	reports, err := m.List(ctx, 1000)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if len(reports) > 0 {
		copy := reports[0]
		m.latest = &copy
	}
	for _, report := range reports {
		if report.Status != StatusFailed {
			at := report.CompletedAt
			m.lastSuccessfulAt = &at
			break
		}
	}
	m.mu.Unlock()
	if m.cfg.RecoveryDrill.Enabled {
		go m.scheduleLoop(ctx)
	}
	return nil
}

func (m *Manager) scheduleLoop(ctx context.Context) {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			status := m.Status(m.now())
			if status.NextScheduledAt == nil || !status.NextScheduledAt.After(m.now()) {
				if _, err := m.Trigger(Request{Mode: m.cfg.RecoveryDrill.Mode, Trigger: "scheduled", Actor: "scheduler"}); err != nil && !errors.Is(err, ErrAlreadyRunning) {
					m.logger.Error("schedule recovery drill", "event", "recovery_drill.schedule", "result", "failure", "error", err)
				}
			}
			interval := time.Minute
			if m.cfg.RecoveryDrill.ScheduleInterval < interval {
				interval = m.cfg.RecoveryDrill.ScheduleInterval
			}
			timer.Reset(interval)
		}
	}
}

func (m *Manager) Trigger(request Request) (string, error) {
	if err := os.MkdirAll(m.cfg.RecoveryDrill.ReportDirectory, 0o750); err != nil {
		return "", fmt.Errorf("create recovery drill report directory: %w", err)
	}
	if request.Mode == "" {
		request.Mode = m.cfg.RecoveryDrill.Mode
	}
	if request.Mode != ModeSimulation && request.Mode != ModeCredentialed {
		return "", fmt.Errorf("invalid recovery drill mode %q", request.Mode)
	}
	if request.Mode == ModeCredentialed && (!m.cfg.Backup.Continuous.Enabled || m.cfg.Archive.Provider == "disabled") {
		return "", errors.New("credentialed mode requires configured continuous backup and immutable archive")
	}
	if request.Trigger == "" {
		request.Trigger = "manual"
	}
	id := "drill_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	m.mu.Lock()
	if m.runningID != "" {
		m.mu.Unlock()
		return "", ErrAlreadyRunning
	}
	m.runningID = id
	parent := m.ctx
	if parent == nil {
		parent = context.Background()
	}
	m.mu.Unlock()
	go m.executeAndPersist(parent, id, request)
	return id, nil
}

// RunNow executes synchronously. It exists for controlled local tooling and
// tests; the administrative API uses Trigger so HTTP timeouts cannot abort a
// long restore.
func (m *Manager) RunNow(ctx context.Context, request Request) (Report, error) {
	if err := os.MkdirAll(m.cfg.RecoveryDrill.ReportDirectory, 0o750); err != nil {
		return Report{}, fmt.Errorf("create recovery drill report directory: %w", err)
	}
	if request.Mode == "" {
		request.Mode = m.cfg.RecoveryDrill.Mode
	}
	if request.Trigger == "" {
		request.Trigger = "manual"
	}
	id := "drill_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	report := m.run(ctx, id, request)
	if err := m.writeReport(report); err != nil {
		return report, err
	}
	_ = m.cleanupReports(m.now())
	m.recordLatest(report)
	return report, statusError(report)
}

func (m *Manager) executeAndPersist(parent context.Context, id string, request Request) {
	ctx, cancel := context.WithTimeout(parent, m.cfg.RecoveryDrill.Timeout)
	defer cancel()
	started := m.now()
	_ = m.appendAudit(ctx, "recovery_drill.started", id, request, map[string]any{"result": "started", "mode": request.Mode, "trigger": request.Trigger}, started)
	report := m.run(ctx, id, request)
	writeErr := m.writeReport(report)
	if writeErr != nil {
		report.Status = StatusFailed
		report.FailureCode = "report_persistence_failed"
		report.FailureDetail = bounded(writeErr.Error())
		m.logger.Error("persist recovery drill report", "event", "recovery_drill.report", "result", "failure", "drill_id", id, "error", writeErr)
	} else if cleanupErr := m.cleanupReports(m.now()); cleanupErr != nil {
		m.logger.Warn("prune recovery drill reports", "event", "recovery_drill.retention", "result", "failure", "error", cleanupErr)
	}
	m.runs.Add(1)
	if report.Status != StatusPassed {
		m.failures.Add(1)
	}
	m.recordLatest(report)
	result := "success"
	eventType := "recovery_drill.completed"
	if report.Status != StatusPassed {
		result = "failure"
		eventType = "recovery_drill.failed"
	}
	_ = m.appendAudit(context.Background(), eventType, id, request, map[string]any{"result": result, "status": report.Status, "mode": report.Mode, "rpo_seconds": report.Objectives.RPOSeconds, "rto_seconds": report.Objectives.RTOSeconds, "alerts": report.Alerts, "failure_code": report.FailureCode}, report.CompletedAt)
	if report.Status == StatusPassed {
		m.logger.Info("recovery drill completed", "event", eventType, "result", result, "drill_id", id, "mode", report.Mode, "rpo_seconds", report.Objectives.RPOSeconds, "rto_seconds", report.Objectives.RTOSeconds)
	} else {
		m.logger.Error("recovery drill requires attention", "event", eventType, "result", result, "reason_code", report.FailureCode, "drill_id", id, "mode", report.Mode, "status", report.Status, "alerts", report.Alerts)
	}
	m.mu.Lock()
	if m.runningID == id {
		m.runningID = ""
	}
	m.mu.Unlock()
}

func (m *Manager) run(parent context.Context, id string, request Request) Report {
	started := m.now()
	report := Report{SchemaVersion: ReportSchemaVersion, DrillID: id, Mode: request.Mode, Trigger: request.Trigger, Status: StatusPassed, StartedAt: started}
	tempRoot, err := os.MkdirTemp(m.cfg.RecoveryDrill.ReportDirectory, ".isolated-drill-")
	if err != nil {
		return m.finishFailure(report, "isolation_failed", err)
	}
	defer os.RemoveAll(tempRoot)
	restoredPath := filepath.Join(tempRoot, "restored.db")
	rebuiltPath := filepath.Join(tempRoot, "archive-rebuilt.db")

	var source domain.ArchiveStore = m.archive
	var recoveryPoint time.Time
	checkStart := m.now()
	if request.Mode == ModeSimulation {
		backup, ok := m.repo.(interface {
			Backup(context.Context, string) error
		})
		if !ok {
			return m.finishFailure(report, "simulation_unsupported", errors.New("repository does not support an isolated SQLite snapshot"))
		}
		if err = backup.Backup(parent, restoredPath); err != nil {
			return m.finishFailure(report, "snapshot_failed", err)
		}
		recoveryPoint = m.now()
		source, err = m.syntheticArchive(parent)
		if err != nil {
			return m.finishFailure(report, "archive_simulation_failed", err)
		}
		report.Checks = append(report.Checks, passed("isolated_restore", "safe local snapshot; no S3/KMS credentials used", m.now().Sub(checkStart)))
	} else {
		points, pointErr := m.restorePoints(parent, m.cfg)
		if pointErr != nil || len(points) == 0 {
			if pointErr == nil {
				pointErr = errors.New("no remote restore points were returned")
			}
			return m.finishFailure(report, "restore_point_unavailable", pointErr)
		}
		recoveryPoint = points[0].Timestamp
		for _, point := range points[1:] {
			if point.Timestamp.After(recoveryPoint) {
				recoveryPoint = point.Timestamp
			}
		}
		if _, err = m.restore(parent, m.cfg, restoredPath, nil, false); err != nil {
			return m.finishFailure(report, "remote_restore_failed", err)
		}
		report.Checks = append(report.Checks, passed("isolated_restore", "restored from configured encrypted S3 replica", m.now().Sub(checkStart)))
	}
	report.RecoveryPointAt = &recoveryPoint
	if recoveryPoint.After(started.Add(time.Minute)) {
		return m.finishFailure(report, "invalid_recovery_point", errors.New("recovery point is in the future"))
	}

	restoreCfg := m.cfg
	restoreCfg.Database.Driver = "sqlite"
	restoreCfg.Database.DSN = restoredPath
	restored, err := sqliterepo.Open(restoreCfg)
	if err != nil {
		return m.finishFailure(report, "restored_database_open_failed", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = restored.Close()
		}
	}()

	checkStart = m.now()
	report.Suppressions, err = recovery.ApplyArchiveSuppressions(parent, restored, source, "recovery-drill", m.now())
	if err != nil {
		return m.finishFailure(report, "suppression_reconciliation_failed", err)
	}
	report.Checks = append(report.Checks, passed("deletion_suppressions", "immutable suppression tombstones reapplied before verification", m.now().Sub(checkStart)))

	checkStart = m.now()
	if err = restored.Verify(parent, true); err != nil {
		return m.finishFailure(report, "database_integrity_failed", err)
	}
	report.Checks = append(report.Checks, passed("database_integrity", "full integrity and foreign-key checks passed", m.now().Sub(checkStart)))
	checkStart = m.now()
	if err = restored.VerifyAudit(parent); err != nil {
		return m.finishFailure(report, "audit_chain_failed", err)
	}
	report.Checks = append(report.Checks, passed("audit_chain", "tamper-evident audit chain verified", m.now().Sub(checkStart)))
	if schema, schemaErr := restored.SchemaStatus(parent); schemaErr != nil || !schema.Compatible {
		if schemaErr == nil {
			schemaErr = fmt.Errorf("restored schema %d is not supported schema %d", schema.Current, schema.Supported)
		}
		return m.finishFailure(report, "schema_incompatible", schemaErr)
	}
	report.Checks = append(report.Checks, passed("schema_compatibility", "restored schema is exactly supported", 0))

	checkStart = m.now()
	report.DatabaseCounts, err = verifyRecords(parent, restored)
	if err != nil {
		return m.finishFailure(report, "licence_verification_failed", err)
	}
	report.Checks = append(report.Checks, passed("licence_signatures", fmt.Sprintf("verified %d signed licences", report.DatabaseCounts.Licences), m.now().Sub(checkStart)))

	checkStart = m.now()
	if err = restored.Close(); err != nil {
		return m.finishFailure(report, "restart_close_failed", err)
	}
	closed = true
	restored, err = sqliterepo.Open(restoreCfg)
	if err != nil {
		return m.finishFailure(report, "restart_reopen_failed", err)
	}
	closed = false
	if err = restored.Ping(parent); err != nil {
		return m.finishFailure(report, "restart_ping_failed", err)
	}
	report.Checks = append(report.Checks, passed("restored_service_restart", "restored state closed and reopened as a fresh service process would", m.now().Sub(checkStart)))

	if request.RestartEvidence == nil {
		report.Checks = append(report.Checks, skipped("host_service_restart", "run with --exercise-service-restart for OS service evidence"))
	} else if err = validateRestartEvidence(*request.RestartEvidence, started); err != nil {
		return m.finishFailure(report, "host_service_restart_invalid", err)
	} else {
		report.Checks = append(report.Checks, passed("host_service_restart", fmt.Sprintf("boot identity changed; readiness returned after %.3fs", request.RestartEvidence.ReadyAfterSeconds), time.Duration(request.RestartEvidence.ReadyAfterSeconds*float64(time.Second))))
	}

	currentRoots, err := m.repo.ListRootKeys(parent)
	if err != nil {
		return m.finishFailure(report, "root_keyring_unavailable", err)
	}
	checkStart = m.now()
	rebuild, err := recovery.RebuildFromStoreKeyring(parent, source, rebuiltPath, rootkey.KeyringFromRoots(currentRoots))
	if err != nil {
		return m.finishFailure(report, "archive_reconstruction_failed", err)
	}
	report.ArchiveCounts = ArchiveCounts{Events: rebuild.SourceEvents, Rebuilt: rebuild.Licences}
	events, err := source.ListEvents(parent)
	if err != nil {
		return m.finishFailure(report, "archive_listing_failed", err)
	}
	for _, event := range events {
		switch event.EventType {
		case "licence.issued":
			report.ArchiveCounts.Issued++
		case "licence.revoked":
			report.ArchiveCounts.Revoked++
		case "data.suppressed":
			report.ArchiveCounts.Suppressions++
		}
	}
	report.Checks = append(report.Checks, passed("archive_reconstruction", fmt.Sprintf("rebuilt %d paid licences from %d immutable events", rebuild.Licences, rebuild.SourceEvents), m.now().Sub(checkStart)))

	rebuiltCfg := restoreCfg
	rebuiltCfg.Database.DSN = rebuiltPath
	rebuiltRepo, err := sqliterepo.Open(rebuiltCfg)
	if err != nil {
		return m.finishFailure(report, "rebuilt_database_open_failed", err)
	}
	checkStart = m.now()
	err = comparePaidRecords(parent, restored, rebuiltRepo)
	closeErr := rebuiltRepo.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return m.finishFailure(report, "database_archive_mismatch", err)
	}
	report.Checks = append(report.Checks, passed("database_archive_reconciliation", "paid licence IDs, status and payload hashes match", m.now().Sub(checkStart)))
	if err = restored.Close(); err != nil {
		return m.finishFailure(report, "restored_database_close_failed", err)
	}
	closed = true

	report.Artifacts.RestoredDatabaseSHA256, report.Artifacts.RestoredDatabaseBytes, err = hashFile(restoredPath)
	if err != nil {
		return m.finishFailure(report, "restored_checksum_failed", err)
	}
	report.Artifacts.RebuiltDatabaseSHA256, report.Artifacts.RebuiltDatabaseBytes, err = hashFile(rebuiltPath)
	if err != nil {
		return m.finishFailure(report, "rebuilt_checksum_failed", err)
	}
	report.Checks = append(report.Checks, passed("artifact_checksums", "SHA-256 evidence recorded for both isolated databases", 0))

	if err = m.proxyCheck(parent, &report); err != nil {
		return m.finishFailure(report, "reverse_proxy_failed", err)
	}
	m.measureResources(tempRoot, &report)
	if report.Resources.MemoryBytes > report.Resources.MemoryLimitBytes || report.Resources.Goroutines > report.Resources.GoroutineLimit || report.Resources.TemporaryBytes > report.Resources.TemporaryLimitBytes {
		return m.finishFailure(report, "resource_limit_exceeded", errors.New("recovery drill exceeded a configured resource limit"))
	}
	report.Checks = append(report.Checks, passed("resource_limits", "memory, goroutine and temporary-storage budgets remained within policy", 0))

	completed := m.now()
	report.CompletedAt = completed
	report.Objectives = Objectives{
		RPOSeconds: completed.Sub(recoveryPoint).Seconds(), RPOObjectiveSecs: m.cfg.RecoveryDrill.RPOObjective.Seconds(),
		RTOSeconds: completed.Sub(started).Seconds(), RTOObjectiveSecs: m.cfg.RecoveryDrill.RTOObjective.Seconds(),
	}
	if report.Objectives.RPOSeconds < 0 {
		report.Objectives.RPOSeconds = 0
	}
	report.Objectives.RPOMet = report.Objectives.RPOSeconds <= report.Objectives.RPOObjectiveSecs
	report.Objectives.RTOMet = report.Objectives.RTOSeconds <= report.Objectives.RTOObjectiveSecs
	if !report.Objectives.RPOMet {
		report.Alerts = append(report.Alerts, "rpo_objective_missed")
	}
	if !report.Objectives.RTOMet {
		report.Alerts = append(report.Alerts, "rto_objective_missed")
	}
	if len(report.Alerts) > 0 {
		report.Status = StatusObjectivesMissed
	}
	return report
}

func (m *Manager) finishFailure(report Report, code string, err error) Report {
	report.Status = StatusFailed
	report.CompletedAt = m.now()
	report.FailureCode = code
	report.FailureDetail = bounded(err.Error())
	report.Alerts = append(report.Alerts, code)
	report.Checks = append(report.Checks, Check{Name: code, Status: "failed", ReasonCode: code, Detail: report.FailureDetail})
	if report.RecoveryPointAt != nil {
		report.Objectives.RPOSeconds = report.CompletedAt.Sub(*report.RecoveryPointAt).Seconds()
	}
	report.Objectives.RPOObjectiveSecs = m.cfg.RecoveryDrill.RPOObjective.Seconds()
	report.Objectives.RTOSeconds = report.CompletedAt.Sub(report.StartedAt).Seconds()
	report.Objectives.RTOObjectiveSecs = m.cfg.RecoveryDrill.RTOObjective.Seconds()
	report.Objectives.RPOMet = report.RecoveryPointAt != nil && report.Objectives.RPOSeconds <= report.Objectives.RPOObjectiveSecs
	report.Objectives.RTOMet = report.Objectives.RTOSeconds <= report.Objectives.RTOObjectiveSecs
	return report
}

func (m *Manager) syntheticArchive(ctx context.Context) (domain.ArchiveStore, error) {
	snapshot, err := m.repo.QueryDataExport(ctx, domain.DataExportFilter{})
	if err != nil {
		return nil, err
	}
	tombstones, err := m.repo.ListSuppressionTombstones(ctx)
	if err != nil {
		return nil, err
	}
	store := &memoryArchive{}
	for _, licence := range snapshot.Licences {
		if licence.LicenceType == "trial" {
			continue
		}
		store.events = append(store.events, domain.ArchiveEvent{SchemaVersion: 1, EventID: "simulation-issued-" + licence.LicenceID, EventType: "licence.issued", OccurredAt: licence.CreatedAt, LicenceID: licence.LicenceID, ProductID: licence.ProductID, CustomerRef: licence.CustomerRef, PurchaseRef: licence.PurchaseRef, PayloadHash: hex.EncodeToString(licence.PayloadHash), SignedLicenceArtifact: base64.RawURLEncoding.EncodeToString(licence.SignedArtifact), IssuerKeyID: licence.IssuerKeyID})
	}
	for _, revocation := range snapshot.Revocations {
		copy := revocation
		store.events = append(store.events, domain.ArchiveEvent{SchemaVersion: 1, EventID: "simulation-revoked-" + revocation.RevocationID, EventType: "licence.revoked", OccurredAt: revocation.RevokedAt, LicenceID: revocation.LicenceID, Revocation: &copy})
	}
	for i := range tombstones {
		copy := tombstones[i]
		store.events = append(store.events, domain.ArchiveEvent{SchemaVersion: 1, EventID: fmt.Sprintf("simulation-suppression-%06d", i), EventType: "data.suppressed", OccurredAt: copy.DeletedAt, Suppression: &copy})
	}
	return store, nil
}

type memoryArchive struct{ events []domain.ArchiveEvent }

func (m *memoryArchive) PutEvent(context.Context, domain.ArchiveEvent) error {
	return errors.New("simulation archive is read-only")
}
func (m *memoryArchive) ListEvents(context.Context) ([]domain.ArchiveEvent, error) {
	return append([]domain.ArchiveEvent(nil), m.events...), nil
}
func (m *memoryArchive) Verify(context.Context) error { return nil }

func verifyRecords(ctx context.Context, repo domain.Repository) (RecordCounts, error) {
	var counts RecordCounts
	snapshot, err := repo.QueryDataExport(ctx, domain.DataExportFilter{})
	if err != nil {
		return counts, err
	}
	roots, err := repo.ListRootKeys(ctx)
	if err != nil {
		return counts, err
	}
	keyring := rootkey.KeyringFromRoots(roots)
	for _, licence := range snapshot.Licences {
		payload, verifyErr := licencefmt.VerifyArtifactSignatureKeyring(keyring, licence.SignedArtifact, licence.ProductID)
		if verifyErr != nil {
			return counts, fmt.Errorf("licence %s: %w", licence.LicenceID, verifyErr)
		}
		if payload.LicenceID != licence.LicenceID {
			return counts, fmt.Errorf("licence %s signed payload identity mismatch", licence.LicenceID)
		}
		if licence.LicenceType != "trial" {
			counts.PaidLicences++
		}
	}
	products, err := repo.ListProducts(ctx)
	if err != nil {
		return counts, err
	}
	issuers, err := repo.ListIssuers(ctx)
	if err != nil {
		return counts, err
	}
	transitions, err := repo.ListRootTransitions(ctx)
	if err != nil {
		return counts, err
	}
	tombstones, err := repo.ListSuppressionTombstones(ctx)
	if err != nil {
		return counts, err
	}
	counts.Products = len(products)
	counts.Licences = len(snapshot.Licences)
	counts.Activations = len(snapshot.Activations)
	counts.Revocations = len(snapshot.Revocations)
	counts.RelevantAuditRecords = len(snapshot.AuditEvents)
	counts.IssuerKeys = len(issuers)
	counts.RootKeys = len(roots)
	counts.RootTransitions = len(transitions)
	counts.SuppressionTombstones = len(tombstones)
	return counts, nil
}

func comparePaidRecords(ctx context.Context, restored, rebuilt domain.Repository) error {
	a, err := restored.ListPaidLicences(ctx)
	if err != nil {
		return err
	}
	b, err := rebuilt.ListPaidLicences(ctx)
	if err != nil {
		return err
	}
	if len(a) != len(b) {
		return fmt.Errorf("restored paid licences=%d archive paid licences=%d", len(a), len(b))
	}
	byID := make(map[string]domain.LicenceRecord, len(b))
	paidIDs := make(map[string]struct{}, len(a))
	for _, record := range a {
		paidIDs[record.LicenceID] = struct{}{}
	}
	for _, record := range b {
		byID[record.LicenceID] = record
	}
	for _, record := range a {
		other, ok := byID[record.LicenceID]
		artifactA := sha256.Sum256(record.SignedArtifact)
		artifactB := sha256.Sum256(other.SignedArtifact)
		if !ok || record.Status != other.Status || record.ProductID != other.ProductID || record.IssuerKeyID != other.IssuerKeyID || record.CustomerRef != other.CustomerRef || record.PurchaseRef != other.PurchaseRef || !strings.EqualFold(hex.EncodeToString(record.PayloadHash), hex.EncodeToString(other.PayloadHash)) || artifactA != artifactB {
			return fmt.Errorf("paid licence %s differs between restored database and archive", record.LicenceID)
		}
	}
	allRevocationsA, err := restored.ListRevocations(ctx)
	if err != nil {
		return err
	}
	revocationsB, err := rebuilt.ListRevocations(ctx)
	if err != nil {
		return err
	}
	var revocationsA []domain.Revocation
	for _, revocation := range allRevocationsA {
		if _, paid := paidIDs[revocation.LicenceID]; paid {
			revocationsA = append(revocationsA, revocation)
		}
	}
	if len(revocationsA) != len(revocationsB) {
		return fmt.Errorf("restored revocations=%d archive revocations=%d", len(revocationsA), len(revocationsB))
	}
	revocationByLicence := make(map[string]domain.Revocation, len(revocationsB))
	for _, revocation := range revocationsB {
		revocationByLicence[revocation.LicenceID] = revocation
	}
	for _, revocation := range revocationsA {
		other, ok := revocationByLicence[revocation.LicenceID]
		if !ok || revocation.ReasonCode != other.ReasonCode || revocation.ReasonText != other.ReasonText || !revocation.RevokedAt.Equal(other.RevokedAt) {
			return fmt.Errorf("revocation for paid licence %s differs between restored database and archive", revocation.LicenceID)
		}
	}
	return nil
}

func (m *Manager) proxyCheck(ctx context.Context, report *Report) error {
	if m.cfg.RecoveryDrill.ReverseProxyURL == "" {
		report.Checks = append(report.Checks, skipped("reverse_proxy", "no production reverse-proxy origin configured"))
		if m.cfg.RecoveryDrill.RequireReverseProxy {
			return errors.New("a reverse-proxy acceptance check is required")
		}
		return nil
	}
	origin, err := url.Parse(m.cfg.RecoveryDrill.ReverseProxyURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || strings.Trim(origin.Path, "/") != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("configured reverse-proxy origin is invalid")
	}
	origin.Path = "/v1/service-info"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.String(), nil)
	if err != nil {
		return err
	}
	started := m.now()
	response, err := m.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("reverse proxy returned HTTP %d", response.StatusCode)
	}
	if !strings.Contains(strings.ToLower(response.Header.Get("Strict-Transport-Security")), "max-age=") {
		return errors.New("reverse proxy response omitted HSTS")
	}
	var info struct {
		APIVersion string `json:"api_version"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	if err = decoder.Decode(&info); err != nil || info.APIVersion != "v1" {
		return errors.New("reverse proxy service-info response is invalid")
	}
	report.Checks = append(report.Checks, passed("reverse_proxy", "HTTPS, HSTS and public service-info passed through the configured proxy", m.now().Sub(started)))
	return nil
}

func (m *Manager) measureResources(root string, report *Report) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	report.Resources = ResourceUsage{MemoryBytes: stats.Sys, MemoryLimitBytes: m.cfg.RecoveryDrill.MaxMemoryBytes, Goroutines: runtime.NumGoroutine(), GoroutineLimit: m.cfg.RecoveryDrill.MaxGoroutines, TemporaryBytes: directorySize(root), TemporaryLimitBytes: m.cfg.RecoveryDrill.MaxTemporaryStorageBytes}
}

func (m *Manager) Status(now time.Time) Status {
	m.mu.RLock()
	runningID := m.runningID
	var latest *Report
	var lastSuccessfulAt *time.Time
	if m.latest != nil {
		copy := *m.latest
		latest = &copy
	}
	if m.lastSuccessfulAt != nil {
		copy := *m.lastSuccessfulAt
		lastSuccessfulAt = &copy
	}
	m.mu.RUnlock()
	status := Status{Enabled: m.cfg.RecoveryDrill.Enabled, Required: m.cfg.RecoveryDrill.Required, ConfiguredMode: m.cfg.RecoveryDrill.Mode, Running: runningID != "", RunningDrillID: runningID, Latest: latest, LastSuccessfulAt: lastSuccessfulAt, Readiness: "ok"}
	if status.LastSuccessfulAt == nil {
		due := now
		status.NextScheduledAt = &due
		status.Overdue = m.cfg.RecoveryDrill.Enabled
	} else {
		due := status.LastSuccessfulAt.Add(m.cfg.RecoveryDrill.ScheduleInterval)
		status.NextScheduledAt = &due
		status.Overdue = now.Sub(*status.LastSuccessfulAt) > m.cfg.RecoveryDrill.MaxReportAge
	}
	if latest != nil && latest.Status == StatusFailed {
		status.Alerts = append(status.Alerts, "last_recovery_drill_failed")
		status.Readiness = "warning"
	}
	if latest != nil && latest.Status == StatusObjectivesMissed {
		status.Alerts = append(status.Alerts, latest.Alerts...)
		status.Readiness = "warning"
	}
	if status.Overdue {
		status.Alerts = append(status.Alerts, "recovery_drill_overdue")
		status.Readiness = "warning"
	}
	if status.Required && (status.Overdue || latest != nil && latest.Status != StatusPassed) {
		status.Readiness = "blocked"
	}
	return status
}

func (m *Manager) Ready(now time.Time) bool { return m.Status(now).Readiness != "blocked" }

func (m *Manager) Metrics(now time.Time) Metrics {
	status := m.Status(now)
	metrics := Metrics{Runs: m.runs.Load(), Failures: m.failures.Load(), Running: status.Running, Overdue: status.Overdue}
	if status.LastSuccessfulAt != nil {
		at := *status.LastSuccessfulAt
		metrics.LastSuccess = &at
	}
	if status.Latest != nil {
		metrics.LastRPO = status.Latest.Objectives.RPOSeconds
		metrics.LastRTO = status.Latest.Objectives.RTOSeconds
		metrics.ObjectivesMet = status.Latest.Objectives.RPOMet && status.Latest.Objectives.RTOMet
	}
	return metrics
}

func (m *Manager) List(_ context.Context, limit int) ([]Report, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	entries, err := os.ReadDir(m.cfg.RecoveryDrill.ReportDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var reports []Report
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "drill_") || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		report, readErr := readReport(filepath.Join(m.cfg.RecoveryDrill.ReportDirectory, entry.Name()))
		if readErr != nil {
			return nil, readErr
		}
		reports = append(reports, report)
	}
	sort.Slice(reports, func(i, j int) bool { return reports[i].CompletedAt.After(reports[j].CompletedAt) })
	if len(reports) > limit {
		reports = reports[:limit]
	}
	return reports, nil
}

func (m *Manager) Get(ctx context.Context, id string) (Report, error) {
	if !validID(id) {
		return Report{}, domain.ErrInvalid
	}
	reports, err := m.List(ctx, 1000)
	if err != nil {
		return Report{}, err
	}
	for _, report := range reports {
		if report.DrillID == id {
			return report, nil
		}
	}
	return Report{}, domain.ErrNotFound
}

func (m *Manager) writeReport(report Report) error {
	if report.SchemaVersion != ReportSchemaVersion || !validID(report.DrillID) {
		return errors.New("invalid recovery drill report")
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if len(b) > maxReportBytes {
		return errors.New("recovery drill report exceeds size limit")
	}
	if err = os.MkdirAll(m.cfg.RecoveryDrill.ReportDirectory, 0o750); err != nil {
		return err
	}
	final := filepath.Join(m.cfg.RecoveryDrill.ReportDirectory, report.DrillID+".json")
	if _, err = os.Stat(final); err == nil {
		return fmt.Errorf("refusing to overwrite recovery drill report %s", report.DrillID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(m.cfg.RecoveryDrill.ReportDirectory, ".drill-report-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err = temporary.Chmod(0o640); err != nil {
		return err
	}
	if _, err = temporary.Write(b); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, final); err != nil {
		return err
	}
	ok = true
	return nil
}

func (m *Manager) cleanupReports(now time.Time) error {
	reports, err := m.List(context.Background(), 1000)
	if err != nil {
		return err
	}
	for _, report := range reports {
		if now.Sub(report.CompletedAt) <= m.cfg.RecoveryDrill.ReportRetention {
			continue
		}
		path := filepath.Join(m.cfg.RecoveryDrill.ReportDirectory, report.DrillID+".json")
		if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m *Manager) cleanupStaleTemporary(now time.Time) error {
	root := filepath.Clean(m.cfg.RecoveryDrill.ReportDirectory)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	minimumAge := m.cfg.RecoveryDrill.Timeout + time.Hour
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !(strings.HasPrefix(entry.Name(), ".isolated-drill-") || strings.HasPrefix(entry.Name(), ".drill-report-")) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || now.Sub(info.ModTime()) <= minimumAge {
			continue
		}
		candidate := filepath.Join(root, entry.Name())
		if filepath.Dir(filepath.Clean(candidate)) != root {
			return errors.New("recovery drill temporary path escaped report directory")
		}
		if entry.IsDir() {
			err = os.RemoveAll(candidate)
		} else {
			err = os.Remove(candidate)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (m *Manager) recordLatest(report Report) {
	m.mu.Lock()
	if m.latest == nil || report.CompletedAt.After(m.latest.CompletedAt) {
		copy := report
		m.latest = &copy
	}
	if report.Status != StatusFailed && (m.lastSuccessfulAt == nil || report.CompletedAt.After(*m.lastSuccessfulAt)) {
		at := report.CompletedAt
		m.lastSuccessfulAt = &at
	}
	m.mu.Unlock()
}

func (m *Manager) appendAudit(ctx context.Context, eventType, id string, request Request, details any, at time.Time) error {
	payload, _ := json.Marshal(details)
	actorType := "administrator"
	actor := request.Actor
	if request.Trigger == "scheduled" {
		actorType = "system"
		actor = "recovery-drill-scheduler"
	}
	return m.repo.AppendAudit(ctx, domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: at, ActorType: actorType, ActorRef: actor, EventType: eventType, AggregateType: "recovery_drill", AggregateID: id, RequestID: request.RequestID, Event: payload})
}

func readReport(path string) (Report, error) {
	var report Report
	f, err := os.Open(path)
	if err != nil {
		return report, err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, maxReportBytes+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&report); err != nil {
		return report, fmt.Errorf("read recovery drill report %s: %w", filepath.Base(path), err)
	}
	if report.SchemaVersion != ReportSchemaVersion || !validID(report.DrillID) {
		return report, fmt.Errorf("invalid recovery drill report %s", filepath.Base(path))
	}
	return report, nil
}

func validateRestartEvidence(evidence RestartEvidence, drillStart time.Time) error {
	if evidence.BeforeBootID == "" || evidence.AfterBootID == "" || evidence.BeforeBootID == evidence.AfterBootID || evidence.ReadyAfterSeconds < 0 || evidence.ReadyAfterSeconds > 60 {
		return errors.New("service restart evidence is invalid")
	}
	if evidence.RestartedAt.Before(drillStart.Add(-30*time.Minute)) || evidence.RestartedAt.After(drillStart.Add(5*time.Minute)) {
		return errors.New("service restart evidence is not fresh")
	}
	return nil
}

func passed(name, detail string, elapsed time.Duration) Check {
	return Check{Name: name, Status: "passed", Detail: detail, DurationSeconds: elapsed.Seconds()}
}

func skipped(name, detail string) Check { return Check{Name: name, Status: "skipped", Detail: detail} }

func statusError(report Report) error {
	if report.Status == StatusPassed {
		return nil
	}
	return fmt.Errorf("recovery drill %s: %s", report.Status, report.FailureCode)
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func directorySize(root string) int64 {
	var size int64
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		if info, statErr := entry.Info(); statErr == nil {
			size += info.Size()
		}
		return nil
	})
	return size
}

func validID(id string) bool {
	if !strings.HasPrefix(id, "drill_") || len(id) > 96 {
		return false
	}
	for _, r := range id {
		if !(r == '_' || r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func bounded(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1024 {
		return value[:1024]
	}
	return value
}
