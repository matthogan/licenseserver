package daemon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/admintransport"
	"github.com/matthogan/licenceserver/internal/api"
	archivepkg "github.com/matthogan/licenceserver/internal/archive"
	archivefs "github.com/matthogan/licenceserver/internal/archive/filesystem"
	archives3 "github.com/matthogan/licenceserver/internal/archive/s3"
	"github.com/matthogan/licenceserver/internal/buildinfo"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/continuousbackup"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/issuer"
	"github.com/matthogan/licenceserver/internal/licensing"
	logwriter "github.com/matthogan/licenceserver/internal/logging"
	"github.com/matthogan/licenceserver/internal/recovery"
	"github.com/matthogan/licenceserver/internal/recoverydrill"
	"github.com/matthogan/licenceserver/internal/rootkey"
	"github.com/matthogan/licenceserver/internal/secretvalue"
	"github.com/matthogan/licenceserver/internal/security"
	"github.com/matthogan/licenceserver/internal/signing"
	postgresrepo "github.com/matthogan/licenceserver/internal/storage/postgres"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

func Run(ctx context.Context, c config.Config) error {
	logger, logCloser, err := newLogger(c)
	if err != nil {
		return fmt.Errorf("configure logging: %w", err)
	}
	if logCloser != nil {
		defer logCloser.Close()
	}
	logger.Info("service starting", "event", "service.start", "result", "started", "database", c.Database.Driver, "signer", c.Signer.Provider, "archive", c.Archive.Provider)
	var repo *sqliterepo.Repository
	if c.Database.Driver == "postgres" {
		repo, err = postgresrepo.Open(ctx, c)
	} else {
		repo, err = sqliterepo.Open(c)
	}
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer repo.Close()
	if !c.Server.ReadOnly {
		if err = repo.MigrateWithOptions(ctx, sqliterepo.MigrationOptions{BackupMaxAge: c.Database.MigrationBackupMaxAge}); err != nil {
			return fmt.Errorf("migrate database: %w", err)
		}
		logger.Info("database migrations complete", "event", "database.migrate", "result", "success", "database", c.Database.Driver)
	}
	backupManager := continuousbackup.New(c, logger)
	if err = backupManager.Start(ctx); err != nil {
		return fmt.Errorf("start continuous backup: %w", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), c.Backup.Continuous.ShutdownTimeout+5*time.Second)
		defer stopCancel()
		if stopErr := backupManager.Stop(stopCtx); stopErr != nil {
			logger.Error("stop continuous backup", "event", "backup.stop", "result", "failure", "reason_code", "shutdown_error", "error", stopErr)
		}
	}()
	root, err := signing.ReadPublicKey(c.Signer.RootPublicKeyFile)
	if err != nil {
		return fmt.Errorf("load trusted root public key: %w", err)
	}
	signerManager := signing.NewManager(nil)
	rootService := rootkey.New(repo, signerManager)
	if err = rootService.Initialize(ctx, root); err != nil {
		return fmt.Errorf("initialize trusted root keyring: %w", err)
	}
	var issuerService *issuer.Service
	if c.Signer.Provider == "aws-kms" {
		issuerService, err = issuer.NewWithKMS(repo, signerManager, root, filepath.Dir(c.Signer.IssuerCertificateFile), c.Signer.KMS.Region, c.Signer.KMS.Endpoint)
	} else {
		issuerService, err = issuer.New(repo, signerManager, root, c.SignerKeyDirectory())
	}
	if err != nil {
		return fmt.Errorf("configure issuer lifecycle: %w", err)
	}
	privateRef := c.Signer.PrivateKeyFile
	if c.Signer.Provider == "aws-kms" {
		privateRef = c.Signer.KMS.KeyID
	}
	if err = issuerService.Initialize(ctx, privateRef, c.Signer.IssuerCertificateFile); err != nil {
		// A missing/lost online issuer must not make the recovery administration
		// plane inaccessible. Issuance remains fail-closed and readiness fails.
		logger.Error("active issuer unavailable; issuance disabled until recovery", "event", "issuer.initialize", "result", "failure", "reason_code", "active_issuer_unavailable", "error", err)
	} else {
		logger.Info("issuer initialized", "event", "issuer.initialize", "result", "success", "provider", c.Signer.Provider)
	}
	var store domain.ArchiveStore
	if c.Archive.Provider == "filesystem" {
		store, err = archivefs.New(c.Archive.Directory)
		if err != nil {
			return fmt.Errorf("open archive: %w", err)
		}
	} else if c.Archive.Provider == "s3" {
		store, err = archives3.New(ctx, c)
		if err != nil {
			return fmt.Errorf("open S3 archive: %w", err)
		}
	} else {
		store = archivepkg.Disabled{}
	}
	if !c.Server.ReadOnly && c.Archive.Provider != "disabled" {
		counts, suppressionErr := recovery.ApplyArchiveSuppressions(ctx, repo, store, "service-startup", time.Now().UTC())
		if suppressionErr != nil {
			return fmt.Errorf("reconcile archived deletion suppressions before serving: %w", suppressionErr)
		}
		if counts.Licences+counts.Activations > 0 {
			logger.Warn("suppressed restored historical data before serving", "event", "data.suppression", "result", "success", "licences", counts.Licences, "activations", counts.Activations)
		}
	}
	pepper, err := secretvalue.Read(c.Trial.PepperEnv)
	if err != nil {
		return err
	}
	activationPepper, err := secretvalue.Read(c.Activation.PepperEnv)
	if err != nil {
		return err
	}
	rateLimitPepper, err := secretvalue.Read(c.RateLimit.PepperEnv)
	if err != nil {
		return err
	}
	svc := licensing.New(repo, store, signerManager, pepper, activationPepper, c.Trial.DefaultDuration, c.Archive.PaidLicenceAckPolicy == "strict")
	drillManager := recoverydrill.New(c, repo, store, logger)
	if err = drillManager.Start(ctx); err != nil {
		return fmt.Errorf("start recovery drill manager: %w", err)
	}
	apiServer := api.NewWithRoots(svc, issuerService, rootService, repo, backupManager, c, rateLimitPepper, logger)
	apiServer.SetRecoveryDrills(drillManager)
	publicHandler := apiServer.PublicHandler()
	if c.TLS.ReverseProxy.Enabled {
		publicHandler, err = security.TrustedProxyOnly(c.TLS.ReverseProxy.TrustedCIDRs, publicHandler)
		if err != nil {
			return err
		}
	}
	if c.TLS.Enabled || c.TLS.ReverseProxy.Enabled {
		publicHandler = security.PublicSecurityHeaders(publicHandler)
	}
	public := &http.Server{Addr: c.Server.PublicListen, Handler: publicHandler, ReadHeaderTimeout: c.HTTP.ReadHeaderTimeout, ReadTimeout: c.HTTP.ReadTimeout, WriteTimeout: c.HTTP.WriteTimeout, IdleTimeout: c.HTTP.IdleTimeout, MaxHeaderBytes: c.HTTP.MaxHeaderBytes, TLSConfig: security.PublicTLSConfig()}
	adminHandler := security.AdminAuthorizationWithAudit(c, apiServer.AdminHandler(), logger, apiServer.AuditSecurityEvent)
	admin := &http.Server{Handler: adminHandler, ReadHeaderTimeout: c.HTTP.ReadHeaderTimeout, ReadTimeout: c.HTTP.ReadTimeout, WriteTimeout: c.HTTP.WriteTimeout, IdleTimeout: c.HTTP.IdleTimeout, MaxHeaderBytes: c.HTTP.MaxHeaderBytes}
	adminAddress := c.Server.AdminListen
	switch c.Server.AdminTransport {
	case "unix":
		adminAddress = c.Server.AdminSocket
	case "named_pipe":
		adminAddress = c.Server.AdminPipe
	}
	adminListener, err := admintransport.Listen(admintransport.ListenerConfig{Transport: c.Server.AdminTransport, Address: adminAddress, SocketMode: c.Server.AdminSocketMode, PipeSDDL: c.Server.AdminPipeSDDL})
	if err != nil {
		return fmt.Errorf("open admin listener: %w", err)
	}
	if c.Server.AdminTransport == "tcp" && c.AdminTLS.Enabled {
		tlsConfig, tlsErr := security.AdminTLSConfig(c)
		if tlsErr != nil {
			adminListener.Close()
			return fmt.Errorf("configure admin mTLS: %w", tlsErr)
		}
		adminListener = tls.NewListener(adminListener, tlsConfig)
	}
	errCh := make(chan error, 2)
	go func() {
		logger.Info("public API listening", "event", "listener.start", "result", "success", "listener", "public", "address", c.Server.PublicListen, "tls", c.TLS.Enabled, "trusted_proxy", c.TLS.ReverseProxy.Enabled)
		if c.TLS.Enabled {
			errCh <- public.ListenAndServeTLS(c.TLS.CertificateFile, c.TLS.PrivateKeyFile)
		} else {
			errCh <- public.ListenAndServe()
		}
	}()
	go func() {
		logger.Info("admin API listening", "event", "listener.start", "result", "success", "listener", "admin", "transport", c.Server.AdminTransport, "address", adminAddress, "mtls", c.AdminTLS.Enabled)
		errCh <- admin.Serve(adminListener)
	}()
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !c.Server.ReadOnly {
		go reconcileLoop(workerCtx, svc, repo, logger, apiServer.RecordArchiveFailure)
	}
	var runErr error
	backupErrors := backupManager.Errors()
	waiting := true
	for waiting {
		select {
		case <-ctx.Done():
			logger.Info("shutdown requested", "event", "service.shutdown", "result", "started")
			waiting = false
		case err = <-errCh:
			if !errors.Is(err, http.ErrServerClosed) {
				cancel()
				runErr = err
			}
			waiting = false
		case err = <-backupErrors:
			if ctx.Err() == nil {
				if err == nil {
					err = errors.New("process stopped")
				}
				if c.Backup.Continuous.Required {
					cancel()
					runErr = fmt.Errorf("Litestream exited unexpectedly: %w", err)
					waiting = false
				} else {
					logger.Error("optional Litestream process exited", "event", "backup.process", "result", "failure", "reason_code", "process_exited", "error", err)
					backupErrors = nil
				}
			}
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer shutdownCancel()
	e1 := public.Shutdown(shutdownCtx)
	e2 := admin.Shutdown(shutdownCtx)
	return errors.Join(runErr, e1, e2)
}

func reconcileLoop(ctx context.Context, svc *licensing.Service, repo domain.Repository, logger *slog.Logger, recordFailure func()) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			maintenance, stateErr := repo.GetMaintenance(ctx)
			if stateErr != nil {
				logger.Warn("maintenance state unavailable; archive worker paused", "event", "archive.reconcile", "result", "paused", "reason_code", "maintenance_state_unavailable", "error", stateErr)
				continue
			}
			if maintenance.Enabled {
				continue
			}
			if n, err := svc.ReconcileArchive(ctx); err != nil {
				recordFailure()
				logger.Warn("archive reconciliation failed", "event", "archive.reconcile", "result", "failure", "reason_code", "delivery_failed", "error", err)
			} else if n > 0 {
				logger.Info("archive reconciled", "event", "archive.reconcile", "result", "success", "events", n)
				payload, _ := json.Marshal(map[string]any{"result": "success", "events": n})
				if auditErr := repo.AppendAudit(ctx, domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: time.Now().UTC(), ActorType: "system", ActorRef: "archive-reconciler", EventType: "archive.reconciled", AggregateType: "archive", AggregateID: "primary", Event: payload}); auditErr != nil {
					logger.Error("archive reconciliation audit failed", "event", "audit.write", "result", "failure", "reason_code", "archive_reconcile_audit", "error", auditErr)
				}
			}
		}
	}
}
func newLogger(c config.Config) (*slog.Logger, io.Closer, error) {
	level := slog.LevelInfo
	switch strings.ToLower(c.Logging.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var output io.Writer = os.Stdout
	var closer io.Closer
	if c.Logging.Output == "stderr" {
		output = os.Stderr
	}
	if c.Logging.Output != "stdout" && c.Logging.Output != "stderr" {
		writer, err := logwriter.NewRotatingWriter(c.Logging.Output, c.Logging.File.MaxSizeBytes, c.Logging.File.MaxBackups, c.Logging.File.MaxAge)
		if err != nil {
			return nil, nil, err
		}
		output, closer = writer, writer
	}
	var handler slog.Handler
	if c.Logging.Format == "text" {
		handler = slog.NewTextHandler(output, opts)
	} else {
		handler = slog.NewJSONHandler(output, opts)
	}
	logger := slog.New(handler).With("service", "licd", "version", buildinfo.Version)
	return logger, closer, nil
}
