package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/exportdata"
	"github.com/matthogan/licenceserver/internal/buildinfo"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/continuousbackup"
	dataexporter "github.com/matthogan/licenceserver/internal/dataexport"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/issuer"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/licensing"
	"github.com/matthogan/licenceserver/internal/recoverydrill"
	"github.com/matthogan/licenceserver/internal/rootkey"
	"github.com/matthogan/licenceserver/internal/security"
	"github.com/matthogan/licenceserver/internal/signing"
)

type API struct {
	svc                *licensing.Service
	issuers            *issuer.Service
	roots              *rootkey.Service
	repo               domain.Repository
	maxBody            int64
	log                *slog.Logger
	readOnly           bool
	backup             *continuousbackup.Manager
	requests           atomic.Uint64
	issued             atomic.Uint64
	trials             atomic.Uint64
	activationFailures atomic.Uint64
	auditFailures      atomic.Uint64
	rateLimitFailures  atomic.Uint64
	archiveFailures    atomic.Uint64
	databaseErrors     atomic.Uint64
	signerErrors       atomic.Uint64
	durationMicros     atomic.Uint64
	durationBuckets    [9]atomic.Uint64
	ratePepper         []byte
	rateConfig         config.Config
	recoveryDrills     *recoverydrill.Manager
	bootID             string
	startedAt          time.Time
}

func (a *API) RecordArchiveFailure() { a.archiveFailures.Add(1) }

func New(svc *licensing.Service, issuers *issuer.Service, repo domain.Repository, backup *continuousbackup.Manager, c config.Config, ratePepper []byte, logger *slog.Logger) *API {
	return NewWithRoots(svc, issuers, nil, repo, backup, c, ratePepper, logger)
}

func NewWithRoots(svc *licensing.Service, issuers *issuer.Service, roots *rootkey.Service, repo domain.Repository, backup *continuousbackup.Manager, c config.Config, ratePepper []byte, logger *slog.Logger) *API {
	return &API{svc: svc, issuers: issuers, roots: roots, repo: repo, backup: backup, maxBody: c.HTTP.MaxBodyBytes, log: logger, readOnly: c.Server.ReadOnly, ratePepper: append([]byte(nil), ratePepper...), rateConfig: c, bootID: "boot_" + strings.ReplaceAll(uuid.NewString(), "-", ""), startedAt: time.Now().UTC()}
}

func (a *API) SetRecoveryDrills(manager *recoverydrill.Manager) { a.recoveryDrills = manager }

func (a *API) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/trials", a.issueTrial)
	mux.HandleFunc("POST /v1/activations", a.redeemActivation)
	mux.HandleFunc("POST /v1/licences/status", a.licenceStatus)
	mux.HandleFunc("GET /v1/service-info", func(w http.ResponseWriter, r *http.Request) {
		if !a.enforceRate(w, r, "status.ip", clientIP(r), a.rateConfig.RateLimit.Status.PerIP) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "v1", "build": buildinfo.Current()})
	})
	mux.HandleFunc("/", methodAwareNotFound(mux))
	return a.middleware(mux, true)
}

func (a *API) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/health/live", a.live)
	mux.HandleFunc("GET /admin/v1/health/ready", a.ready)
	mux.HandleFunc("GET /admin/v1/metrics", a.metrics)
	mux.HandleFunc("GET /admin/v1/backup/status", a.backupStatus)
	mux.HandleFunc("GET /admin/v1/recovery-drills/status", a.recoveryDrillStatus)
	mux.HandleFunc("GET /admin/v1/recovery-drills", a.listRecoveryDrills)
	mux.HandleFunc("POST /admin/v1/recovery-drills", a.startRecoveryDrill)
	mux.HandleFunc("GET /admin/v1/recovery-drills/{id}", a.showRecoveryDrill)
	mux.HandleFunc("GET /admin/v1/maintenance", a.maintenanceStatus)
	mux.HandleFunc("POST /admin/v1/maintenance", a.setMaintenance)
	mux.HandleFunc("POST /admin/v1/products", a.createProduct)
	mux.HandleFunc("GET /admin/v1/products", a.listProducts)
	mux.HandleFunc("GET /admin/v1/products/{id}", a.showProduct)
	mux.HandleFunc("PATCH /admin/v1/products/{id}", a.updateProduct)
	mux.HandleFunc("GET /admin/v1/trials/{id}", a.showTrial)
	mux.HandleFunc("POST /admin/v1/licences", a.issueLicence)
	mux.HandleFunc("GET /admin/v1/licences", a.listLicences)
	mux.HandleFunc("GET /admin/v1/licences/{id}", a.showLicence)
	mux.HandleFunc("POST /admin/v1/licences/{id}/revoke", a.revokeLicence)
	mux.HandleFunc("POST /admin/v1/licences/{id}/reissue", a.reissueLicence)
	mux.HandleFunc("POST /admin/v1/activations", a.createActivation)
	mux.HandleFunc("GET /admin/v1/activations", a.listActivations)
	mux.HandleFunc("GET /admin/v1/activations/{id}", a.showActivation)
	mux.HandleFunc("POST /admin/v1/activations/{id}/revoke", a.revokeActivation)
	mux.HandleFunc("GET /admin/v1/activation-codes", a.listActivationCodes)
	mux.HandleFunc("GET /admin/v1/activation-codes/{id}", a.showActivationCode)
	mux.HandleFunc("POST /admin/v1/activation-codes/{id}/revoke", a.revokeActivationCode)
	mux.HandleFunc("GET /admin/v1/issuers", a.listIssuers)
	mux.HandleFunc("GET /admin/v1/issuers/{id}", a.showIssuer)
	mux.HandleFunc("POST /admin/v1/issuers/register", a.registerIssuer)
	mux.HandleFunc("POST /admin/v1/issuers/rotate", a.rotateIssuer)
	mux.HandleFunc("POST /admin/v1/issuers/{id}/activate", a.activateIssuer)
	mux.HandleFunc("POST /admin/v1/issuers/{id}/status", a.setIssuerStatus)
	mux.HandleFunc("GET /admin/v1/roots", a.listRoots)
	mux.HandleFunc("GET /admin/v1/roots/keyring", a.rootKeyring)
	mux.HandleFunc("GET /admin/v1/root-transitions", a.listRootTransitions)
	mux.HandleFunc("GET /admin/v1/root-transitions/{id}", a.showRootTransition)
	mux.HandleFunc("POST /admin/v1/root-transitions/activate", a.activateRootTransition)
	mux.HandleFunc("POST /admin/v1/root-transitions/{id}/retire", a.retireRootTransition)
	mux.HandleFunc("POST /admin/v1/root-transitions/{id}/rollback", a.rollbackRootTransition)
	mux.HandleFunc("GET /admin/v1/archive/status", a.archiveStatus)
	mux.HandleFunc("POST /admin/v1/archive/reconcile", a.reconcile)
	mux.HandleFunc("POST /admin/v1/archive/verify", a.verifyArchive)
	mux.HandleFunc("POST /admin/v1/data-exports", a.exportData)
	mux.HandleFunc("GET /admin/v1/data-retention/policies", a.listRetentionPolicies)
	mux.HandleFunc("POST /admin/v1/data-retention/policies", a.setRetentionPolicy)
	mux.HandleFunc("POST /admin/v1/data-retention/plan", a.planRetention)
	mux.HandleFunc("POST /admin/v1/data-retention/apply", a.applyRetention)
	mux.HandleFunc("GET /admin/v1/data-holds", a.listLegalHolds)
	mux.HandleFunc("POST /admin/v1/data-holds", a.createLegalHold)
	mux.HandleFunc("POST /admin/v1/data-holds/{id}/release", a.releaseLegalHold)
	mux.HandleFunc("POST /admin/v1/data-deletions/plan", a.planDataDeletion)
	mux.HandleFunc("POST /admin/v1/data-deletions", a.deleteData)
	mux.HandleFunc("GET /admin/v1/data-tombstones", a.listDataTombstones)
	mux.HandleFunc("/", methodAwareNotFound(mux))
	return a.middleware(mux, false)
}

func (a *API) issueTrial(w http.ResponseWriter, r *http.Request) {
	if !a.enforceRate(w, r, "trial.ip", clientIP(r), a.rateConfig.RateLimit.Trial.PerIP) {
		return
	}
	var req licensing.IssueTrialRequest
	if !decode(w, r, &req) {
		return
	}
	if !a.enforceRate(w, r, "trial.product", strings.TrimSpace(req.ProductID), a.rateConfig.RateLimit.Trial.PerProduct) {
		return
	}
	if !a.enforceRate(w, r, "trial.subject", strings.TrimSpace(req.ProductID)+"\x00"+strings.TrimSpace(req.InstallID), a.rateConfig.RateLimit.Trial.PerSubject) {
		return
	}
	result, err := a.svc.IssueTrial(r.Context(), req, requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	a.trials.Add(1)
	writeJSON(w, http.StatusCreated, result)
}
func (a *API) redeemActivation(w http.ResponseWriter, r *http.Request) {
	if !a.enforceRate(w, r, "activation.ip", clientIP(r), a.rateConfig.RateLimit.Activation.PerIP) {
		a.activationFailures.Add(1)
		return
	}
	var req licensing.RedeemActivationRequest
	if !decode(w, r, &req) {
		a.activationFailures.Add(1)
		return
	}
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(req.Code), "-", ""))
	if !a.enforceRate(w, r, "activation.code", normalized, a.rateConfig.RateLimit.Activation.PerCode) {
		a.activationFailures.Add(1)
		return
	}
	req.IdempotencyKey = r.Header.Get("Idempotency-Key")
	result, err := a.svc.RedeemActivationCode(r.Context(), req, requestID(r))
	if err != nil {
		a.activationFailures.Add(1)
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (a *API) licenceStatus(w http.ResponseWriter, r *http.Request) {
	if !a.enforceRate(w, r, "status.ip", clientIP(r), a.rateConfig.RateLimit.Status.PerIP) {
		return
	}
	var req domain.LicenceStatusRequest
	if !decode(w, r, &req) {
		return
	}
	result, err := a.svc.LicenceStatus(r.Context(), req, requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (a *API) createProduct(w http.ResponseWriter, r *http.Request) {
	var p domain.Product
	if !decode(w, r, &p) {
		return
	}
	if err := a.svc.CreateProduct(r.Context(), p, security.Actor(r.Context()), requestID(r)); err != nil {
		a.handleError(w, r, err)
		return
	}
	created, _ := a.svc.GetProduct(r.Context(), p.ProductID)
	writeJSON(w, http.StatusCreated, created)
}
func (a *API) listProducts(w http.ResponseWriter, r *http.Request) {
	p, err := a.svc.ListProducts(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"products": p})
}
func (a *API) showProduct(w http.ResponseWriter, r *http.Request) {
	p, err := a.svc.GetProduct(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}
func (a *API) updateProduct(w http.ResponseWriter, r *http.Request) {
	var update domain.ProductUpdate
	if !decode(w, r, &update) {
		return
	}
	p, err := a.svc.UpdateProduct(r.Context(), r.PathValue("id"), update, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}
func (a *API) showTrial(w http.ResponseWriter, r *http.Request) {
	trial, licence, err := a.svc.GetTrial(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"trial": trial, "licence": licence})
}
func (a *API) issueLicence(w http.ResponseWriter, r *http.Request) {
	var req licensing.IssueLicenceRequest
	if !decode(w, r, &req) {
		return
	}
	result, err := a.svc.IssueLicence(r.Context(), req, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	a.issued.Add(1)
	status := http.StatusCreated
	if result.Existing {
		status = http.StatusOK
	}
	writeJSON(w, status, result)
}
func (a *API) listLicences(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ls, err := a.svc.ListLicences(r.Context(), r.URL.Query().Get("product"), limit)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	for i := range ls {
		ls[i].SignedArtifact = nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"licences": ls})
}
func (a *API) showLicence(w http.ResponseWriter, r *http.Request) {
	l, err := a.svc.GetLicence(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (a *API) exportData(w http.ResponseWriter, r *http.Request) {
	var filter exportdata.Filter
	if !decode(w, r, &filter) {
		return
	}
	actor, request := security.Actor(r.Context()), requestID(r)
	summary := map[string]any{
		"product_id": filter.ProductID, "licence_id": filter.LicenceID,
		"customer_ref_filter": filter.CustomerRef != "", "status": filter.Status,
		"from": filter.From, "to": filter.To,
	}
	if err := a.appendOperationalAudit(r.Context(), "data.export_requested", "data_export", request, actor, request, map[string]any{"result": "attempt", "filters": summary}); err != nil {
		a.handleError(w, r, err)
		return
	}
	temporary, err := os.CreateTemp("", "licd-data-export-*.tar.gz")
	if err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.export_failed", "data_export", request, actor, request, map[string]any{"result": "failure", "reason_code": "temporary_file"})
		a.handleError(w, r, err)
		return
	}
	path := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(path)
	}()
	createdAt := time.Now().UTC()
	manifest, err := dataexporter.WriteArchive(r.Context(), a.repo, filter, createdAt, temporary)
	if err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.export_failed", "data_export", request, actor, request, map[string]any{"result": "failure", "reason_code": exportFailureCode(err)})
		a.handleError(w, r, err)
		return
	}
	if err = temporary.Sync(); err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.export_failed", "data_export", request, actor, request, map[string]any{"result": "failure", "reason_code": "sync"})
		a.handleError(w, r, err)
		return
	}
	if _, err = temporary.Seek(0, io.SeekStart); err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.export_failed", "data_export", request, actor, request, map[string]any{"result": "failure", "reason_code": "seek"})
		a.handleError(w, r, err)
		return
	}
	hash := sha256.New()
	size, err := io.Copy(hash, temporary)
	if err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.export_failed", "data_export", request, actor, request, map[string]any{"result": "failure", "reason_code": "hash"})
		a.handleError(w, r, err)
		return
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if _, err = temporary.Seek(0, io.SeekStart); err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.export_failed", "data_export", request, actor, request, map[string]any{"result": "failure", "reason_code": "seek"})
		a.handleError(w, r, err)
		return
	}
	filterJSON, _ := json.Marshal(manifest.Filters)
	countJSON, _ := json.Marshal(manifest.RecordCounts)
	exportAudit := a.operationalAudit("data.exported", "data_export", request, actor, request, map[string]any{"result": "success", "sha256": digest, "size_bytes": size, "record_counts": manifest.RecordCounts, "filters": summary})
	if err = a.repo.RecordDataExportProof(r.Context(), domain.DataExportProof{SHA256: digest, CreatedAt: createdAt, FilterJSON: filterJSON, RecordCounts: countJSON}, exportAudit); err != nil {
		a.handleError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="licd-data-export-%s.tar.gz"`, createdAt.Format("20060102T150405Z")))
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("X-Licd-Export-SHA256", digest)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, temporary)
}

func exportFailureCode(err error) string {
	if errors.Is(err, domain.ErrInvalid) {
		return "invalid_filter"
	}
	return "generation_failed"
}
func (a *API) revokeLicence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
		Text   string `json:"text"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.svc.Revoke(r.Context(), r.PathValue("id"), req.Reason, req.Text, security.Actor(r.Context()), requestID(r)); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
func (a *API) reissueLicence(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	result, err := a.svc.ReissueLicence(r.Context(), r.PathValue("id"), req.Reason, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}
func (a *API) createActivation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LicenceID string     `json:"licence_id"`
		MaxUses   int        `json:"max_uses"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if !decode(w, r, &req) {
		return
	}
	created, err := a.svc.CreateActivationCode(r.Context(), req.LicenceID, req.MaxUses, req.ExpiresAt, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}
func (a *API) listActivationCodes(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	codes, err := a.svc.ListActivationCodes(r.Context(), r.URL.Query().Get("licence_id"), limit)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activation_codes": codes})
}
func (a *API) showActivationCode(w http.ResponseWriter, r *http.Request) {
	code, err := a.svc.GetActivationCode(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, code)
}
func (a *API) revokeActivationCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.svc.RevokeActivationCode(r.Context(), r.PathValue("id"), req.Reason, security.Actor(r.Context()), requestID(r)); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
func (a *API) listActivations(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	records, err := a.svc.ListActivations(r.Context(), r.URL.Query().Get("licence_id"), r.URL.Query().Get("activation_code_id"), limit)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activations": records})
}
func (a *API) showActivation(w http.ResponseWriter, r *http.Request) {
	record, err := a.svc.GetActivation(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}
func (a *API) revokeActivation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.svc.RevokeActivation(r.Context(), r.PathValue("id"), req.Reason, security.Actor(r.Context()), requestID(r)); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
func (a *API) listIssuers(w http.ResponseWriter, r *http.Request) {
	keys, err := a.issuers.List(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"issuers": keys})
}
func (a *API) showIssuer(w http.ResponseWriter, r *http.Request) {
	key, err := a.issuers.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}
func (a *API) registerIssuer(w http.ResponseWriter, r *http.Request) {
	var req issuer.LocalFiles
	if !decode(w, r, &req) {
		return
	}
	key, err := a.issuers.Register(r.Context(), req, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, key)
}
func (a *API) rotateIssuer(w http.ResponseWriter, r *http.Request) {
	var req issuer.LocalFiles
	if !decode(w, r, &req) {
		return
	}
	key, err := a.issuers.Rotate(r.Context(), req, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}
func (a *API) activateIssuer(w http.ResponseWriter, r *http.Request) {
	key, err := a.issuers.Activate(r.Context(), r.PathValue("id"), security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}
func (a *API) setIssuerStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status        string `json:"status"`
		Reason        string `json:"reason"`
		AllowNoActive bool   `json:"allow_no_active"`
	}
	if !decode(w, r, &req) {
		return
	}
	key, err := a.issuers.SetStatus(r.Context(), r.PathValue("id"), req.Status, req.Reason, req.AllowNoActive, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, key)
}

func (a *API) listRoots(w http.ResponseWriter, r *http.Request) {
	roots, err := a.roots.ListRoots(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roots": roots})
}

func (a *API) rootKeyring(w http.ResponseWriter, r *http.Request) {
	keyring, err := a.roots.Keyring(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, keyring)
}

func (a *API) listRootTransitions(w http.ResponseWriter, r *http.Request) {
	transitions, err := a.roots.ListTransitions(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"transitions": transitions})
}

func (a *API) showRootTransition(w http.ResponseWriter, r *http.Request) {
	transition, err := a.roots.GetTransition(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, transition)
}

func (a *API) activateRootTransition(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Artifact       string `json:"artifact"`
		ConfirmNewRoot string `json:"confirm_new_root"`
	}
	if !decode(w, r, &req) {
		return
	}
	inspection, err := licencefmt.InspectRootTransition(req.Artifact)
	if err != nil || req.ConfirmNewRoot != inspection.Payload.NewRootKeyID {
		a.handleError(w, r, domain.ErrInvalid)
		return
	}
	transition, err := a.roots.Activate(r.Context(), req.Artifact, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, transition)
}

func (a *API) retireRootTransition(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason         string `json:"reason"`
		CompromiseOld  bool   `json:"compromise_old"`
		ConfirmOldRoot string `json:"confirm_old_root"`
	}
	if !decode(w, r, &req) {
		return
	}
	current, err := a.roots.GetTransition(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	if req.ConfirmOldRoot != current.OldRootKeyID {
		a.handleError(w, r, domain.ErrInvalid)
		return
	}
	transition, err := a.roots.Retire(r.Context(), r.PathValue("id"), req.Reason, req.CompromiseOld, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, transition)
}

func (a *API) rollbackRootTransition(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason         string `json:"reason"`
		CompromiseNew  bool   `json:"compromise_new"`
		ConfirmNewRoot string `json:"confirm_new_root"`
	}
	if !decode(w, r, &req) {
		return
	}
	current, err := a.roots.GetTransition(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	if req.ConfirmNewRoot != current.NewRootKeyID {
		a.handleError(w, r, domain.ErrInvalid)
		return
	}
	transition, err := a.roots.Rollback(r.Context(), r.PathValue("id"), req.Reason, req.CompromiseNew, security.Actor(r.Context()), requestID(r))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, transition)
}
func (a *API) archiveStatus(w http.ResponseWriter, r *http.Request) {
	n, oldest, err := a.svc.ArchiveStatus(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": n, "oldest_pending_at": oldest})
}
func (a *API) reconcile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Deep   bool `json:"deep"`
		Repair bool `json:"repair"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Repair && !req.Deep {
		a.handleError(w, r, domain.ErrInvalid)
		return
	}
	if req.Deep {
		report, err := a.svc.ReconcileArchiveDeep(r.Context(), req.Repair, security.Actor(r.Context()), requestID(r))
		if err != nil {
			a.archiveFailures.Add(1)
			a.handleError(w, r, err)
			return
		}
		if err = a.appendOperationalAudit(r.Context(), "archive.deep_reconciled", "archive", "primary", security.Actor(r.Context()), requestID(r), map[string]any{"result": "success", "repair": req.Repair, "report": report}); err != nil {
			a.handleError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, report)
		return
	}
	n, err := a.svc.ReconcileArchive(r.Context())
	if err != nil {
		a.archiveFailures.Add(1)
		a.handleError(w, r, err)
		return
	}
	if err = a.appendOperationalAudit(r.Context(), "archive.reconciled", "archive", "primary", security.Actor(r.Context()), requestID(r), map[string]any{"result": "success", "events": n}); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"archived": n})
}

func (a *API) maintenanceStatus(w http.ResponseWriter, r *http.Request) {
	state, err := a.repo.GetMaintenance(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (a *API) setMaintenance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 512 {
		a.handleError(w, r, domain.ErrInvalid)
		return
	}
	actor := security.Actor(r.Context())
	state := domain.MaintenanceState{Enabled: req.Enabled, Reason: req.Reason, ChangedAt: time.Now().UTC(), ChangedBy: actor}
	eventType := "maintenance.disabled"
	if req.Enabled {
		eventType = "maintenance.enabled"
	}
	payload, _ := json.Marshal(map[string]any{"enabled": req.Enabled, "reason": req.Reason, "result": "success"})
	audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: state.ChangedAt, ActorType: "administrator", ActorRef: actor, EventType: eventType, AggregateType: "service", AggregateID: "maintenance", RequestID: requestID(r), Event: payload}
	if err := a.repo.SetMaintenance(r.Context(), state, audit); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}
func (a *API) verifyArchive(w http.ResponseWriter, r *http.Request) {
	if err := a.svc.VerifyArchive(r.Context()); err != nil {
		a.archiveFailures.Add(1)
		a.handleError(w, r, err)
		return
	}
	if err := a.appendOperationalAudit(r.Context(), "archive.verified", "archive", "primary", security.Actor(r.Context()), requestID(r), map[string]any{"result": "success"}); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (a *API) backupStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.backup.Health())
}

func (a *API) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "live", "boot_id": a.bootID, "started_at": a.startedAt})
}

func (a *API) recoveryDrillStatus(w http.ResponseWriter, _ *http.Request) {
	if a.recoveryDrills == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "readiness": "not_configured"})
		return
	}
	writeJSON(w, http.StatusOK, a.recoveryDrills.Status(time.Now().UTC()))
}

func (a *API) listRecoveryDrills(w http.ResponseWriter, r *http.Request) {
	if a.recoveryDrills == nil {
		writeJSON(w, http.StatusOK, map[string]any{"reports": []any{}})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	reports, err := a.recoveryDrills.List(r.Context(), limit)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": reports})
}

func (a *API) showRecoveryDrill(w http.ResponseWriter, r *http.Request) {
	if a.recoveryDrills == nil {
		a.handleError(w, r, domain.ErrNotFound)
		return
	}
	report, err := a.recoveryDrills.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (a *API) startRecoveryDrill(w http.ResponseWriter, r *http.Request) {
	if a.recoveryDrills == nil {
		a.handleError(w, r, errors.New("recovery drill manager is unavailable"))
		return
	}
	var request recoverydrill.Request
	if !decode(w, r, &request) {
		return
	}
	request.Trigger = "manual"
	request.Actor = security.Actor(r.Context())
	request.RequestID = requestID(r)
	if request.RestartEvidence != nil && request.RestartEvidence.AfterBootID != a.bootID {
		a.handleError(w, r, domain.ErrInvalid)
		return
	}
	id, err := a.recoveryDrills.Trigger(request)
	if err != nil {
		if errors.Is(err, recoverydrill.ErrAlreadyRunning) {
			a.handleError(w, r, domain.ErrConflict)
			return
		}
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"drill_id": id, "status": "running"})
}
func (a *API) ready(w http.ResponseWriter, r *http.Request) {
	status := http.StatusOK
	db := "ok"
	if err := a.repo.Ping(r.Context()); err != nil {
		a.databaseErrors.Add(1)
		status = http.StatusServiceUnavailable
		db = "error"
	}
	schema, schemaErr := a.repo.SchemaStatus(r.Context())
	if schemaErr != nil {
		a.databaseErrors.Add(1)
		status = http.StatusServiceUnavailable
		db = "error"
	} else if !schema.Compatible {
		status = http.StatusServiceUnavailable
		db = "schema_incompatible"
	}
	pending, oldest, err := a.svc.ArchiveStatus(r.Context())
	archive := "ok"
	if err != nil {
		a.archiveFailures.Add(1)
		status = http.StatusServiceUnavailable
		archive = "error"
	} else if pending > 0 {
		archive = "pending"
		if a.rateConfig.Archive.PaidLicenceAckPolicy == "strict" {
			status = http.StatusServiceUnavailable
			archive = "blocked"
		}
	}
	signer := "ok"
	if err = a.svc.SignerHealth(time.Now().UTC()); err != nil {
		a.signerErrors.Add(1)
		status = http.StatusServiceUnavailable
		signer = "error"
	}
	rootKeyring := "ok"
	if a.roots != nil {
		if rootErr := a.roots.Healthy(r.Context(), time.Now().UTC()); rootErr != nil {
			status = http.StatusServiceUnavailable
			rootKeyring = "error"
		}
	}
	state := "ready"
	backup := a.backup.Health()
	if !a.backup.Ready() {
		status = http.StatusServiceUnavailable
	}
	maintenance, maintenanceErr := a.repo.GetMaintenance(r.Context())
	if maintenanceErr != nil {
		a.databaseErrors.Add(1)
		status = http.StatusServiceUnavailable
	} else if maintenance.Enabled {
		status = http.StatusServiceUnavailable
	}
	var recoveryDrill any = map[string]any{"enabled": false, "readiness": "not_configured"}
	if a.recoveryDrills != nil {
		drillStatus := a.recoveryDrills.Status(time.Now().UTC())
		recoveryDrill = drillStatus
		if !a.recoveryDrills.Ready(time.Now().UTC()) {
			status = http.StatusServiceUnavailable
		}
	}
	if status != http.StatusOK {
		state = "not_ready"
	}
	writeJSON(w, status, map[string]any{"status": state, "database": db, "schema": schema, "signer": signer, "root_keyring": rootKeyring, "archive": archive, "archive_pending": pending, "archive_oldest_pending_at": oldest, "backup": backup, "maintenance": maintenance, "recovery_drill": recoveryDrill})
}
func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	h := a.backup.Health()
	up := 0
	enabled := 0
	if h.Enabled {
		enabled = 1
	}
	if h.Enabled && h.Running {
		up = 1
	}
	lastSuccess := float64(0)
	if h.LastSuccess != nil {
		lastSuccess = float64(h.LastSuccess.Unix())
	}
	pending := 0
	oldestAge := float64(0)
	if n, oldest, err := a.svc.ArchiveStatus(r.Context()); err != nil {
		a.archiveFailures.Add(1)
	} else {
		pending = n
		if oldest != nil {
			oldestAge = time.Since(*oldest).Seconds()
			if oldestAge < 0 {
				oldestAge = 0
			}
		}
	}
	dbStats := a.repo.DatabaseStats()
	fmt.Fprintf(w, "# TYPE licd_http_requests_total counter\nlicd_http_requests_total %d\n", a.requests.Load())
	fmt.Fprintln(w, "# TYPE licd_http_request_duration_seconds histogram")
	for i := range metricDurationBounds {
		fmt.Fprintf(w, "licd_http_request_duration_seconds_bucket{le=\"%s\"} %d\n", metricDurationLabels[i], a.durationBuckets[i].Load())
	}
	fmt.Fprintf(w, "licd_http_request_duration_seconds_bucket{le=\"+Inf\"} %d\nlicd_http_request_duration_seconds_sum %.6f\nlicd_http_request_duration_seconds_count %d\n", a.durationBuckets[len(metricDurationBounds)].Load(), float64(a.durationMicros.Load())/1e6, a.durationBuckets[len(metricDurationBounds)].Load())
	fmt.Fprintf(w, "# TYPE licd_licences_issued_total counter\nlicd_licences_issued_total %d\n# TYPE licd_trials_issued_total counter\nlicd_trials_issued_total %d\n# TYPE licd_activation_failures_total counter\nlicd_activation_failures_total %d\n# TYPE licd_audit_write_failures_total counter\nlicd_audit_write_failures_total %d\n# TYPE licd_rate_limit_storage_failures_total counter\nlicd_rate_limit_storage_failures_total %d\n", a.issued.Load(), a.trials.Load(), a.activationFailures.Load(), a.auditFailures.Load(), a.rateLimitFailures.Load())
	fmt.Fprintf(w, "# TYPE licd_archive_pending_events gauge\nlicd_archive_pending_events %d\n# TYPE licd_archive_oldest_pending_age_seconds gauge\nlicd_archive_oldest_pending_age_seconds %.6f\n# TYPE licd_archive_failures_total counter\nlicd_archive_failures_total %d\n", pending, oldestAge, a.archiveFailures.Load())
	fmt.Fprintf(w, "# TYPE licd_database_errors_total counter\nlicd_database_errors_total %d\n# TYPE licd_database_open_connections gauge\nlicd_database_open_connections %d\n# TYPE licd_database_in_use_connections gauge\nlicd_database_in_use_connections %d\n# TYPE licd_database_idle_connections gauge\nlicd_database_idle_connections %d\n# TYPE licd_database_wait_count_total counter\nlicd_database_wait_count_total %d\n# TYPE licd_database_wait_duration_seconds_total counter\nlicd_database_wait_duration_seconds_total %.6f\n", a.databaseErrors.Load(), dbStats.OpenConnections, dbStats.InUseConnections, dbStats.IdleConnections, dbStats.WaitCount, dbStats.WaitDuration.Seconds())
	fmt.Fprintf(w, "# TYPE licd_signer_errors_total counter\nlicd_signer_errors_total %d\n# TYPE licd_backup_enabled gauge\nlicd_backup_enabled %d\n# TYPE licd_backup_process_up gauge\nlicd_backup_process_up %d\n# TYPE licd_backup_last_success_timestamp_seconds gauge\nlicd_backup_last_success_timestamp_seconds %.0f\n", a.signerErrors.Load(), enabled, up, lastSuccess)
	if a.recoveryDrills != nil {
		drill := a.recoveryDrills.Metrics(time.Now().UTC())
		running, overdue, objectivesMet := 0, 0, 0
		if drill.Running {
			running = 1
		}
		if drill.Overdue {
			overdue = 1
		}
		if drill.ObjectivesMet {
			objectivesMet = 1
		}
		lastDrillSuccess := float64(0)
		if drill.LastSuccess != nil {
			lastDrillSuccess = float64(drill.LastSuccess.Unix())
		}
		fmt.Fprintf(w, "# TYPE licd_recovery_drill_runs_total counter\nlicd_recovery_drill_runs_total %d\n# TYPE licd_recovery_drill_failures_total counter\nlicd_recovery_drill_failures_total %d\n# TYPE licd_recovery_drill_running gauge\nlicd_recovery_drill_running %d\n# TYPE licd_recovery_drill_overdue gauge\nlicd_recovery_drill_overdue %d\n# TYPE licd_recovery_drill_last_success_timestamp_seconds gauge\nlicd_recovery_drill_last_success_timestamp_seconds %.0f\n# TYPE licd_recovery_drill_last_rpo_seconds gauge\nlicd_recovery_drill_last_rpo_seconds %.6f\n# TYPE licd_recovery_drill_last_rto_seconds gauge\nlicd_recovery_drill_last_rto_seconds %.6f\n# TYPE licd_recovery_drill_objectives_met gauge\nlicd_recovery_drill_objectives_met %d\n", drill.Runs, drill.Failures, running, overdue, lastDrillSuccess, drill.LastRPO, drill.LastRTO, objectivesMet)
	}
}

var metricDurationBounds = [...]time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond, time.Second, 5 * time.Second}
var metricDurationLabels = [...]string{"0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "1", "5"}

func (a *API) observeDuration(elapsed time.Duration) {
	a.durationMicros.Add(uint64(elapsed.Microseconds()))
	for i, boundary := range metricDurationBounds {
		if elapsed <= boundary {
			a.durationBuckets[i].Add(1)
		}
	}
	a.durationBuckets[len(metricDurationBounds)].Add(1)
}

func (a *API) middleware(next http.Handler, public bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = "req_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		}
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, a.maxBody)
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		r = r.WithContext(ctx)
		start := time.Now()
		status := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		readAction := !public && r.Method == http.MethodPost && (r.URL.Path == "/admin/v1/data-exports" || r.URL.Path == "/admin/v1/data-retention/plan" || r.URL.Path == "/admin/v1/data-deletions/plan")
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead && !readAction
		maintenanceControl := !public && r.URL.Path == "/admin/v1/maintenance"
		blocked := false
		if a.readOnly && mutating {
			writeError(status, r, http.StatusServiceUnavailable, "READ_ONLY", "The service is in read-only recovery mode.")
			blocked = true
		} else if mutating && !maintenanceControl && a.repo != nil {
			maintenance, err := a.repo.GetMaintenance(r.Context())
			if err != nil {
				a.handleError(status, r, err)
				blocked = true
			} else if maintenance.Enabled {
				status.Header().Set("Retry-After", "60")
				writeError(status, r, http.StatusServiceUnavailable, "MAINTENANCE", "The service is temporarily in maintenance mode.")
				blocked = true
			}
		}
		if !blocked {
			next.ServeHTTP(status, r)
		}
		actor := ""
		if !public {
			actor = security.Actor(r.Context())
			a.appendAdminAudit(r.Context(), actor, id, r.Method, r.URL.Path, status.status)
		}
		result := "success"
		if status.status >= 400 {
			result = "failure"
		}
		elapsed := time.Since(start)
		a.observeDuration(elapsed)
		a.log.Info("http request", "event", "http.request", "operation", r.Pattern, "result", result, "request_id", id, "method", r.Method, "path", r.URL.Path, "status", status.status, "response_bytes", status.bytes, "remote_ip", clientIP(r), "public", public, "actor", actor, "duration_ms", elapsed.Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}

func (a *API) appendAdminAudit(ctx context.Context, actor, requestID, method, path string, status int) {
	result := "success"
	reason := ""
	if status >= 400 {
		result = "failure"
		reason = "http_status_" + strconv.Itoa(status)
	}
	payload, _ := json.Marshal(map[string]any{"method": method, "path": path, "status": status, "result": result, "reason_code": reason})
	event := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: time.Now().UTC(), ActorType: "administrator", ActorRef: actor, EventType: "admin.request", AggregateType: "http_route", AggregateID: path, RequestID: requestID, Event: payload}
	if err := a.repo.AppendAudit(ctx, event); err != nil {
		a.auditFailures.Add(1)
		a.log.Error("admin request audit failed", "request_id", requestID, "error", err)
	}
}

func (a *API) appendOperationalAudit(ctx context.Context, eventType, aggregateType, aggregateID, actor, requestID string, details any) error {
	event := a.operationalAudit(eventType, aggregateType, aggregateID, actor, requestID, details)
	var err error
	if err = a.repo.AppendAudit(ctx, event); err != nil {
		a.auditFailures.Add(1)
		a.log.Error("operational audit failed", "request_id", requestID, "event_type", eventType, "error", err)
	}
	return err
}

func (a *API) operationalAudit(eventType, aggregateType, aggregateID, actor, requestID string, details any) domain.AuditEvent {
	payload, err := json.Marshal(details)
	if err != nil {
		payload = json.RawMessage(`{"result":"failure","reason_code":"audit_serialization"}`)
	}
	return domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: time.Now().UTC(), ActorType: "administrator", ActorRef: actor, EventType: eventType, AggregateType: aggregateType, AggregateID: aggregateID, RequestID: requestID, Event: payload}
}

// AuditSecurityEvent records rejections that occur before the authenticated
// administration handler is entered.
func (a *API) AuditSecurityEvent(ctx context.Context, eventType, actor, requestID, method, path, reason string) {
	payload, _ := json.Marshal(map[string]any{"method": method, "path": path, "result": "failure", "reason_code": reason})
	event := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: time.Now().UTC(), ActorType: "administrator", ActorRef: actor, EventType: eventType, AggregateType: "http_route", AggregateID: path, RequestID: requestID, Event: payload}
	if err := a.repo.AppendAudit(ctx, event); err != nil {
		a.auditFailures.Add(1)
		a.log.Error("admin security audit failed", "request_id", requestID, "error", err)
	}
}
func (a *API) handleError(w http.ResponseWriter, r *http.Request, err error) {
	model := apiError{Status: http.StatusInternalServerError, Code: "INTERNAL_ERROR", Message: "An internal error occurred."}
	switch {
	case errors.Is(err, domain.ErrUnknownProduct):
		model = apiError{http.StatusNotFound, "UNKNOWN_PRODUCT", "The requested product does not exist."}
	case errors.Is(err, domain.ErrTrialExpired):
		model = apiError{http.StatusGone, "TRIAL_ALREADY_EXPIRED", "Trial is no longer available."}
	case errors.Is(err, domain.ErrNotFound):
		model = notFoundError(r)
	case errors.Is(err, domain.ErrConflict):
		model = conflictError(r)
	case errors.Is(err, domain.ErrIdempotencyConflict):
		model = apiError{http.StatusConflict, "IDEMPOTENCY_CONFLICT", "The idempotency key was already used for a different activation request."}
	case errors.Is(err, domain.ErrInvalid):
		model = apiError{http.StatusBadRequest, "INVALID_REQUEST", "The request is invalid."}
	case errors.Is(err, licencefmt.ErrMalformed), errors.Is(err, licencefmt.ErrSignature), errors.Is(err, licencefmt.ErrUntrustedRoot), errors.Is(err, licencefmt.ErrTransitionExpired), errors.Is(err, licencefmt.ErrTransitionInactive):
		model = apiError{http.StatusBadRequest, "INVALID_ROOT_TRANSITION", "The root transition artefact is invalid or outside its installation window."}
	case errors.Is(err, domain.ErrTrialUnavailable):
		model = apiError{http.StatusForbidden, "TRIAL_NOT_AVAILABLE", "A trial is not available."}
	case errors.Is(err, domain.ErrActivationExhausted):
		model = apiError{http.StatusConflict, "ACTIVATION_EXHAUSTED", "The activation code has no remaining uses."}
	case errors.Is(err, domain.ErrActivationExpired):
		model = apiError{http.StatusGone, "ACTIVATION_EXPIRED", "The activation code has expired."}
	case errors.Is(err, domain.ErrActivationRevoked):
		model = apiError{http.StatusGone, "ACTIVATION_REVOKED", "The activation or activation code was revoked."}
	case errors.Is(err, domain.ErrActivationInvalid):
		model = apiError{http.StatusNotFound, "ACTIVATION_INVALID", "The activation code is invalid."}
	case errors.Is(err, domain.ErrLicenceRevoked):
		model = apiError{http.StatusConflict, "LICENCE_REVOKED", "The licence was revoked."}
	case errors.Is(err, domain.ErrPayloadTooLarge):
		model = apiError{http.StatusUnprocessableEntity, "LICENCE_PAYLOAD_TOO_LARGE", "The licence payload exceeds the signing-provider limit."}
	case errors.Is(err, domain.ErrArchive):
		a.archiveFailures.Add(1)
		model = apiError{http.StatusServiceUnavailable, "ARCHIVE_UNAVAILABLE", "Durable archive acknowledgement is pending; retry this request."}
	case errors.Is(err, signing.ErrNoActiveIssuer), errors.Is(err, signing.ErrSignerUnavailable):
		a.signerErrors.Add(1)
		model = apiError{http.StatusServiceUnavailable, "SIGNER_UNAVAILABLE", "Licence signing is temporarily unavailable."}
	}
	if model.Code == "INTERNAL_ERROR" {
		a.databaseErrors.Add(1)
	}
	if model.Status >= 500 {
		a.log.Error("request failed", "event", "http.error", "result", "failure", "reason_code", model.Code, "request_id", requestID(r), "error", err)
	}
	writeError(w, r, model.Status, model.Code, model.Message)
}

type apiError struct {
	Status        int
	Code, Message string
}

func notFoundError(r *http.Request) apiError {
	path := r.URL.Path
	switch {
	case path == "/admin/v1/activations" && r.Method == http.MethodPost:
		return apiError{http.StatusNotFound, "LICENCE_NOT_FOUND", "The requested licence was not found."}
	case strings.Contains(path, "/products/"):
		return apiError{http.StatusNotFound, "UNKNOWN_PRODUCT", "The requested product does not exist."}
	case strings.Contains(path, "/trials/"):
		return apiError{http.StatusNotFound, "TRIAL_NOT_FOUND", "The requested trial was not found."}
	case strings.Contains(path, "/activation-codes/"):
		return apiError{http.StatusNotFound, "ACTIVATION_CODE_NOT_FOUND", "The requested activation code was not found."}
	case strings.Contains(path, "/activations/"):
		return apiError{http.StatusNotFound, "ACTIVATION_NOT_FOUND", "The requested activation was not found."}
	case strings.Contains(path, "/issuers/"):
		return apiError{http.StatusNotFound, "ISSUER_NOT_FOUND", "The requested issuer was not found."}
	case strings.Contains(path, "/root-transitions/"):
		return apiError{http.StatusNotFound, "ROOT_TRANSITION_NOT_FOUND", "The requested root transition was not found."}
	case strings.Contains(path, "/recovery-drills/"):
		return apiError{http.StatusNotFound, "RECOVERY_DRILL_NOT_FOUND", "The requested recovery drill report was not found."}
	case strings.Contains(path, "/licences/"):
		return apiError{http.StatusNotFound, "LICENCE_NOT_FOUND", "The requested licence was not found."}
	default:
		return apiError{http.StatusNotFound, "RESOURCE_NOT_FOUND", "The requested resource was not found."}
	}
}

func conflictError(r *http.Request) apiError {
	path := r.URL.Path
	switch {
	case strings.Contains(path, "/data-retention") || strings.Contains(path, "/data-deletions"):
		return apiError{http.StatusConflict, "DATA_DELETION_BLOCKED", "Deletion is blocked; inspect the dry-run plan and satisfy every blocker."}
	case path == "/admin/v1/products":
		return apiError{http.StatusConflict, "PRODUCT_ALREADY_EXISTS", "The product already exists."}
	case strings.HasSuffix(path, "/revoke"):
		return apiError{http.StatusConflict, "ALREADY_REVOKED", "The resource is already revoked."}
	case strings.Contains(path, "/issuers"):
		return apiError{http.StatusConflict, "ISSUER_STATE_CONFLICT", "The issuer lifecycle state conflicts with this operation."}
	case strings.Contains(path, "/root-transitions"):
		return apiError{http.StatusConflict, "ROOT_TRANSITION_STATE_CONFLICT", "The root transition lifecycle state conflicts with this operation."}
	case strings.Contains(path, "/recovery-drills"):
		return apiError{http.StatusConflict, "RECOVERY_DRILL_RUNNING", "Another recovery drill is already running."}
	default:
		return apiError{http.StatusConflict, "PURCHASE_REF_CONFLICT", "The idempotency reference conflicts with an existing record."}
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", "The request body exceeds the configured limit.")
			return false
		}
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "The request body is invalid.")
		return false
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "The request body must contain exactly one JSON value.")
		return false
	}
	return true
}

func methodAwareNotFound(mux *http.ServeMux) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead} {
			if method == r.Method {
				continue
			}
			copy := r.Clone(r.Context())
			copy.Method = method
			_, pattern := mux.Handler(copy)
			if pattern != "" && pattern != "/" {
				writeError(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "The HTTP method is not supported for this resource.")
				return
			}
		}
		writeError(w, r, http.StatusNotFound, "ROUTE_NOT_FOUND", "The requested API route does not exist.")
	}
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message, "request_id": requestID(r)}})
}

type requestIDKey struct{}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (a *API) enforceRate(w http.ResponseWriter, r *http.Request, scope, value string, limit int) bool {
	mac := hmac.New(sha256.New, a.ratePepper)
	_, _ = mac.Write([]byte(scope + "\x00" + value))
	key := scope + ":" + hex.EncodeToString(mac.Sum(nil))
	now := time.Now().UTC()
	window := a.rateConfig.RateLimit.Window
	start := now.Truncate(window)
	count, err := a.repo.ConsumeRateLimit(r.Context(), key, start, now.Add(a.rateConfig.RateLimit.Retention), limit)
	if err != nil {
		a.rateLimitFailures.Add(1)
		a.log.Error("rate-limit storage failed", "request_id", requestID(r), "scope", scope, "error", err)
		writeError(w, r, http.StatusServiceUnavailable, "RATE_LIMIT_UNAVAILABLE", "Request protection is temporarily unavailable.")
		return false
	}
	if count > limit {
		retry := int(time.Until(start.Add(window)).Seconds())
		if retry < 1 {
			retry = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeError(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests.")
		return false
	}
	return true
}
