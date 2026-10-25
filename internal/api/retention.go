package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/security"
)

func (a *API) listRetentionPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := a.repo.ListRetentionPolicies(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": domain.RetentionPolicySchemaVersion, "policies": policies})
}

func (a *API) setRetentionPolicy(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Category         string `json:"category"`
		RetainForSeconds int64  `json:"retain_for_seconds"`
		RequireExport    bool   `json:"require_export"`
	}
	if !decode(w, r, &request) {
		return
	}
	now, actor, reqID := time.Now().UTC(), security.Actor(r.Context()), requestID(r)
	policy := domain.RetentionPolicy{Category: request.Category, RetainForSeconds: request.RetainForSeconds, RequireExport: request.RequireExport, CreatedAt: now, CreatedBy: actor}
	audit := a.operationalAudit("data.retention_policy_created", "retention_policy", request.Category, actor, reqID, map[string]any{"result": "success", "category": request.Category, "retain_for_seconds": request.RetainForSeconds, "require_export": request.RequireExport})
	created, err := a.repo.SetRetentionPolicy(r.Context(), policy, audit)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (a *API) planRetention(w http.ResponseWriter, r *http.Request) {
	var request domain.RetentionApplyRequest
	if !decode(w, r, &request) {
		return
	}
	plan, err := a.repo.PlanRetention(r.Context(), request, time.Now().UTC())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	a.addArchiveSuppressionBlocker(&plan)
	_ = a.appendOperationalAudit(r.Context(), "data.retention_planned", "retention", "active", security.Actor(r.Context()), requestID(r), map[string]any{"result": "success", "counts": plan.Counts, "blocker_count": len(plan.Blockers), "policy_versions": plan.PolicyVersions})
	writeJSON(w, http.StatusOK, plan)
}

func (a *API) applyRetention(w http.ResponseWriter, r *http.Request) {
	var request domain.RetentionApplyRequest
	if !decode(w, r, &request) {
		return
	}
	actor, reqID, now := security.Actor(r.Context()), requestID(r), time.Now().UTC()
	if a.rateConfig.Archive.Provider == "disabled" {
		_ = a.appendOperationalAudit(r.Context(), "data.retention_failed", "retention", "active", actor, reqID, map[string]any{"result": "failure", "reason_code": "suppression_archive_disabled"})
		a.handleError(w, r, domain.ErrRetentionBlocked)
		return
	}
	_ = a.appendOperationalAudit(r.Context(), "data.retention_requested", "retention", "active", actor, reqID, map[string]any{"result": "attempt"})
	audit := a.operationalAudit("data.retention_applied", "retention", "active", actor, reqID, map[string]any{"result": "success"})
	plan, err := a.repo.ApplyRetention(r.Context(), request, now, audit)
	if err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.retention_failed", "retention", "active", actor, reqID, map[string]any{"result": "failure", "reason_code": retentionFailureCode(err)})
		a.handleError(w, r, err)
		return
	}
	if err = a.ensureSuppressionArchived(r, "data.retention_suppression_archived", "retention", "active"); err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.retention_failed", "retention", "active", actor, reqID, map[string]any{"result": "failure", "reason_code": "suppression_delivery_failed", "committed": true})
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (a *API) createLegalHold(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Scope  domain.DataScope `json:"scope"`
		Reason string           `json:"reason"`
	}
	if !decode(w, r, &request) {
		return
	}
	actor, reqID, now := security.Actor(r.Context()), requestID(r), time.Now().UTC()
	hold := domain.LegalHold{HoldID: "hold_" + strings.ReplaceAll(uuid.NewString(), "-", ""), Scope: request.Scope, Reason: request.Reason, CreatedAt: now, CreatedBy: actor}
	audit := a.operationalAudit("data.legal_hold_created", "legal_hold", hold.HoldID, actor, reqID, map[string]any{"result": "success", "scope": safeDataScope(request.Scope), "reason": request.Reason})
	if err := a.repo.CreateLegalHold(r.Context(), hold, audit); err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, hold)
}

func (a *API) listLegalHolds(w http.ResponseWriter, r *http.Request) {
	activeOnly := r.URL.Query().Get("active") != "false"
	holds, err := a.repo.ListLegalHolds(r.Context(), activeOnly)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"holds": holds})
}

func (a *API) releaseLegalHold(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &request) {
		return
	}
	if strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 512 {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "A release reason is required.")
		return
	}
	actor, reqID, now, id := security.Actor(r.Context()), requestID(r), time.Now().UTC(), r.PathValue("id")
	audit := a.operationalAudit("data.legal_hold_released", "legal_hold", id, actor, reqID, map[string]any{"result": "success", "reason": request.Reason})
	hold, err := a.repo.ReleaseLegalHold(r.Context(), id, actor, now, audit)
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, hold)
}

func (a *API) planDataDeletion(w http.ResponseWriter, r *http.Request) {
	var request domain.DataDeletionRequest
	if !decode(w, r, &request) {
		return
	}
	plan, err := a.repo.PlanDataDeletion(r.Context(), request, time.Now().UTC())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	a.addArchiveSuppressionBlocker(&plan)
	_ = a.appendOperationalAudit(r.Context(), "data.deletion_planned", "data_scope", "redacted", security.Actor(r.Context()), requestID(r), map[string]any{"result": "success", "scope": safeDataScope(request.Scope), "counts": plan.Counts, "blocker_count": len(plan.Blockers)})
	writeJSON(w, http.StatusOK, plan)
}

func (a *API) deleteData(w http.ResponseWriter, r *http.Request) {
	var request domain.DataDeletionRequest
	if !decode(w, r, &request) {
		return
	}
	actor, reqID, now := security.Actor(r.Context()), requestID(r), time.Now().UTC()
	if a.rateConfig.Archive.Provider == "disabled" {
		_ = a.appendOperationalAudit(r.Context(), "data.deletion_failed", "data_scope", "redacted", actor, reqID, map[string]any{"result": "failure", "reason_code": "suppression_archive_disabled", "scope": safeDataScope(request.Scope)})
		a.handleError(w, r, domain.ErrRetentionBlocked)
		return
	}
	_ = a.appendOperationalAudit(r.Context(), "data.deletion_requested", "data_scope", "redacted", actor, reqID, map[string]any{"result": "attempt", "scope": safeDataScope(request.Scope)})
	audit := a.operationalAudit("data.deleted", "data_scope", "redacted", actor, reqID, map[string]any{"result": "success", "scope": safeDataScope(request.Scope)})
	plan, err := a.repo.DeleteData(r.Context(), request, now, audit)
	if err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.deletion_failed", "data_scope", "redacted", actor, reqID, map[string]any{"result": "failure", "reason_code": retentionFailureCode(err), "scope": safeDataScope(request.Scope)})
		a.handleError(w, r, err)
		return
	}
	if err = a.ensureSuppressionArchived(r, "data.deletion_suppression_archived", "data_scope", "redacted"); err != nil {
		_ = a.appendOperationalAudit(r.Context(), "data.deletion_failed", "data_scope", "redacted", actor, reqID, map[string]any{"result": "failure", "reason_code": "suppression_delivery_failed", "committed": true, "scope": safeDataScope(request.Scope)})
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (a *API) listDataTombstones(w http.ResponseWriter, r *http.Request) {
	tombstones, err := a.repo.ListSuppressionTombstones(r.Context())
	if err != nil {
		a.handleError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": 1, "tombstones": tombstones})
}

func (a *API) addArchiveSuppressionBlocker(plan *domain.DataDeletionPlan) {
	if a.rateConfig.Archive.Provider == "disabled" && plan.Counts.Tombstones > 0 {
		plan.Blockers = append(plan.Blockers, domain.DeletionBlocker{Code: "suppression_archive_disabled", Detail: "configure the immutable archive before deleting live data"})
		plan.Executable = false
	}
}

func safeDataScope(scope domain.DataScope) map[string]any {
	return map[string]any{"product_id": scope.ProductID, "licence_id": scope.LicenceID, "customer_ref_filter": scope.CustomerRef != ""}
}

func retentionFailureCode(err error) string {
	if errors.Is(err, domain.ErrRetentionBlocked) {
		return "blocked"
	}
	if errors.Is(err, domain.ErrInvalid) {
		return "invalid_request"
	}
	return "transaction_failed"
}

func (a *API) ensureSuppressionArchived(r *http.Request, eventType, aggregateType, aggregateID string) error {
	if a.svc == nil {
		return errors.New("archive delivery service is unavailable")
	}
	delivered, err := a.svc.ReconcileArchive(r.Context())
	if err != nil {
		return errors.Join(domain.ErrArchive, err)
	}
	return a.appendOperationalAudit(r.Context(), eventType, aggregateType, aggregateID, security.Actor(r.Context()), requestID(r), map[string]any{"result": "success", "events": delivered})
}
