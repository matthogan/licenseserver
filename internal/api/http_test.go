package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/exportdata"
	archivefs "github.com/matthogan/licenceserver/internal/archive/filesystem"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/continuousbackup"
	dataexporter "github.com/matthogan/licenceserver/internal/dataexport"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/licensing"
	"github.com/matthogan/licenceserver/internal/rootkey"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
	_ "modernc.org/sqlite"
)

func TestDecodeRejectsTrailingJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"one":1} {"two":2}`))
	rec := httptest.NewRecorder()
	var value map[string]int
	if decode(rec, req, &value) {
		t.Fatal("decode accepted multiple JSON values")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func FuzzStrictHTTPJSONDecoderFailsClosed(f *testing.F) {
	f.Add([]byte(`{"product_id":"product","licence_type":"perpetual","purchase_ref":"order"}`))
	f.Add([]byte(`{"one":1}{"two":2}`))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/test", bytes.NewReader(data))
		rec := httptest.NewRecorder()
		var value licensing.IssueLicenceRequest
		_ = decode(rec, req, &value)
	})
}

func TestStableErrorCatalogue(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := &API{log: logger}
	tests := []struct {
		path   string
		err    error
		status int
		code   string
	}{
		{"/v1/trials", domain.ErrUnknownProduct, 404, "UNKNOWN_PRODUCT"},
		{"/v1/trials", domain.ErrTrialExpired, 410, "TRIAL_ALREADY_EXPIRED"},
		{"/v1/activations", domain.ErrActivationExhausted, 409, "ACTIVATION_EXHAUSTED"},
		{"/v1/activations", domain.ErrActivationExpired, 410, "ACTIVATION_EXPIRED"},
		{"/admin/v1/licences/missing", domain.ErrNotFound, 404, "LICENCE_NOT_FOUND"},
		{"/admin/v1/trials/missing", domain.ErrNotFound, 404, "TRIAL_NOT_FOUND"},
		{"/admin/v1/issuers/missing", domain.ErrNotFound, 404, "ISSUER_NOT_FOUND"},
		{"/admin/v1/root-transitions/missing", domain.ErrNotFound, 404, "ROOT_TRANSITION_NOT_FOUND"},
		{"/admin/v1/root-transitions/activate", licencefmt.ErrSignature, 400, "INVALID_ROOT_TRANSITION"},
		{"/admin/v1/root-transitions/activate", domain.ErrConflict, 409, "ROOT_TRANSITION_STATE_CONFLICT"},
		{"/admin/v1/recovery-drills/missing", domain.ErrNotFound, 404, "RECOVERY_DRILL_NOT_FOUND"},
		{"/admin/v1/recovery-drills", domain.ErrConflict, 409, "RECOVERY_DRILL_RUNNING"},
		{"/admin/v1/data-deletions", domain.ErrRetentionBlocked, 409, "DATA_DELETION_BLOCKED"},
		{"/admin/v1/products", domain.ErrConflict, 409, "PRODUCT_ALREADY_EXISTS"},
		{"/admin/v1/licences", signing.ErrNoActiveIssuer, 503, "SIGNER_UNAVAILABLE"},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, test.path, nil)
			rec := httptest.NewRecorder()
			a.handleError(rec, req, test.err)
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != test.status || body.Error.Code != test.code {
				t.Fatalf("status=%d code=%s body=%s", rec.Code, body.Error.Code, rec.Body.String())
			}
		})
	}
}

func TestUnknownRouteAndMethodUseJSONErrors(t *testing.T) {
	c := config.Defaults()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(nil, nil, nil, nil, c, []byte("rate-limit-test-pepper-that-is-long-enough"), logger).PublicHandler()
	for _, test := range []struct {
		method, path, code string
		status             int
	}{{http.MethodGet, "/v1/missing", "ROUTE_NOT_FOUND", 404}, {http.MethodDelete, "/v1/trials", "METHOD_NOT_ALLOWED", 405}} {
		req := httptest.NewRequest(test.method, test.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != test.status || !bytes.Contains(rec.Body.Bytes(), []byte(test.code)) || rec.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
	}
}

func TestAdminReadIsAudited(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "audit.db")
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(nil, nil, repo, nil, c, []byte("rate-limit-test-pepper-that-is-long-enough"), logger).AdminHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/health/live", nil)
	req.Header.Set("X-Request-ID", "req-audit-read")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(c.Database.DSN))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var eventType, requestID, payload string
	if err = db.QueryRow(`SELECT event_type,request_id,event_json FROM audit_events ORDER BY rowid DESC LIMIT 1`).Scan(&eventType, &requestID, &payload); err != nil {
		t.Fatal(err)
	}
	if eventType != "admin.request" || requestID != "req-audit-read" {
		t.Fatalf("event=%q request=%q payload=%s", eventType, requestID, payload)
	}
}

func TestDataExportIsDeterministicValidatedAndAudited(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "data-export.db")
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2034, 2, 3, 4, 5, 6, 0, time.UTC)
	audit := func(eventID, eventType, aggregateType, aggregateID string) domain.AuditEvent {
		return domain.AuditEvent{EventID: eventID, OccurredAt: now, ActorType: "test", EventType: eventType, AggregateType: aggregateType, AggregateID: aggregateID, Event: json.RawMessage(`{"result":"success"}`)}
	}
	product := domain.Product{ProductID: "export-product", DisplayName: "Export Product", Active: true, CreatedAt: now}
	if err = repo.CreateProduct(ctx, product, audit("evt-product", "product.created", "product", product.ProductID)); err != nil {
		t.Fatal(err)
	}
	licence := domain.LicenceRecord{
		LicenceID: "lic-export", ProductID: product.ProductID, LicenceType: "perpetual",
		CustomerRef: "opaque-customer", IssuerKeyID: "issuer", IssuedAt: now,
		NotBefore: now, Status: "active", PayloadHash: []byte{0xab},
		SignedArtifact: json.RawMessage(`{"schema_version":1,"licence_id":"lic-export"}`), CreatedAt: now,
	}
	if err = repo.CreateLicence(ctx, licence, nil, audit("evt-licence", "licence.issued", "licence", licence.LicenceID), nil); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(nil, nil, repo, nil, c, []byte("rate-limit-test-pepper-that-is-long-enough"), logger).AdminHandler()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/data-exports", bytes.NewBufferString(`{"product_id":"export-product","customer_ref":"opaque-customer"}`))
	req.Header.Set("X-Request-ID", "req-data-export")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/gzip" || rec.Header().Get("X-Licd-Export-SHA256") == "" {
		t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	bundle, err := dataexporter.ReadArchive(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Manifest.SchemaVersion != exportdata.SchemaVersion || len(bundle.Licences) != 1 || bundle.Licences[0].LicenceID != licence.LicenceID {
		t.Fatalf("unexpected bundle: manifest=%+v licences=%+v", bundle.Manifest, bundle.Licences)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(c.Database.DSN))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, eventType := range []string{"data.export_requested", "data.exported", "admin.request"} {
		var count int
		if err = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE request_id = ? AND event_type = ?`, "req-data-export", eventType).Scan(&count); err != nil || count != 1 {
			t.Fatalf("event=%s count=%d err=%v", eventType, count, err)
		}
	}

	invalid := httptest.NewRequest(http.MethodPost, "/admin/v1/data-exports", bytes.NewBufferString(`{"from":"2034-02-04T00:00:00Z","to":"2034-02-03T00:00:00Z"}`))
	invalid.Header.Set("X-Request-ID", "req-data-export-invalid")
	invalidRec := httptest.NewRecorder()
	handler.ServeHTTP(invalidRec, invalid)
	if invalidRec.Code != http.StatusBadRequest || !bytes.Contains(invalidRec.Body.Bytes(), []byte(`"INVALID_REQUEST"`)) {
		t.Fatalf("invalid status=%d body=%s", invalidRec.Code, invalidRec.Body.String())
	}
	var failed int
	if err = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE request_id = ? AND event_type = 'data.export_failed'`, "req-data-export-invalid").Scan(&failed); err != nil || failed != 1 {
		t.Fatalf("failed audit count=%d err=%v", failed, err)
	}
}

func TestAdminDataDeletionIsPlannedAppliedAndAudited(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "data-deletion.db")
	c.Archive.Directory = filepath.Join(t.TempDir(), "data-deletion-archive")
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-2 * time.Hour)
	audit := func(eventType, aggregateType, aggregateID string) domain.AuditEvent {
		return domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "test", EventType: eventType, AggregateType: aggregateType, AggregateID: aggregateID, Event: json.RawMessage(`{"result":"success"}`)}
	}
	product := domain.Product{ProductID: "delete-product", DisplayName: "Delete", Active: true, CreatedAt: now}
	if err = repo.CreateProduct(ctx, product, audit("product.created", "product", product.ProductID)); err != nil {
		t.Fatal(err)
	}
	licence := domain.LicenceRecord{LicenceID: "lic-delete-api", ProductID: product.ProductID, LicenceType: "perpetual", CustomerRef: "opaque-delete-customer", IssuerKeyID: "issuer", IssuedAt: now, NotBefore: now, Status: "active", PayloadHash: []byte{1}, SignedArtifact: json.RawMessage(`{"signed":true}`), CreatedAt: now}
	if err = repo.CreateLicence(ctx, licence, nil, audit("licence.issued", "licence", licence.LicenceID), nil); err != nil {
		t.Fatal(err)
	}
	revocation := domain.Revocation{RevocationID: "rev-delete-api", LicenceID: licence.LicenceID, ReasonCode: "customer", RevokedAt: now.Add(time.Minute)}
	if err = repo.RevokeLicence(ctx, revocation, audit("licence.revoked", "licence", licence.LicenceID), nil); err != nil {
		t.Fatal(err)
	}

	store, err := archivefs.New(c.Archive.Directory)
	if err != nil {
		t.Fatal(err)
	}
	svc := licensing.New(repo, store, signing.NewManager(nil), []byte("trial-pepper"), []byte("activation-pepper"), 24*time.Hour, true)
	handler := New(svc, nil, repo, nil, c, []byte("rate-limit-test-pepper-that-is-long-enough"), slog.New(slog.NewTextHandler(io.Discard, nil))).AdminHandler()
	body := `{"scope":{"licence_id":"lic-delete-api"},"reason":"verified customer request","acknowledge_immutable_residue":true}`
	planReq := httptest.NewRequest(http.MethodPost, "/admin/v1/data-deletions/plan", bytes.NewBufferString(body))
	planRec := httptest.NewRecorder()
	handler.ServeHTTP(planRec, planReq)
	var plan domain.DataDeletionPlan
	if planRec.Code != http.StatusOK || json.Unmarshal(planRec.Body.Bytes(), &plan) != nil || !plan.Executable || plan.Counts.Licences != 1 {
		t.Fatalf("plan status=%d plan=%+v body=%s", planRec.Code, plan, planRec.Body.String())
	}
	deleteReq := httptest.NewRequest(http.MethodPost, "/admin/v1/data-deletions", bytes.NewBufferString(body))
	deleteReq.Header.Set("X-Request-ID", "req-data-delete")
	deleteRec := httptest.NewRecorder()
	handler.ServeHTTP(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", deleteRec.Code, deleteRec.Body.String())
	}
	if _, err = repo.GetLicence(ctx, licence.LicenceID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("licence was not deleted: %v", err)
	}
	events, err := store.ListEvents(ctx)
	if err != nil || len(events) != 1 || events[0].EventType != "data.suppressed" || events[0].Suppression == nil {
		t.Fatalf("archived suppressions=%+v err=%v", events, err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(c.Database.DSN))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, eventType := range []string{"data.deletion_requested", "data.deleted", "admin.request"} {
		var count int
		if err = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE request_id=? AND event_type=?`, "req-data-delete", eventType).Scan(&count); err != nil || count != 1 {
			t.Fatalf("event=%s count=%d err=%v", eventType, count, err)
		}
	}
}

func TestPersistentMaintenanceModeAuditsAndGatesMutations(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "maintenance.db")
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(nil, nil, repo, nil, c, []byte("rate-limit-test-pepper-that-is-long-enough"), logger)
	admin := server.AdminHandler()
	public := server.PublicHandler()

	enableBody := bytes.NewBufferString(`{"enabled":true,"reason":"pre-migration safety window"}`)
	enable := httptest.NewRequest(http.MethodPost, "/admin/v1/maintenance", enableBody)
	enableRec := httptest.NewRecorder()
	admin.ServeHTTP(enableRec, enable)
	if enableRec.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", enableRec.Code, enableRec.Body.String())
	}

	blocked := httptest.NewRequest(http.MethodPost, "/v1/trials", bytes.NewBufferString(`{}`))
	blockedRec := httptest.NewRecorder()
	public.ServeHTTP(blockedRec, blocked)
	if blockedRec.Code != http.StatusServiceUnavailable || blockedRec.Header().Get("Retry-After") != "60" || !bytes.Contains(blockedRec.Body.Bytes(), []byte(`"MAINTENANCE"`)) {
		t.Fatalf("blocked status=%d headers=%v body=%s", blockedRec.Code, blockedRec.Header(), blockedRec.Body.String())
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/admin/v1/maintenance", nil)
	statusRec := httptest.NewRecorder()
	admin.ServeHTTP(statusRec, statusReq)
	var state domain.MaintenanceState
	if err = json.Unmarshal(statusRec.Body.Bytes(), &state); err != nil || !state.Enabled || state.Reason != "pre-migration safety window" {
		t.Fatalf("state=%+v err=%v body=%s", state, err, statusRec.Body.String())
	}

	disableBody := bytes.NewBufferString(`{"enabled":false,"reason":"migration complete"}`)
	disableReq := httptest.NewRequest(http.MethodPost, "/admin/v1/maintenance", disableBody)
	disableRec := httptest.NewRecorder()
	admin.ServeHTTP(disableRec, disableReq)
	if disableRec.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", disableRec.Code, disableRec.Body.String())
	}
	persisted, err := repo.GetMaintenance(ctx)
	if err != nil || persisted.Enabled || persisted.Reason != "migration complete" {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(c.Database.DSN))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var transitions int
	if err = db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type IN ('maintenance.enabled','maintenance.disabled')`).Scan(&transitions); err != nil || transitions != 2 {
		t.Fatalf("maintenance audit transitions=%d err=%v", transitions, err)
	}
}

func TestRootTransitionAdminAPIActivatesAndPublishesKeyring(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "roots.db")
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	manager := signing.NewManager(nil)
	roots := rootkey.New(repo, manager)
	if err = roots.Initialize(ctx, oldPublic); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	artefact, err := licencefmt.CreateRootTransition(oldPrivate, newPrivate, licencefmt.RootTransitionPayload{SchemaVersion: 1, TransitionID: "api-transition", Algorithm: "Ed25519", CreatedAt: now.Add(-time.Minute), NotBefore: now.Add(-30 * time.Second), OverlapUntil: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), Reason: "API integration test"})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewWithRoots(nil, nil, roots, repo, nil, c, []byte("rate-limit-test-pepper-that-is-long-enough"), logger).AdminHandler()
	wrongBody, _ := json.Marshal(map[string]string{"artifact": artefact, "confirm_new_root": "sha256:wrong"})
	wrongRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongRecorder, httptest.NewRequest(http.MethodPost, "/admin/v1/root-transitions/activate", bytes.NewReader(wrongBody)))
	if wrongRecorder.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirmation status=%d body=%s", wrongRecorder.Code, wrongRecorder.Body.String())
	}
	inspection, _ := licencefmt.InspectRootTransition(artefact)
	body, _ := json.Marshal(map[string]string{"artifact": artefact, "confirm_new_root": inspection.Payload.NewRootKeyID})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/admin/v1/root-transitions/activate", bytes.NewReader(body)))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("activate status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/v1/roots/keyring", nil))
	var keyring licencefmt.TrustedKeyring
	if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &keyring); recorder.Code != http.StatusOK || decodeErr != nil || len(keyring.Roots) != 2 {
		t.Fatalf("keyring status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPublicSignedLicenceStatusEndpoint(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(dir, "status.db")
	c.Archive.Directory = filepath.Join(dir, "archive")
	c.Signer.PrivateKeyFile = filepath.Join(dir, "issuer.key")
	c.Signer.IssuerCertificateFile = filepath.Join(dir, "issuer.cert")
	rootPub, rootPrivate, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerPrivate, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cert, err := licencefmt.CreateIssuerCertificate(rootPrivate, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer-status", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPub), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"product-status"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = signing.WriteKey(c.Signer.PrivateKeyFile, issuerPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(c.Signer.IssuerCertificateFile, []byte(cert), 0o600); err != nil {
		t.Fatal(err)
	}
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	localSigner, err := signing.Load(c.Signer.PrivateKeyFile, c.Signer.IssuerCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := archivefs.New(c.Archive.Directory)
	if err != nil {
		t.Fatal(err)
	}
	svc := licensing.New(repo, archive, signing.NewManager(localSigner), []byte("trial-pepper-long-enough"), []byte("activation-pepper-long-enough"), 24*time.Hour, true)
	if err = svc.CreateProduct(ctx, domain.Product{ProductID: "product-status", DisplayName: "Status", Active: true}, "test", "req-product"); err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueLicence(ctx, licensing.IssueLicenceRequest{ProductID: "product-status", LicenceType: "perpetual", PurchaseRef: "status-order"}, "test", "req-issue")
	if err != nil {
		t.Fatal(err)
	}
	nonce := "a0d5032c7e004fbb8e98f95954358b80"
	body, _ := json.Marshal(domain.LicenceStatusRequest{LicenceID: issued.LicenceID, ProductID: "product-status", Nonce: nonce})
	req := httptest.NewRequest(http.MethodPost, "/v1/licences/status", bytes.NewReader(body))
	req.RemoteAddr = "192.0.2.10:443"
	rec := httptest.NewRecorder()
	New(svc, nil, repo, nil, c, []byte("rate-pepper-long-enough-for-tests"), slog.New(slog.NewTextHandler(io.Discard, nil))).PublicHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var statement domain.SignedLicenceStatus
	if err = json.Unmarshal(rec.Body.Bytes(), &statement); err != nil {
		t.Fatal(err)
	}
	verified, err := licencefmt.VerifyStatus(ed25519.PublicKey(rootPub), statement, issued.LicenceID, "product-status", nonce, time.Now().UTC(), time.Minute)
	if err != nil || verified.Status != "active" {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
}

func TestReadinessBlocksStrictArchiveBacklogAndIncompatibleSchema(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "ready.db")
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(c.Database.DSN))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`INSERT INTO archive_outbox(event_id,event_type,event_json,created_at,archived_at) VALUES('evt-pending','licence.issued','{}',?,NULL)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	archive, err := archivefs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := licensing.New(repo, archive, signing.NewManager(nil), []byte("trial-pepper-long-enough"), []byte("activation-pepper-long-enough"), time.Hour, true)
	backup := continuousbackup.New(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := New(svc, nil, repo, backup, c, []byte("rate-pepper-long-enough-for-tests"), slog.New(slog.NewTextHandler(io.Discard, nil))).AdminHandler()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/health/ready", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !bytes.Contains(rec.Body.Bytes(), []byte(`"archive":"blocked"`)) {
		t.Fatalf("strict backlog readiness status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err = db.Exec(`DELETE FROM schema_migrations WHERE version=(SELECT MAX(version) FROM schema_migrations)`); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/health/ready", nil))
	if rec.Code != http.StatusServiceUnavailable || !bytes.Contains(rec.Body.Bytes(), []byte(`"database":"schema_incompatible"`)) {
		t.Fatalf("schema readiness status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMetricsIncludeDurationArchiveAndDatabaseFamilies(t *testing.T) {
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "metrics.db")
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	archive, err := archivefs.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	svc := licensing.New(repo, archive, signing.NewManager(nil), []byte("trial-pepper-long-enough"), []byte("activation-pepper-long-enough"), time.Hour, true)
	backup := continuousbackup.New(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler := New(svc, nil, repo, backup, c, []byte("rate-pepper-long-enough-for-tests"), slog.New(slog.NewTextHandler(io.Discard, nil))).AdminHandler()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/v1/health/live", nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/v1/metrics", nil))
	for _, metric := range []string{"licd_http_request_duration_seconds_bucket", "licd_archive_pending_events", "licd_archive_failures_total", "licd_database_open_connections", "licd_database_wait_count_total", "licd_database_wait_duration_seconds_total", "licd_signer_errors_total"} {
		if !bytes.Contains(rec.Body.Bytes(), []byte(metric)) {
			t.Fatalf("metrics missing %s:\n%s", metric, rec.Body.String())
		}
	}
}
