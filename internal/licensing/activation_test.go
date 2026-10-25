package licensing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	archivepkg "github.com/matthogan/licenceserver/internal/archive"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

var testActivationPepper = []byte("activation-test-pepper-is-distinct-and-long")

func TestActivationIdempotencyAdministrationAndRestart(t *testing.T) {
	ctx := context.Background()
	svc, repo, cfg, closeRepo := activationTestService(t)
	defer closeRepo()

	created, err := svc.CreateActivationCode(ctx, "lic-activation", 2, nil, "admin", "req-create-code")
	if err != nil {
		t.Fatal(err)
	}
	if created.Code == "" || created.ActivationCode.ActivationCodeID == "" || created.ActivationCode.HashVersion != "hmac-sha256-v1" {
		t.Fatalf("created=%+v", created)
	}
	legacy := sha256.Sum256([]byte(normalizeActivationCode(created.Code)))
	if string(created.ActivationCode.CodeHash) == string(legacy[:]) {
		t.Fatal("new activation code used an unkeyed digest")
	}
	storedJSON, err := json.Marshal(created.ActivationCode)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedJSON) == "" || strings.Contains(string(storedJSON), created.Code) || strings.Contains(string(storedJSON), "code_hash") {
		t.Fatalf("stored activation code exposed secret material: %s", storedJSON)
	}

	firstReq := RedeemActivationRequest{Code: created.Code, InstallationID: "installation-00000001", IdempotencyKey: "request-000000000001", Metadata: map[string]string{"platform": "windows"}}
	first, err := svc.RedeemActivationCode(ctx, firstReq, "http-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Existing || first.ActivationID == "" || first.LicenceID != "lic-activation" {
		t.Fatalf("first=%+v", first)
	}
	retry, err := svc.RedeemActivationCode(ctx, firstReq, "http-2")
	if err != nil {
		t.Fatal(err)
	}
	if !retry.Existing || retry.ActivationID != first.ActivationID || string(retry.LicenceArtifact) != string(first.LicenceArtifact) {
		t.Fatalf("retry=%+v first=%+v", retry, first)
	}
	installationRetry := firstReq
	installationRetry.IdempotencyKey = "request-000000000002"
	retry, err = svc.RedeemActivationCode(ctx, installationRetry, "http-3")
	if err != nil || !retry.Existing || retry.ActivationID != first.ActivationID {
		t.Fatalf("installation retry=%+v err=%v", retry, err)
	}
	conflict := firstReq
	conflict.InstallationID = "installation-00000002"
	if _, err = svc.RedeemActivationCode(ctx, conflict, "http-4"); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	metadataConflict := firstReq
	metadataConflict.Metadata = map[string]string{"platform": "linux"}
	if _, err = svc.RedeemActivationCode(ctx, metadataConflict, "http-4b"); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("expected metadata idempotency conflict, got %v", err)
	}
	otherCode, err := svc.CreateActivationCode(ctx, "lic-activation", 1, nil, "admin", "req-other-code")
	if err != nil {
		t.Fatal(err)
	}
	codeConflict := firstReq
	codeConflict.Code = otherCode.Code
	if _, err = svc.RedeemActivationCode(ctx, codeConflict, "http-4c"); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("expected cross-code idempotency conflict, got %v", err)
	}
	code, err := svc.GetActivationCode(ctx, created.ActivationCode.ActivationCodeID)
	if err != nil || code.UseCount != 1 {
		t.Fatalf("code=%+v err=%v", code, err)
	}
	record, err := svc.GetActivation(ctx, first.ActivationID)
	if err != nil {
		t.Fatal(err)
	}
	if record.InstanceRef == "" || record.InstanceRef == firstReq.InstallationID || record.RequestRef == firstReq.IdempotencyKey || string(record.Metadata) != `{"platform":"windows"}` {
		t.Fatalf("record=%+v", record)
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(recordJSON), firstReq.InstallationID) || strings.Contains(string(recordJSON), firstReq.IdempotencyKey) || strings.Contains(string(recordJSON), "instance_ref_hash") || strings.Contains(string(recordJSON), "request_ref_hash") {
		t.Fatalf("activation response exposed raw references: %s", recordJSON)
	}

	secondReq := RedeemActivationRequest{Code: created.Code, InstallationID: "installation-00000003", IdempotencyKey: "request-000000000003"}
	second, err := svc.RedeemActivationCode(ctx, secondReq, "http-5")
	if err != nil {
		t.Fatal(err)
	}
	thirdReq := RedeemActivationRequest{Code: created.Code, InstallationID: "installation-00000004", IdempotencyKey: "request-000000000004"}
	if _, err = svc.RedeemActivationCode(ctx, thirdReq, "http-6"); !errors.Is(err, domain.ErrActivationInvalid) {
		t.Fatalf("expected exhausted code, got %v", err)
	}
	if err = svc.RevokeActivation(ctx, first.ActivationID, "device retired", "admin", "req-revoke-device"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.RedeemActivationCode(ctx, firstReq, "http-7"); !errors.Is(err, domain.ErrActivationInvalid) {
		t.Fatalf("revoked activation was resurrected: %v", err)
	}
	third, err := svc.RedeemActivationCode(ctx, thirdReq, "http-8")
	if err != nil || third.ActivationID == "" {
		t.Fatalf("capacity was not released: %+v err=%v", third, err)
	}
	if err = svc.RevokeActivationCode(ctx, created.ActivationCode.ActivationCodeID, "order refunded", "admin", "req-revoke-code"); err != nil {
		t.Fatal(err)
	}
	fourthReq := RedeemActivationRequest{Code: created.Code, InstallationID: "installation-00000005", IdempotencyKey: "request-000000000005"}
	if _, err = svc.RedeemActivationCode(ctx, fourthReq, "http-9"); !errors.Is(err, domain.ErrActivationInvalid) {
		t.Fatalf("revoked code allowed new activation: %v", err)
	}
	secondRetry, err := svc.RedeemActivationCode(ctx, secondReq, "http-10")
	if err != nil || !secondRetry.Existing || secondRetry.ActivationID != second.ActivationID {
		t.Fatalf("code revocation stranded existing retry: %+v err=%v", secondRetry, err)
	}
	records, err := svc.ListActivations(ctx, "lic-activation", created.ActivationCode.ActivationCodeID, 100)
	if err != nil || len(records) != 3 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}

	// The same client request remains idempotent after closing and reopening
	// SQLite; it is not merely an in-memory retry cache.
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	restarted := New(repo, archivepkg.Disabled{}, svc.signer, []byte("trial-test-pepper-long-enough"), testActivationPepper, 30*24*time.Hour, false)
	retry, err = restarted.RedeemActivationCode(ctx, secondReq, "http-after-restart")
	if err != nil || !retry.Existing || retry.ActivationID != second.ActivationID {
		t.Fatalf("restart retry=%+v err=%v", retry, err)
	}
}

func TestConcurrentActivationCapacity(t *testing.T) {
	ctx := context.Background()
	svc, repo, _, closeRepo := activationTestService(t)
	defer closeRepo()
	created, err := svc.CreateActivationCode(ctx, "lic-activation", 3, nil, "admin", "req-code")
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 20
	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := RedeemActivationRequest{Code: created.Code, InstallationID: fmt.Sprintf("installation-%08d", i), IdempotencyKey: fmt.Sprintf("request-%012d", i)}
			_, redeemErr := svc.RedeemActivationCode(ctx, req, fmt.Sprintf("http-%d", i))
			results <- redeemErr
		}(i)
	}
	wg.Wait()
	close(results)
	success, exhausted := 0, 0
	for result := range results {
		switch {
		case result == nil:
			success++
		case errors.Is(result, domain.ErrActivationInvalid):
			exhausted++
		default:
			t.Fatalf("unexpected concurrent result: %v", result)
		}
	}
	if success != 3 || exhausted != attempts-3 {
		t.Fatalf("success=%d exhausted=%d", success, exhausted)
	}
	code, err := svc.GetActivationCode(ctx, created.ActivationCode.ActivationCodeID)
	if err != nil || code.UseCount != 3 {
		t.Fatalf("code=%+v err=%v", code, err)
	}
	records, err := svc.ListActivations(ctx, "", created.ActivationCode.ActivationCodeID, 100)
	if err != nil || len(records) != 3 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyActivationCodeRemainsRedeemable(t *testing.T) {
	ctx := context.Background()
	svc, repo, _, closeRepo := activationTestService(t)
	defer closeRepo()
	plaintext := "LEGACY-ABCDEF-GHIJKL-MNOPQR"
	normalized := normalizeActivationCode(plaintext)
	hash := sha256.Sum256([]byte(normalized))
	now := time.Now().UTC()
	legacy := domain.ActivationCode{ActivationCodeID: "legacy-code", CodeHash: hash[:], HashVersion: "sha256-v1", LicenceID: "lic-activation", MaxUses: 1, CreatedAt: now}
	audit := newAudit("activation_code.created", "activation_code", legacy.ActivationCodeID, "migration-test", "legacy", map[string]string{"source": "legacy"}, now)
	if err := repo.CreateActivationCode(ctx, legacy, audit); err != nil {
		t.Fatal(err)
	}
	issued, err := svc.RedeemActivationCode(ctx, RedeemActivationRequest{Code: plaintext, InstallationID: "legacy-installation-01", IdempotencyKey: "legacy-request-000001"}, "legacy-http")
	if err != nil || issued.ActivationID == "" {
		t.Fatalf("legacy issued=%+v err=%v", issued, err)
	}
}

func TestActivationExpiryBoundaryAndLicenceRevocation(t *testing.T) {
	ctx := context.Background()
	svc, _, _, closeRepo := activationTestService(t)
	defer closeRepo()
	fixed := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	svc.now = func() time.Time { return fixed }
	expires := fixed.Add(time.Hour)
	expiring, err := svc.CreateActivationCode(ctx, "lic-activation", 1, &expires, "admin", "create-expiring")
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return expires }
	request := RedeemActivationRequest{Code: expiring.Code, InstallationID: "expiry-installation-01", IdempotencyKey: "expiry-request-000001"}
	if _, err = svc.RedeemActivationCode(ctx, request, "expiry-http"); !errors.Is(err, domain.ErrActivationInvalid) {
		t.Fatalf("activation succeeded at exact expiry: %v", err)
	}

	svc.now = func() time.Time { return fixed }
	active, err := svc.CreateActivationCode(ctx, "lic-activation", 1, nil, "admin", "create-active")
	if err != nil {
		t.Fatal(err)
	}
	request = RedeemActivationRequest{Code: active.Code, InstallationID: "revoked-installation-1", IdempotencyKey: "revoked-request-00001"}
	if _, err = svc.RedeemActivationCode(ctx, request, "active-http"); err != nil {
		t.Fatal(err)
	}
	if err = svc.Revoke(ctx, "lic-activation", "refund", "", "admin", "revoke-licence"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.RedeemActivationCode(ctx, request, "revoked-http"); !errors.Is(err, domain.ErrActivationInvalid) {
		t.Fatalf("revoked licence was returned: %v", err)
	}
}

func activationTestService(t *testing.T) (*Service, *sqliterepo.Repository, config.Config, func()) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(dir, "activation.db")
	_, rootPrivate, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificate, err := licencefmt.CreateIssuerCertificate(rootPrivate, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer-activation", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "issuer.key")
	certFile := filepath.Join(dir, "issuer.cert")
	if err = signing.WriteKey(keyFile, issuerPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certFile, []byte(certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	local, err := signing.Load(keyFile, certFile)
	if err != nil {
		t.Fatal(err)
	}
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	svc := New(repo, archivepkg.Disabled{}, signing.NewManager(local), []byte("trial-test-pepper-long-enough"), testActivationPepper, 30*24*time.Hour, false)
	if err = repo.CreateProduct(ctx, domain.Product{ProductID: "activation-product", DisplayName: "Activation Product", DefaultTrialSeconds: 86400, Active: true, CreatedAt: now}, domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "test", EventType: "product.created", Event: json.RawMessage(`{"result":"success"}`)}); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	payload := domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic-activation", ProductID: "activation-product", LicenceType: "perpetual", IssuedAt: now, NotBefore: now}
	envelope, payloadBytes, err := licencefmt.SignPayload(local.PrivateKey(), local.KeyID(), payload)
	if err != nil {
		repo.Close()
		t.Fatal(err)
	}
	artifact, _ := licencefmt.MarshalArtifact(envelope, local.Certificate())
	sum := sha256.Sum256(payloadBytes)
	record := domain.LicenceRecord{LicenceID: payload.LicenceID, ProductID: payload.ProductID, LicenceType: payload.LicenceType, IssuerKeyID: local.KeyID(), IssuedAt: now, NotBefore: now, Status: "active", PayloadHash: sum[:], SignedArtifact: artifact, CreatedAt: now}
	audit := newAudit("licence.issued", "licence", record.LicenceID, "test", "setup", map[string]string{"source": "test"}, now)
	if err = repo.CreateLicence(ctx, record, nil, audit, nil); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	closed := false
	return svc, repo, cfg, func() {
		if !closed {
			_ = repo.Close()
			closed = true
		}
	}
}
