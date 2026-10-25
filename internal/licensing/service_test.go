package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	archivefs "github.com/matthogan/licenceserver/internal/archive/filesystem"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

func TestIssueIdempotencyTrialAndRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(dir, "licensing.db")
	cfg.Archive.Directory = filepath.Join(dir, "archive")
	cfg.Signer.PrivateKeyFile = filepath.Join(dir, "issuer.key")
	cfg.Signer.IssuerCertificateFile = filepath.Join(dir, "issuer.cert")
	rootPub, rootPriv, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, issuerPriv, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cert, err := licencefmt.CreateIssuerCertificate(rootPriv, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer-test", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPub), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = signing.WriteKey(cfg.Signer.PrivateKeyFile, issuerPriv, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Signer.IssuerCertificateFile, []byte(cert), 0o600); err != nil {
		t.Fatal(err)
	}
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	signer, err := signing.Load(cfg.Signer.PrivateKeyFile, cfg.Signer.IssuerCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := archivefs.New(cfg.Archive.Directory)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(repo, archive, signing.NewManager(signer), []byte("a sufficiently long test pepper"), []byte("a distinct activation pepper long enough"), 30*24*time.Hour, true)
	if err = svc.CreateProduct(ctx, domain.Product{ProductID: "com.example.app", DisplayName: "Example", Active: true}, "test", "req-test"); err != nil {
		t.Fatal(err)
	}
	major := 1
	req := IssueLicenceRequest{ProductID: "com.example.app", LicenceType: "perpetual", CustomerRef: "cust_1", PurchaseRef: "order_1", MaxMajorVersion: &major, Entitlements: []string{"core"}}
	first, err := svc.IssueLicence(ctx, req, "test", "req_1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.IssueLicence(ctx, req, "test", "req_2")
	if err != nil {
		t.Fatal(err)
	}
	if !second.Existing || first.LicenceID != second.LicenceID || string(first.LicenceArtifact) != string(second.LicenceArtifact) {
		t.Fatal("idempotent issue did not return original artifact")
	}
	conflict := req
	conflict.CustomerRef = "cust_2"
	if _, err = svc.IssueLicence(ctx, conflict, "test", "req_3"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	trial1, err := svc.IssueTrial(ctx, IssueTrialRequest{ProductID: "com.example.app", InstallID: "550e8400-e29b-41d4-a716-446655440000"}, "req_4")
	if err != nil {
		t.Fatal(err)
	}
	trial2, err := svc.IssueTrial(ctx, IssueTrialRequest{ProductID: "com.example.app", InstallID: "550e8400-e29b-41d4-a716-446655440000"}, "req_5")
	if err != nil {
		t.Fatal(err)
	}
	if !trial2.Existing || trial1.LicenceID != trial2.LicenceID || !trial1.ExpiresAt.Equal(*trial2.ExpiresAt) {
		t.Fatal("trial was extended")
	}
	if _, err = licencefmt.VerifyArtifact(ed25519.PublicKey(rootPub), first.LicenceArtifact, "com.example.app", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	updatedName := "Example Desktop"
	updated, err := svc.UpdateProduct(ctx, "com.example.app", domain.ProductUpdate{DisplayName: &updatedName}, "test", "req-update")
	if err != nil || updated.DisplayName != updatedName {
		t.Fatalf("product update=%+v err=%v", updated, err)
	}
	shownTrial, _, err := svc.GetTrial(ctx, trial1.LicenceID)
	if err != nil || shownTrial.LicenceID != trial1.LicenceID {
		t.Fatalf("trial lookup=%+v err=%v", shownTrial, err)
	}
	reissued, err := svc.ReissueLicence(ctx, first.LicenceID, "entitlement-correction", "test", "req-reissue")
	if err != nil {
		t.Fatal(err)
	}
	if reissued.LicenceID == first.LicenceID || string(reissued.LicenceArtifact) == string(first.LicenceArtifact) {
		t.Fatal("reissue did not create a distinct signed artifact")
	}
	if _, err = licencefmt.VerifyArtifact(ed25519.PublicKey(rootPub), reissued.LicenceArtifact, "com.example.app", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	nonce := "6db829e5a8bb4cf2b8ebba2e61a80824"
	status, err := svc.LicenceStatus(ctx, domain.LicenceStatusRequest{LicenceID: first.LicenceID, ProductID: "com.example.app", Nonce: nonce}, "req-status")
	if err != nil {
		t.Fatal(err)
	}
	verifiedStatus, err := licencefmt.VerifyStatus(ed25519.PublicKey(rootPub), status, first.LicenceID, "com.example.app", nonce, time.Now().UTC(), time.Minute)
	if err != nil || verifiedStatus.Status != "active" {
		t.Fatalf("status=%+v err=%v", verifiedStatus, err)
	}
	tampered := status
	tampered.Payload.Status = "revoked"
	if _, err = licencefmt.VerifyStatus(ed25519.PublicKey(rootPub), tampered, first.LicenceID, "com.example.app", nonce, time.Now().UTC(), time.Minute); !errors.Is(err, licencefmt.ErrSignature) {
		t.Fatalf("tampered status error=%v", err)
	}
	if err = svc.Revoke(ctx, first.LicenceID, "manual-support", "status test", "test", "req-revoke"); err != nil {
		t.Fatal(err)
	}
	revokedStatus, err := svc.LicenceStatus(ctx, domain.LicenceStatusRequest{LicenceID: first.LicenceID, ProductID: "com.example.app", Nonce: nonce}, "req-status-revoked")
	if err != nil {
		t.Fatal(err)
	}
	verifiedStatus, err = licencefmt.VerifyStatus(ed25519.PublicKey(rootPub), revokedStatus, first.LicenceID, "com.example.app", nonce, time.Now().UTC(), time.Minute)
	if err != nil || verifiedStatus.Status != "revoked" {
		t.Fatalf("revoked status=%+v err=%v", verifiedStatus, err)
	}
	pending, _, err := repo.ArchiveStatus(ctx)
	if err != nil || pending != 0 {
		t.Fatalf("archive pending=%d err=%v", pending, err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "backup.db")
	if err = repo.Backup(ctx, backupPath); err != nil {
		t.Fatal(err)
	}
	logicalDir := filepath.Join(dir, "logical")
	if err = repo.ExportLogical(ctx, logicalDir, "test"); err != nil {
		t.Fatal(err)
	}
	publicSigningMetadata, err := os.ReadFile(filepath.Join(logicalDir, "signing-public-metadata.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(publicSigningMetadata), "private_key_ref") {
		t.Fatal("logical export disclosed a private signing-key reference")
	}
	backupCfg := cfg
	backupCfg.Database.DSN = backupPath
	backupRepo, err := sqliterepo.Open(backupCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = backupRepo.Verify(ctx, true); err != nil {
		t.Fatal(err)
	}
	backupRepo.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	loaded, err := repo.GetLicence(ctx, first.LicenceID)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.SignedArtifact) != string(first.LicenceArtifact) {
		t.Fatal("artifact changed after restart")
	}
}
