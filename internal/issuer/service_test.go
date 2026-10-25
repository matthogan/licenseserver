package issuer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	archivepkg "github.com/matthogan/licenceserver/internal/archive"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/licensing"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

func TestRotationCompromiseRecoveryAndRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Now().UTC()
	rootPublic, rootPrivate, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	writeIssuer(t, dir, rootPrivate, "issuer-old", now.Add(-time.Hour), now.Add(48*time.Hour))

	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(dir, "licensing.db")
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	manager := signing.NewManager(nil)
	lifecycle, err := New(repo, manager, rootPublic, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = lifecycle.Initialize(ctx, "issuer-old.key", "issuer-old.cert"); err != nil {
		t.Fatal(err)
	}
	svc := licensing.New(repo, archivepkg.Disabled{}, manager, []byte("a sufficiently long test pepper"), []byte("a distinct activation pepper long enough"), 30*24*time.Hour, false)
	if err = svc.CreateProduct(ctx, domain.Product{ProductID: "com.example.app", DisplayName: "Example", Active: true}, "test", "req-test"); err != nil {
		t.Fatal(err)
	}
	oldLicence := issue(t, ctx, svc, "order-old")

	writeIssuer(t, dir, rootPrivate, "issuer-new", now.Add(-time.Hour), now.Add(48*time.Hour))
	rotated, err := lifecycle.Rotate(ctx, LocalFiles{PrivateKeyFile: "issuer-new.key", CertificateFile: "issuer-new.cert"}, "test-admin", "req-rotate")
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Status != domain.IssuerStatusActive || rotated.IssuerKeyID != "issuer-new" || rotated.Fingerprint == "" {
		t.Fatalf("rotated issuer=%+v", rotated)
	}
	old, err := lifecycle.Get(ctx, "issuer-old")
	if err != nil || old.Status != domain.IssuerStatusRetired {
		t.Fatalf("old issuer=%+v err=%v", old, err)
	}
	newLicence := issue(t, ctx, svc, "order-new")
	assertArtifact(t, rootPublic, oldLicence, "issuer-old")
	assertArtifact(t, rootPublic, newLicence, "issuer-new")

	// A failed durable rotation must leave the in-memory signer unchanged.
	if _, err = lifecycle.Rotate(ctx, LocalFiles{PrivateKeyFile: "issuer-new.key", CertificateFile: "issuer-new.cert"}, "test-admin", "req-duplicate"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("expected duplicate conflict, got %v", err)
	}
	if current, ok := manager.Current(); !ok || current != "issuer-new" {
		t.Fatalf("current issuer after failed rotation=%q ok=%v", current, ok)
	}
	if _, err = lifecycle.SetStatus(ctx, "issuer-new", domain.IssuerStatusRetired, "unsafe retirement", false, "test-admin", "req-retire"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("expected explicit no-active refusal, got %v", err)
	}

	compromised, err := lifecycle.SetStatus(ctx, "issuer-new", domain.IssuerStatusCompromised, "key copied from host", false, "incident-admin", "req-compromise")
	if err != nil {
		t.Fatal(err)
	}
	if compromised.Status != domain.IssuerStatusCompromised {
		t.Fatalf("compromised issuer=%+v", compromised)
	}
	if err = manager.Healthy(time.Now().UTC()); !errors.Is(err, signing.ErrNoActiveIssuer) {
		t.Fatalf("issuance did not fail closed: %v", err)
	}
	if _, err = lifecycle.Activate(ctx, "issuer-new", "incident-admin", "req-reactivate"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("expected compromised issuer activation rejection, got %v", err)
	}
	if _, err = svc.IssueLicence(ctx, paidRequest("order-blocked"), "test", "req-blocked"); !errors.Is(err, signing.ErrNoActiveIssuer) {
		t.Fatalf("expected no active issuer, got %v", err)
	}

	writeIssuer(t, dir, rootPrivate, "issuer-recovery", now.Add(-time.Hour), now.Add(48*time.Hour))
	recovered, err := lifecycle.Rotate(ctx, LocalFiles{PrivateKeyFile: "issuer-recovery.key", CertificateFile: "issuer-recovery.cert", Replaces: "issuer-new"}, "recovery-admin", "req-recover")
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Status != domain.IssuerStatusActive {
		t.Fatalf("recovered issuer=%+v", recovered)
	}
	recoveryLicence := issue(t, ctx, svc, "order-recovery")
	assertArtifact(t, rootPublic, recoveryLicence, "issuer-recovery")
	assertArtifact(t, rootPublic, oldLicence, "issuer-old")
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}

	// Restart restores the database-selected key rather than the obsolete
	// bootstrap paths still present in static configuration.
	restartedManager := signing.NewManager(nil)
	restarted, err := New(repo, restartedManager, rootPublic, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Initialize(ctx, "issuer-old.key", "issuer-old.cert"); err != nil {
		t.Fatal(err)
	}
	if current, ok := restartedManager.Current(); !ok || current != "issuer-recovery" {
		t.Fatalf("restored issuer=%q ok=%v", current, ok)
	}
}

func TestRejectsUntrustedAndOutOfDirectoryIssuer(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	outside := t.TempDir()
	now := time.Now().UTC()
	rootPublic, _, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, wrongRoot, _ := signing.GenerateKey()
	writeIssuer(t, dir, wrongRoot, "untrusted", now.Add(-time.Hour), now.Add(time.Hour))
	writeIssuer(t, outside, wrongRoot, "outside", now.Add(-time.Hour), now.Add(time.Hour))
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(dir, "db.sqlite")
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := New(repo, signing.NewManager(nil), rootPublic, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lifecycle.Register(ctx, LocalFiles{PrivateKeyFile: "untrusted.key", CertificateFile: "untrusted.cert"}, "test", "req"); err == nil {
		t.Fatal("expected untrusted certificate rejection")
	}
	if _, err = lifecycle.Register(ctx, LocalFiles{PrivateKeyFile: filepath.Join(outside, "outside.key"), CertificateFile: filepath.Join(outside, "outside.cert")}, "test", "req"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("expected directory boundary rejection, got %v", err)
	}
}

func writeIssuer(t *testing.T, dir string, root ed25519.PrivateKey, id string, notBefore, notAfter time.Time) {
	t.Helper()
	public, private, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := licencefmt.CreateIssuerCertificate(root, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: id, Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(public), AuthorityNotBefore: notBefore, AuthorityNotAfter: notAfter, Products: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = signing.WriteKey(filepath.Join(dir, id+".key"), private, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, id+".cert"), []byte(certificate+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func paidRequest(purchase string) licensing.IssueLicenceRequest {
	return licensing.IssueLicenceRequest{ProductID: "com.example.app", LicenceType: "perpetual", PurchaseRef: purchase, SeatCount: 1}
}

func issue(t *testing.T, ctx context.Context, svc *licensing.Service, purchase string) licensing.IssuedLicence {
	t.Helper()
	licence, err := svc.IssueLicence(ctx, paidRequest(purchase), "test", "req-"+purchase)
	if err != nil {
		t.Fatal(err)
	}
	return licence
}

func assertArtifact(t *testing.T, root ed25519.PublicKey, issued licensing.IssuedLicence, issuerID string) {
	t.Helper()
	if _, err := licencefmt.VerifyArtifact(root, issued.LicenceArtifact, "com.example.app", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var artifact licencefmt.Artifact
	if err := json.Unmarshal(issued.LicenceArtifact, &artifact); err != nil {
		t.Fatal(err)
	}
	cert, err := licencefmt.VerifyIssuerCertificate(root, artifact.IssuerCertificate)
	if err != nil || cert.IssuerKeyID != issuerID {
		t.Fatalf("artifact issuer=%q want=%q err=%v", cert.IssuerKeyID, issuerID, err)
	}
}
