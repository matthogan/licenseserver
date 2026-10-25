package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	archivefs "github.com/matthogan/licenceserver/internal/archive/filesystem"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/licensing"
	"github.com/matthogan/licenceserver/internal/retention"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

func TestRebuildFromArchive(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(dir, "source.db")
	cfg.Archive.Directory = filepath.Join(dir, "archive")
	cfg.Signer.PrivateKeyFile = filepath.Join(dir, "issuer.key")
	cfg.Signer.IssuerCertificateFile = filepath.Join(dir, "issuer.cert")
	rootPub, rootPriv, _ := signing.GenerateKey()
	issuerPub, issuerPriv, _ := signing.GenerateKey()
	now := time.Now().UTC()
	cert, err := licencefmt.CreateIssuerCertificate(rootPriv, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer-recovery", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPub), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"*"}})
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
	defer repo.Close()
	local, err := signing.Load(cfg.Signer.PrivateKeyFile, cfg.Signer.IssuerCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	archive, _ := archivefs.New(cfg.Archive.Directory)
	svc := licensing.New(repo, archive, signing.NewManager(local), []byte("long enough recovery pepper"), []byte("distinct recovery activation pepper"), 30*24*time.Hour, true)
	if err = svc.CreateProduct(ctx, domain.Product{ProductID: "com.example.recovery", DisplayName: "Recovery", Active: true}, "test", "req-test"); err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueLicence(ctx, licensing.IssueLicenceRequest{ProductID: "com.example.recovery", LicenceType: "perpetual", CustomerRef: "cust", PurchaseRef: "purchase", Entitlements: []string{"core"}}, "test", "req")
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Revoke(ctx, issued.LicenceID, "support", "rebuild test", "test", "req-revoke"); err != nil {
		t.Fatal(err)
	}
	_, newRootPriv, _ := signing.GenerateKey()
	newIssuerPub, newIssuerPriv, _ := signing.GenerateKey()
	transition, err := licencefmt.CreateRootTransition(rootPriv, newRootPriv, licencefmt.RootTransitionPayload{SchemaVersion: 1, TransitionID: "rebuild-root-transition", Algorithm: "Ed25519", CreatedAt: now.Add(-time.Hour), NotBefore: now.Add(-30 * time.Minute), OverlapUntil: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour), Reason: "archive rebuild test"})
	if err != nil {
		t.Fatal(err)
	}
	keyring, _, err := licencefmt.NewFixedKeyring(rootPub).ApplyRootTransition(transition, now)
	if err != nil {
		t.Fatal(err)
	}
	newCertificate, _ := licencefmt.CreateIssuerCertificate(newRootPriv, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer-recovery-new-root", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(newIssuerPub), AuthorityNotBefore: now.Add(-15 * time.Minute), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"*"}})
	newPayload := domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic-new-root-recovery", ProductID: "com.example.recovery", LicenceType: "perpetual", IssuedAt: now, NotBefore: now, Entitlements: []string{"core"}}
	newEnvelope, payloadBytes, _ := licencefmt.SignPayload(newIssuerPriv, "issuer-recovery-new-root", newPayload)
	newArtifact, _ := licencefmt.MarshalArtifact(newEnvelope, newCertificate)
	payloadHash := sha256.Sum256(payloadBytes)
	if err = archive.PutEvent(ctx, domain.ArchiveEvent{SchemaVersion: 1, EventID: "evt-new-root-recovery", EventType: "licence.issued", OccurredAt: now.Add(time.Second), LicenceID: newPayload.LicenceID, ProductID: newPayload.ProductID, PurchaseRef: "purchase-new-root", PayloadHash: hex.EncodeToString(payloadHash[:]), SignedLicenceArtifact: base64.RawURLEncoding.EncodeToString(newArtifact), IssuerKeyID: "issuer-recovery-new-root"}); err != nil {
		t.Fatal(err)
	}
	rebuilt := filepath.Join(dir, "rebuilt.db")
	report, err := RebuildFromStoreKeyring(ctx, archive, rebuilt, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if report.Licences != 2 {
		t.Fatalf("rebuilt %d licences", report.Licences)
	}
	rebuiltCfg := cfg
	rebuiltCfg.Database.DSN = rebuilt
	rebuiltRepo, err := sqliterepo.Open(rebuiltCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer rebuiltRepo.Close()
	record, err := rebuiltRepo.GetLicence(ctx, issued.LicenceID)
	if err != nil {
		t.Fatal(err)
	}
	if string(record.SignedArtifact) != string(issued.LicenceArtifact) {
		t.Fatal("rebuild did not preserve exact artifact")
	}
	if record.Status != "revoked" {
		t.Fatalf("rebuild did not restore revocation: status=%s", record.Status)
	}
	if _, err = rebuiltRepo.GetLicence(ctx, newPayload.LicenceID); err != nil {
		t.Fatalf("new-root licence was not rebuilt: %v", err)
	}
	tombstone := domain.SuppressionTombstone{SchemaVersion: 1, SubjectType: "licence", SubjectDigest: retention.Digest("licence", issued.LicenceID), DeletedAt: now.Add(2 * time.Second), ReasonCode: "customer_deletion", PolicyVersion: 1}
	if err = archive.PutEvent(ctx, domain.ArchiveEvent{SchemaVersion: 1, EventID: "suppress-rebuild-test", EventType: "data.suppressed", OccurredAt: tombstone.DeletedAt, Suppression: &tombstone}); err != nil {
		t.Fatal(err)
	}
	suppressedDB := filepath.Join(dir, "suppressed-rebuilt.db")
	suppressedReport, err := RebuildFromStoreKeyring(ctx, archive, suppressedDB, keyring)
	if err != nil {
		t.Fatal(err)
	}
	if suppressedReport.Licences != 1 || suppressedReport.Suppressions == 0 {
		t.Fatalf("suppressed rebuild report=%+v", suppressedReport)
	}
	suppressedCfg := cfg
	suppressedCfg.Database.DSN = suppressedDB
	suppressedRepo, err := sqliterepo.Open(suppressedCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer suppressedRepo.Close()
	if _, err = suppressedRepo.GetLicence(ctx, issued.LicenceID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("suppressed licence was resurrected: %v", err)
	}
	if stored, listErr := suppressedRepo.ListSuppressionTombstones(ctx); listErr != nil || len(stored) != 1 || stored[0].SubjectDigest != tombstone.SubjectDigest {
		t.Fatalf("stored suppressions=%+v err=%v", stored, listErr)
	}
}
