package rootkey

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

func TestRootTransitionLifecycleAndRestartValidation(t *testing.T) {
	ctx := context.Background()
	repo := openRepository(t)
	defer repo.Close()
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	created := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	notBefore := created.Add(time.Hour)
	overlapUntil := notBefore.Add(24 * time.Hour)
	artefact, err := licencefmt.CreateRootTransition(oldPrivate, newPrivate, licencefmt.RootTransitionPayload{SchemaVersion: 1, TransitionID: "routine-2031", Algorithm: "Ed25519", CreatedAt: created, NotBefore: notBefore, OverlapUntil: overlapUntil, ExpiresAt: overlapUntil.Add(24 * time.Hour), Reason: "scheduled root custody replacement"})
	if err != nil {
		t.Fatal(err)
	}
	svc := New(repo, nil)
	svc.now = func() time.Time { return created }
	if err = svc.Initialize(ctx, oldPublic); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Activate(ctx, artefact, "operator", "request"); !errors.Is(err, licencefmt.ErrTransitionInactive) {
		t.Fatalf("early activation error=%v", err)
	}
	svc.now = func() time.Time { return notBefore }
	transition, err := svc.Activate(ctx, artefact, "operator", "request")
	if err != nil {
		t.Fatal(err)
	}
	if transition.Status != domain.RootTransitionStatusActive {
		t.Fatalf("status=%s", transition.Status)
	}
	keyring, err := svc.Keyring(ctx)
	if err != nil || len(keyring.Roots) != 2 {
		t.Fatalf("keyring=%+v err=%v", keyring, err)
	}
	if err = New(repo, nil).Initialize(ctx, oldPublic); err != nil {
		t.Fatalf("restart chain validation: %v", err)
	}
	if err = svc.Healthy(ctx, overlapUntil.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("healthy overlap rejected: %v", err)
	}
	if err = svc.Healthy(ctx, overlapUntil); err == nil {
		t.Fatal("overdue active transition did not fail health")
	}
	svc.now = func() time.Time { return overlapUntil }
	transition, err = svc.Retire(ctx, transition.TransitionID, "client rollout verified", false, "operator", "request-2")
	if err != nil {
		t.Fatal(err)
	}
	if transition.Status != domain.RootTransitionStatusRetired {
		t.Fatalf("status=%s", transition.Status)
	}
	if err = svc.Healthy(ctx, overlapUntil); err != nil {
		t.Fatalf("retired transition failed health: %v", err)
	}
	old, _ := repo.GetRootKey(ctx, licencefmt.RootKeyID(oldPublic))
	next, _ := repo.GetRootKey(ctx, licencefmt.RootKeyID(newPublic))
	if old.Status != domain.RootStatusLegacy || next.Status != domain.RootStatusActive {
		t.Fatalf("old=%s new=%s", old.Status, next.Status)
	}
	if err = New(repo, nil).Initialize(ctx, newPublic); err != nil {
		t.Fatalf("restart from successor trust anchor: %v", err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
}

func TestRootTransitionRollbackAndCompromise(t *testing.T) {
	ctx := context.Background()
	repo := openRepository(t)
	defer repo.Close()
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	created := time.Date(2032, 2, 2, 0, 0, 0, 0, time.UTC)
	artefact, _ := licencefmt.CreateRootTransition(oldPrivate, newPrivate, licencefmt.RootTransitionPayload{SchemaVersion: 1, TransitionID: "rollback-2032", Algorithm: "Ed25519", CreatedAt: created, NotBefore: created, OverlapUntil: created.Add(48 * time.Hour), ExpiresAt: created.Add(72 * time.Hour), Reason: "test transition"})
	svc := New(repo, nil)
	svc.now = func() time.Time { return created }
	if err := svc.Initialize(ctx, oldPublic); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Activate(ctx, artefact, "operator", "request"); err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return created.Add(time.Hour) }
	transition, err := svc.Rollback(ctx, "rollback-2032", "new custody failure", true, "operator", "request-2")
	if err != nil {
		t.Fatal(err)
	}
	if transition.Status != domain.RootTransitionStatusRolledBack {
		t.Fatalf("status=%s", transition.Status)
	}
	old, _ := repo.GetRootKey(ctx, licencefmt.RootKeyID(oldPublic))
	next, _ := repo.GetRootKey(ctx, licencefmt.RootKeyID(newPublic))
	if old.Status != domain.RootStatusActive || old.AcceptCertificatesBefore != nil || next.Status != domain.RootStatusCompromised {
		t.Fatalf("old=%+v new=%+v", old, next)
	}
}

func TestOldRootIssuanceStopsAtCutoverAndCompromiseDisablesSigner(t *testing.T) {
	ctx := context.Background()
	repo := openRepository(t)
	defer repo.Close()
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuerPublic, issuerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	created := time.Date(2033, 3, 3, 0, 0, 0, 0, time.UTC)
	overlapUntil := created.Add(24 * time.Hour)
	certificate, _ := licencefmt.CreateIssuerCertificate(oldPrivate, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "old-root-issuer", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic), AuthorityNotBefore: created.Add(-time.Hour), AuthorityNotAfter: overlapUntil.Add(24 * time.Hour), Products: []string{"product"}})
	payload, _ := licencefmt.VerifyIssuerCertificate(oldPublic, certificate)
	manager := signing.NewManager(testSigner{private: issuerPrivate, certificate: certificate, payload: payload})
	svc := New(repo, manager)
	svc.now = func() time.Time { return created }
	if err := svc.Initialize(ctx, oldPublic); err != nil {
		t.Fatal(err)
	}
	artefact, _ := licencefmt.CreateRootTransition(oldPrivate, newPrivate, licencefmt.RootTransitionPayload{SchemaVersion: 1, TransitionID: "cutover-2033", Algorithm: "Ed25519", CreatedAt: created, NotBefore: created, OverlapUntil: overlapUntil, ExpiresAt: overlapUntil.Add(24 * time.Hour), Reason: "cutover enforcement test"})
	if _, err := svc.Activate(ctx, artefact, "operator", "request"); err != nil {
		t.Fatal(err)
	}
	licence := domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic", ProductID: "product", LicenceType: "perpetual", IssuedAt: overlapUntil.Add(-time.Nanosecond), NotBefore: created}
	if _, err := manager.Sign(ctx, licence, overlapUntil.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("old-root issuer rejected before cutover: %v", err)
	}
	licence.IssuedAt = overlapUntil
	if _, err := manager.Sign(ctx, licence, overlapUntil); !errors.Is(err, signing.ErrSignerUnavailable) {
		t.Fatalf("old-root issuer accepted at cutover: %v", err)
	}
	svc.now = func() time.Time { return created.Add(time.Hour) }
	if _, err := svc.Retire(ctx, "cutover-2033", "confirmed old root compromise", true, "operator", "request-2"); err != nil {
		t.Fatal(err)
	}
	if _, active := manager.Current(); active {
		t.Fatal("compromised old-root signer remains active")
	}
}

type testSigner struct {
	private     ed25519.PrivateKey
	certificate string
	payload     licencefmt.IssuerCertificatePayload
}

func (s testSigner) KeyID() string       { return s.payload.IssuerKeyID }
func (s testSigner) Algorithm() string   { return "Ed25519" }
func (s testSigner) Certificate() string { return s.certificate }
func (s testSigner) CertificatePayload() licencefmt.IssuerCertificatePayload {
	return s.payload
}
func (s testSigner) PublicKey() []byte { return s.private.Public().(ed25519.PublicKey) }
func (s testSigner) Sign(_ context.Context, input []byte) ([]byte, error) {
	return ed25519.Sign(s.private, input), nil
}

func openRepository(t *testing.T) *sqliterepo.Repository {
	t.Helper()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(t.TempDir(), "licd.db")
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(context.Background()); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	return repo
}
