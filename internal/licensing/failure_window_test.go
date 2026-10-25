package licensing

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	archivefs "github.com/matthogan/licenceserver/internal/archive/filesystem"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/failurepoint"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/signing"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

type failureFixture struct {
	service    *Service
	repo       *sqliterepo.Repository
	archive    *archivefs.Store
	archiveDir string
	request    IssueLicenceRequest
}

func newFailureFixture(t *testing.T) *failureFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(dir, "failure.db")
	cfg.Archive.Directory = filepath.Join(dir, "archive")
	cfg.Signer.PrivateKeyFile = filepath.Join(dir, "issuer.key")
	cfg.Signer.IssuerCertificateFile = filepath.Join(dir, "issuer.cert")
	_, rootPrivate, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := signing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	certificate, err := licencefmt.CreateIssuerCertificate(rootPrivate, licencefmt.IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer-failure", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"product"}})
	if err != nil {
		t.Fatal(err)
	}
	if err = signing.WriteKey(cfg.Signer.PrivateKeyFile, issuerPrivate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Signer.IssuerCertificateFile, []byte(certificate), 0o600); err != nil {
		t.Fatal(err)
	}
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	localSigner, err := signing.Load(cfg.Signer.PrivateKeyFile, cfg.Signer.IssuerCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := archivefs.New(cfg.Archive.Directory)
	if err != nil {
		t.Fatal(err)
	}
	service := New(repo, archive, signing.NewManager(localSigner), []byte("trial-pepper-long-enough"), []byte("activation-pepper-long-enough"), 24*time.Hour, true)
	if err = service.CreateProduct(ctx, domain.Product{ProductID: "product", DisplayName: "Product", Active: true}, "test", "product-request"); err != nil {
		t.Fatal(err)
	}
	return &failureFixture{service: service, repo: repo, archive: archive, archiveDir: cfg.Archive.Directory, request: IssueLicenceRequest{ProductID: "product", LicenceType: "perpetual", CustomerRef: "customer", PurchaseRef: "purchase", Entitlements: []string{"core"}}}
}

type failOnceArchive struct {
	domain.ArchiveStore
	failed bool
}

func (s *failOnceArchive) PutEvent(ctx context.Context, event domain.ArchiveEvent) error {
	if !s.failed {
		s.failed = true
		return errors.New("injected archive upload failure")
	}
	return s.ArchiveStore.PutEvent(ctx, event)
}

func TestPaidIssuanceCriticalFailureWindows(t *testing.T) {
	tests := []struct {
		name  string
		point string
	}{
		{"before-transaction", failurepoint.BeforeDBTransaction},
		{"during-transaction", failurepoint.DuringDBTransaction},
		{"after-commit", failurepoint.AfterDBCommit},
		{"during-archive-upload", "archive"},
		{"after-archive-upload", failurepoint.AfterArchiveUpload},
		{"after-response", "response"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newFailureFixture(t)
			ctx := context.Background()
			if test.point == "archive" {
				fixture.service.archive = &failOnceArchive{ArchiveStore: fixture.archive}
			}
			firstCtx := ctx
			if test.point != "archive" && test.point != "response" {
				firstCtx = failurepoint.With(ctx, test.point)
			}
			first, firstErr := fixture.service.IssueLicence(firstCtx, fixture.request, "test", "request-first")
			if test.point == "response" {
				if firstErr != nil {
					t.Fatal(firstErr)
				}
			} else if firstErr == nil {
				t.Fatal("injected failure did not interrupt issuance")
			}
			retry, err := fixture.service.IssueLicence(ctx, fixture.request, "test", "request-retry")
			if err != nil {
				t.Fatal(err)
			}
			if test.point == "response" && retry.LicenceID != first.LicenceID {
				t.Fatalf("response retry changed licence: first=%s retry=%s", first.LicenceID, retry.LicenceID)
			}
			third, err := fixture.service.IssueLicence(ctx, fixture.request, "test", "request-third")
			if err != nil || !third.Existing || third.LicenceID != retry.LicenceID {
				t.Fatalf("idempotent retrieval=%+v err=%v", third, err)
			}
			licences, err := fixture.repo.ListPaidLicences(ctx)
			if err != nil || len(licences) != 1 {
				t.Fatalf("licences=%d err=%v", len(licences), err)
			}
			pending, _, err := fixture.repo.ArchiveStatus(ctx)
			if err != nil || pending != 0 {
				t.Fatalf("archive pending=%d err=%v", pending, err)
			}
			events, err := fixture.archive.ListEvents(ctx)
			if err != nil || len(events) != 1 || events[0].LicenceID != retry.LicenceID {
				t.Fatalf("archive events=%+v err=%v", events, err)
			}
		})
	}
}
