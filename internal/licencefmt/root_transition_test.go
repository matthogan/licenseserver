package licencefmt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

func TestRootTransitionAndKeyringVerification(t *testing.T) {
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuerOldPublic, issuerOldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuerNewPublic, issuerNewPrivate, _ := ed25519.GenerateKey(rand.Reader)
	created := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	notBefore := created.Add(time.Hour)
	overlapUntil := notBefore.Add(30 * 24 * time.Hour)
	expires := overlapUntil.Add(7 * 24 * time.Hour)
	artifact, err := CreateRootTransition(oldPrivate, newPrivate, RootTransitionPayload{SchemaVersion: 1, TransitionID: "root-2030", Algorithm: "Ed25519", CreatedAt: created, NotBefore: notBefore, OverlapUntil: overlapUntil, ExpiresAt: expires, Reason: "scheduled custody replacement"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyRootTransition(oldPublic, artifact, created); !errors.Is(err, ErrTransitionInactive) {
		t.Fatalf("expected inactive, got %v", err)
	}
	if _, err = VerifyRootTransition(oldPublic, artifact, expires); !errors.Is(err, ErrTransitionExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
	keyring, payload, err := NewFixedKeyring(oldPublic).ApplyRootTransition(artifact, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	if payload.NewRootKeyID != RootKeyID(newPublic) || len(keyring.Roots) != 2 {
		t.Fatalf("unexpected keyring: %+v", keyring)
	}

	oldCert := mustCertificate(t, oldPrivate, issuerOldPublic, "old-issuer", notBefore.Add(-24*time.Hour), overlapUntil.Add(24*time.Hour))
	newCert := mustCertificate(t, newPrivate, issuerNewPublic, "new-issuer", notBefore, overlapUntil.Add(365*24*time.Hour))
	oldLicence := mustArtifact(t, issuerOldPrivate, oldCert, "old-issuer", notBefore.Add(2*time.Hour))
	newLicence := mustArtifact(t, issuerNewPrivate, newCert, "new-issuer", overlapUntil.Add(time.Hour))
	if _, err = VerifyArtifactKeyring(keyring, oldLicence, "product", overlapUntil.Add(time.Hour)); err != nil {
		t.Fatalf("historical old-root licence rejected: %v", err)
	}
	if _, err = VerifyArtifactKeyring(keyring, newLicence, "product", overlapUntil.Add(2*time.Hour)); err != nil {
		t.Fatalf("new-root licence rejected: %v", err)
	}
	statusPayload := domain.LicenceStatusPayload{SchemaVersion: 1, LicenceID: "lic-new-issuer", ProductID: "product", Status: "active", CheckedAt: overlapUntil.Add(time.Hour), ValidUntil: overlapUntil.Add(2 * time.Hour), Nonce: "0123456789abcdef"}
	statusInput, _, _ := StatusSigningInput("new-issuer", statusPayload)
	status := domain.SignedLicenceStatus{SchemaVersion: 1, Payload: statusPayload, IssuerKeyID: "new-issuer", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerNewPrivate, []byte(statusInput))), IssuerCertificate: newCert}
	if _, err = VerifyStatusKeyring(keyring, status, statusPayload.LicenceID, "product", statusPayload.Nonce, statusPayload.CheckedAt, time.Minute); err != nil {
		t.Fatalf("new-root signed status rejected: %v", err)
	}
	lateOldCert := mustCertificate(t, oldPrivate, issuerOldPublic, "late-old", overlapUntil, overlapUntil.Add(24*time.Hour))
	lateOldLicence := mustArtifact(t, issuerOldPrivate, lateOldCert, "late-old", overlapUntil.Add(time.Hour))
	if _, err = VerifyArtifactKeyring(keyring, lateOldLicence, "product", overlapUntil.Add(2*time.Hour)); !errors.Is(err, ErrUntrustedRoot) {
		t.Fatalf("late old-root certificate accepted: %v", err)
	}

	parts := strings.Split(artifact, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if _, err = VerifyRootTransition(oldPublic, strings.Join(parts, "."), notBefore); !errors.Is(err, ErrSignature) {
		t.Fatalf("invalid transition accepted: %v", err)
	}
}

func FuzzRootTransitionParserFailsClosed(f *testing.F) {
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	created := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	artifact, _ := CreateRootTransition(oldPrivate, newPrivate, RootTransitionPayload{SchemaVersion: 1, TransitionID: "fuzz-seed", Algorithm: "Ed25519", CreatedAt: created, NotBefore: created, OverlapUntil: created.Add(time.Hour), ExpiresAt: created.Add(2 * time.Hour), Reason: "fuzz seed"})
	f.Add([]byte(artifact))
	f.Add([]byte("RKT1.invalid.invalid.invalid"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxArtifactBytes+1 {
			t.Skip()
		}
		_, _ = InspectRootTransition(string(raw))
		_, _ = VerifyRootTransition(oldPublic, string(raw), created)
	})
}

func mustCertificate(t *testing.T, root ed25519.PrivateKey, issuer ed25519.PublicKey, id string, start, end time.Time) string {
	t.Helper()
	cert, err := CreateIssuerCertificate(root, IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: id, Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuer), AuthorityNotBefore: start, AuthorityNotAfter: end, Products: []string{"product"}})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustArtifact(t *testing.T, issuer ed25519.PrivateKey, cert, id string, issued time.Time) []byte {
	t.Helper()
	envelope, _, err := SignPayload(issuer, id, domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic-" + id, ProductID: "product", LicenceType: "perpetual", IssuedAt: issued, NotBefore: issued})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := MarshalArtifact(envelope, cert)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}
