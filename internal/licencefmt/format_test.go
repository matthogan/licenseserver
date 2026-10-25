package licencefmt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

func TestArtifactVerification(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	cert, err := CreateIssuerCertificate(rootPriv, IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer-test", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPub), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"com.example.app"}})
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(24 * time.Hour)
	payload := domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic_test", ProductID: "com.example.app", LicenceType: "trial", IssuedAt: now, NotBefore: now, ExpiresAt: &expires, Entitlements: []string{"*"}}
	envelope, _, err := SignPayload(issuerPriv, "issuer-test", payload)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := MarshalArtifact(envelope, cert)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyArtifact(rootPub, artifact, "com.example.app", now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.LicenceID != payload.LicenceID {
		t.Fatalf("got %q", verified.LicenceID)
	}
	if _, err = VerifyArtifact(rootPub, artifact, "com.example.other", now); !errors.Is(err, ErrWrongProduct) {
		t.Fatalf("expected wrong product, got %v", err)
	}
	if _, err = VerifyArtifact(rootPub, artifact, "com.example.app", expires); !errors.Is(err, ErrExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
	var a Artifact
	if err = json.Unmarshal(artifact, &a); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(a.Envelope, ".")
	parts[2] = parts[2][:len(parts[2])-1] + "A"
	a.Envelope = strings.Join(parts, ".")
	tampered, _ := json.Marshal(a)
	if _, err = VerifyArtifact(rootPub, tampered, "com.example.app", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("expected signature failure, got %v", err)
	}
}

func TestPublishedVector(t *testing.T) {
	b, err := os.ReadFile("../../docs/licence-test-vector-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		RootPublicKey string    `json:"root_public_key"`
		Artifact      Artifact  `json:"licence_artifact"`
		Invalid       string    `json:"invalid_signature_envelope"`
		ValidAt       time.Time `json:"valid_at"`
		ExpiredAt     time.Time `json:"expired_at"`
		WrongProduct  string    `json:"wrong_product"`
	}
	if err = json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	root, err := base64.RawURLEncoding.DecodeString(v.RootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := json.Marshal(v.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyArtifact(ed25519.PublicKey(root), artifact, "com.example.test", v.ValidAt); err != nil {
		t.Fatalf("published valid vector: %v", err)
	}
	bad := v.Artifact
	bad.Envelope = v.Invalid
	rawBad, _ := json.Marshal(bad)
	if _, err = VerifyArtifact(ed25519.PublicKey(root), rawBad, "com.example.test", v.ValidAt); !errors.Is(err, ErrSignature) {
		t.Fatalf("published invalid vector: %v", err)
	}
	if _, err = VerifyArtifact(ed25519.PublicKey(root), artifact, v.WrongProduct, v.ValidAt); !errors.Is(err, ErrWrongProduct) {
		t.Fatalf("wrong product vector: %v", err)
	}
	if _, err = VerifyArtifact(ed25519.PublicKey(root), artifact, "com.example.test", v.ExpiredAt); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry vector: %v", err)
	}
}

func TestPublishedOutsideAuthorityAndSignedStatusVectors(t *testing.T) {
	b, err := os.ReadFile("../../docs/licence-test-vector-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SchemaVersion int    `json:"schema_version"`
		VectorVersion string `json:"vector_version"`
		Outside       struct {
			ExpectedError           string    `json:"expected_error"`
			RootPublicKey           string    `json:"root_public_key"`
			VerifyAt                time.Time `json:"verify_at"`
			LicenceArtifactJSON     string    `json:"licence_artifact_json"`
			LicencePayloadJSON      string    `json:"licence_payload_json"`
			LicencePayloadBase64URL string    `json:"licence_payload_base64url"`
			LicenceSigningInput     string    `json:"licence_signing_input"`
			IssuerPayloadJSON       string    `json:"issuer_certificate_payload_json"`
			IssuerPayloadBase64URL  string    `json:"issuer_certificate_payload_base64url"`
			IssuerSigningInput      string    `json:"issuer_certificate_signing_input"`
		} `json:"outside_authority_case"`
		Status struct {
			RootPublicKey    string                     `json:"root_public_key"`
			PayloadJSON      string                     `json:"payload_json"`
			PayloadBase64URL string                     `json:"payload_base64url"`
			SigningInput     string                     `json:"signing_input"`
			Statement        domain.SignedLicenceStatus `json:"statement"`
			InvalidSignature domain.SignedLicenceStatus `json:"invalid_signature_statement"`
			Cases            []struct {
				Name             string    `json:"name"`
				At               time.Time `json:"at"`
				RequestLicenceID string    `json:"request_licence_id"`
				RequestProductID string    `json:"request_product_id"`
				RequestNonce     string    `json:"request_nonce"`
				Statement        string    `json:"statement"`
				ExpectedStatus   string    `json:"expected_status"`
				ExpectedError    string    `json:"expected_error"`
			} `json:"cases"`
		} `json:"signed_status_vectors"`
	}
	if err = json.Unmarshal(b, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.SchemaVersion != 1 || vector.VectorVersion != "1.1.0" {
		t.Fatalf("unsupported vector version %d/%q", vector.SchemaVersion, vector.VectorVersion)
	}
	outsideRoot, err := base64.RawURLEncoding.DecodeString(vector.Outside.RootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyArtifact(ed25519.PublicKey(outsideRoot), []byte(vector.Outside.LicenceArtifactJSON), "com.example.test", vector.Outside.VerifyAt); !errors.Is(err, ErrIssuerAuthority) {
		t.Fatalf("expected published issuer authority failure, got %v", err)
	}
	if vector.Outside.ExpectedError != "issuer_unauthorized" {
		t.Fatalf("unexpected published authority code %q", vector.Outside.ExpectedError)
	}
	assertVectorInput(t, vector.Outside.LicencePayloadJSON, vector.Outside.LicencePayloadBase64URL, vector.Outside.LicenceSigningInput, "desktop-licence:v1\nissuer-authority-vector-v1\n")
	assertVectorInput(t, vector.Outside.IssuerPayloadJSON, vector.Outside.IssuerPayloadBase64URL, vector.Outside.IssuerSigningInput, "desktop-issuer:v1\n")

	statusRoot, err := base64.RawURLEncoding.DecodeString(vector.Status.RootPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	input, payloadBytes, err := StatusSigningInput(vector.Status.Statement.IssuerKeyID, vector.Status.Statement.Payload)
	if err != nil || input != vector.Status.SigningInput || string(payloadBytes) != vector.Status.PayloadJSON || base64.RawURLEncoding.EncodeToString(payloadBytes) != vector.Status.PayloadBase64URL {
		t.Fatalf("published status signing material mismatch: %v", err)
	}
	if len(vector.Status.Cases) != 5 {
		t.Fatalf("expected five status cases, got %d", len(vector.Status.Cases))
	}
	expectedErrors := map[string]error{
		"expired":           ErrExpired,
		"malformed":         ErrMalformed,
		"invalid_signature": ErrSignature,
	}
	for _, test := range vector.Status.Cases {
		t.Run("published_status_"+test.Name, func(t *testing.T) {
			statement := vector.Status.Statement
			if test.Statement == "invalid_signature" {
				statement = vector.Status.InvalidSignature
			}
			status, verifyErr := VerifyStatus(ed25519.PublicKey(statusRoot), statement, test.RequestLicenceID, test.RequestProductID, test.RequestNonce, test.At, 0)
			if test.ExpectedError == "" {
				if verifyErr != nil || status.Status != test.ExpectedStatus {
					t.Fatalf("expected %q, got %+v / %v", test.ExpectedStatus, status, verifyErr)
				}
				return
			}
			if !errors.Is(verifyErr, expectedErrors[test.ExpectedError]) {
				t.Fatalf("expected %s, got %v", test.ExpectedError, verifyErr)
			}
		})
	}
}

func assertVectorInput(t *testing.T, payloadJSON, payloadBase64URL, signingInput, prefix string) {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(payloadBase64URL)
	if err != nil || string(decoded) != payloadJSON || signingInput != prefix+payloadBase64URL {
		t.Fatalf("published signing material mismatch: %v", err)
	}
}

func TestIssuerOutsideAuthority(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	cert, _ := CreateIssuerCertificate(rootPriv, IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "issuer", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPub), AuthorityNotBefore: now.Add(-2 * time.Hour), AuthorityNotAfter: now.Add(-time.Hour), Products: []string{"*"}})
	p := domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic_test", ProductID: "product", LicenceType: "perpetual", IssuedAt: now, NotBefore: now}
	env, _, _ := SignPayload(issuerPriv, "issuer", p)
	raw, _ := MarshalArtifact(env, cert)
	if _, err := VerifyArtifact(rootPub, raw, "product", now); !errors.Is(err, ErrIssuerAuthority) {
		t.Fatalf("expected issuer authority error, got %v", err)
	}
}

func TestClockAndExpiryMatrix(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	issued := time.Date(2028, 2, 28, 12, 0, 0, 0, time.UTC)
	expires := time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC) // includes leap day
	cert, _ := CreateIssuerCertificate(rootPriv, IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "clock-issuer", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPub), AuthorityNotBefore: issued.Add(-time.Hour), AuthorityNotAfter: expires.Add(time.Hour), Products: []string{"clock-product"}})
	payload := domain.LicencePayload{SchemaVersion: 1, LicenceID: "lic-clock", ProductID: "clock-product", LicenceType: "trial", IssuedAt: issued, NotBefore: issued, ExpiresAt: &expires}
	envelope, _, _ := SignPayload(issuerPriv, "clock-issuer", payload)
	artifact, _ := MarshalArtifact(envelope, cert)
	zones := []string{"UTC", "America/New_York", "Europe/Dublin", "Asia/Tokyo"}
	for _, zone := range zones {
		location, err := time.LoadLocation(zone)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = VerifyArtifact(rootPub, artifact, "clock-product", expires.Add(-time.Nanosecond).In(location)); err != nil {
			t.Fatalf("%s rejected last valid instant: %v", zone, err)
		}
		if _, err = VerifyArtifact(rootPub, artifact, "clock-product", expires.In(location)); !errors.Is(err, ErrExpired) {
			t.Fatalf("%s accepted exact expiry: %v", zone, err)
		}
		if _, err = VerifyArtifact(rootPub, artifact, "clock-product", expires.Add(time.Hour).In(location)); !errors.Is(err, ErrExpired) {
			t.Fatalf("%s accepted forward clock: %v", zone, err)
		}
	}

	// The US spring-forward transition skips from 01:59:59 EST to 03:00 EDT;
	// absolute-time comparison must remain continuous across that missing hour.
	newYork, _ := time.LoadLocation("America/New_York")
	dstExpiry := time.Date(2028, 3, 12, 7, 0, 0, 0, time.UTC)
	payload.ExpiresAt = &dstExpiry
	envelope, _, _ = SignPayload(issuerPriv, "clock-issuer", payload)
	artifact, _ = MarshalArtifact(envelope, cert)
	if _, err := VerifyArtifact(rootPub, artifact, "clock-product", time.Date(2028, 3, 12, 1, 59, 59, 0, newYork)); err != nil {
		t.Fatalf("DST instant before transition rejected: %v", err)
	}
	if _, err := VerifyArtifact(rootPub, artifact, "clock-product", time.Date(2028, 3, 12, 3, 0, 0, 0, newYork)); !errors.Is(err, ErrExpired) {
		t.Fatalf("DST exact boundary accepted: %v", err)
	}
}

func TestSignedStatusClockSkewAndBoundary(t *testing.T) {
	rootPub, rootPriv, _ := ed25519.GenerateKey(rand.Reader)
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	checked := time.Date(2028, 10, 29, 1, 30, 0, 0, time.UTC) // European DST fallback day
	validUntil := checked.Add(5 * time.Minute)
	cert, _ := CreateIssuerCertificate(rootPriv, IssuerCertificatePayload{SchemaVersion: 1, IssuerKeyID: "status-clock", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPub), AuthorityNotBefore: checked.Add(-time.Hour), AuthorityNotAfter: checked.Add(time.Hour), Products: []string{"clock-product"}})
	payload := domain.LicenceStatusPayload{SchemaVersion: 1, LicenceID: "lic-clock", ProductID: "clock-product", Status: "active", CheckedAt: checked, ValidUntil: validUntil, Nonce: "0123456789abcdef"}
	input, _, _ := StatusSigningInput("status-clock", payload)
	statement := domain.SignedLicenceStatus{SchemaVersion: 1, Payload: payload, IssuerKeyID: "status-clock", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPriv, []byte(input))), IssuerCertificate: cert}
	for _, test := range []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{"backward within skew", checked.Add(-30 * time.Second), true},
		{"backward beyond skew", checked.Add(-31 * time.Second), false},
		{"exact issue time", checked, true},
		{"last valid instant", validUntil.Add(-time.Nanosecond), true},
		{"exact validity boundary", validUntil, false},
		{"forward beyond validity", validUntil.Add(time.Hour), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := VerifyStatus(rootPub, statement, "lic-clock", "clock-product", "0123456789abcdef", test.now, 30*time.Second)
			if test.ok && err != nil {
				t.Fatal(err)
			}
			if !test.ok && !errors.Is(err, ErrExpired) {
				t.Fatalf("expected expiry, got %v", err)
			}
		})
	}
}

func FuzzLicenceEnvelopeParserFailsClosed(f *testing.F) {
	rootPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte("not-json"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, artifact []byte) {
		if len(artifact) > 1<<20 {
			t.Skip()
		}
		_, _ = VerifyArtifactSignature(rootPublic, artifact, "")
	})
}
