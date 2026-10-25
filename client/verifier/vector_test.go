package verifier

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPublishedLicenceVector(t *testing.T) {
	data, err := os.ReadFile("../../docs/licence-test-vector-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SchemaVersion           int             `json:"schema_version"`
		VectorVersion           string          `json:"vector_version"`
		RootPublicKey           string          `json:"root_public_key"`
		Artifact                LicenceArtifact `json:"licence_artifact"`
		Invalid                 string          `json:"invalid_signature_envelope"`
		ValidAt                 time.Time       `json:"valid_at"`
		ExpiredAt               time.Time       `json:"expired_at"`
		WrongProduct            string          `json:"wrong_product"`
		LicencePayloadJSON      string          `json:"licence_payload_json"`
		LicencePayloadBase64URL string          `json:"licence_payload_base64url"`
		LicenceSigningInput     string          `json:"licence_signing_input"`
		IssuerPayloadJSON       string          `json:"issuer_certificate_payload_json"`
		IssuerPayloadBase64URL  string          `json:"issuer_certificate_payload_base64url"`
		IssuerSigningInput      string          `json:"issuer_certificate_signing_input"`
		OutsideAuthority        outsideVector   `json:"outside_authority_case"`
		SignedStatus            statusVector    `json:"signed_status_vectors"`
	}
	if err = json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.SchemaVersion != 1 || vector.VectorVersion != "1.1.0" {
		t.Fatalf("unsupported published vector %d/%q", vector.SchemaVersion, vector.VectorVersion)
	}
	assertPublishedSigningInput(t, vector.LicencePayloadJSON, vector.LicencePayloadBase64URL, vector.LicenceSigningInput, "desktop-licence:v1\nissuer-test-2026\n")
	assertPublishedSigningInput(t, vector.IssuerPayloadJSON, vector.IssuerPayloadBase64URL, vector.IssuerSigningInput, "desktop-issuer:v1\n")
	root, err := ParseRootPublicKey([]byte(vector.RootPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	keyring, _ := NewKeyring(root)
	artifact, _ := json.Marshal(vector.Artifact)
	licence, err := VerifyLicence(keyring, artifact, "com.example.test", vector.ValidAt)
	if err != nil || licence.LicenceID != "trl_test_vector" || !licence.Can("anything") {
		t.Fatalf("valid published vector: licence=%+v err=%v", licence, err)
	}
	certificate, trustedRoot, err := VerifyIssuerCertificate(keyring, vector.Artifact.IssuerCertificate)
	if err != nil || certificate.IssuerKeyID != "issuer-test-2026" || trustedRoot.KeyID != RootKeyID(root) {
		t.Fatalf("issuer vector: certificate=%+v root=%+v err=%v", certificate, trustedRoot, err)
	}

	bad := vector.Artifact
	bad.Envelope = vector.Invalid
	badJSON, _ := json.Marshal(bad)
	assertCode(t, VerifyLicenceError(keyring, badJSON, "com.example.test", vector.ValidAt), CodeInvalidSignature)
	assertCode(t, VerifyLicenceError(keyring, artifact, vector.WrongProduct, vector.ValidAt), CodeWrongProduct)
	assertCode(t, VerifyLicenceError(keyring, artifact, "com.example.test", vector.ExpiredAt), CodeExpired)

	clock := ClockFunc(func() time.Time { return vector.ValidAt })
	instance, err := New(keyring, Options{ProductID: "com.example.test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = instance.VerifyLicence(artifact); err != nil {
		t.Fatalf("injected clock: %v", err)
	}

	outsideRoot, err := ParseRootPublicKey([]byte(vector.OutsideAuthority.RootPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	outsideKeyring, _ := NewKeyring(outsideRoot)
	_, err = VerifyLicence(outsideKeyring, []byte(vector.OutsideAuthority.LicenceArtifactJSON), "com.example.test", vector.OutsideAuthority.VerifyAt)
	assertCode(t, err, CodeIssuerUnauthorized)
	if vector.OutsideAuthority.ExpectedError != string(CodeIssuerUnauthorized) {
		t.Fatalf("outside-authority expectation is %q", vector.OutsideAuthority.ExpectedError)
	}
	assertPublishedSigningInput(t, vector.OutsideAuthority.LicencePayloadJSON, vector.OutsideAuthority.LicencePayloadBase64URL, vector.OutsideAuthority.LicenceSigningInput, "desktop-licence:v1\nissuer-authority-vector-v1\n")
	assertPublishedSigningInput(t, vector.OutsideAuthority.IssuerPayloadJSON, vector.OutsideAuthority.IssuerPayloadBase64URL, vector.OutsideAuthority.IssuerSigningInput, "desktop-issuer:v1\n")
	verifyPublishedStatusCases(t, vector.SignedStatus)
}

type outsideVector struct {
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
}

type statusVector struct {
	RootPublicKey                 string       `json:"root_public_key"`
	PayloadJSON                   string       `json:"payload_json"`
	PayloadBase64URL              string       `json:"payload_base64url"`
	SigningInput                  string       `json:"signing_input"`
	StatementJSON                 string       `json:"statement_json"`
	InvalidSignatureStatementJSON string       `json:"invalid_signature_statement_json"`
	Cases                         []statusCase `json:"cases"`
}

type statusCase struct {
	Name             string    `json:"name"`
	At               time.Time `json:"at"`
	RequestLicenceID string    `json:"request_licence_id"`
	RequestProductID string    `json:"request_product_id"`
	RequestNonce     string    `json:"request_nonce"`
	Statement        string    `json:"statement"`
	ExpectedStatus   string    `json:"expected_status"`
	ExpectedError    string    `json:"expected_error"`
}

func verifyPublishedStatusCases(t *testing.T, vector statusVector) {
	t.Helper()
	assertPublishedSigningInput(t, vector.PayloadJSON, vector.PayloadBase64URL, vector.SigningInput, "desktop-licence-status:v1\nissuer-authority-vector-v1\n")
	root, err := ParseRootPublicKey([]byte(vector.RootPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	keyring, _ := NewKeyring(root)
	expectedCodes := map[string]ErrorCode{
		"expired":           CodeExpired,
		"malformed":         CodeMalformed,
		"invalid_signature": CodeInvalidSignature,
	}
	if len(vector.Cases) != 5 {
		t.Fatalf("expected five signed-status cases, got %d", len(vector.Cases))
	}
	for _, test := range vector.Cases {
		t.Run("signed_status_"+test.Name, func(t *testing.T) {
			raw := vector.StatementJSON
			if test.Statement == "invalid_signature" {
				raw = vector.InvalidSignatureStatementJSON
			}
			status, err := VerifySignedStatus(keyring, []byte(raw), StatusRequest{LicenceID: test.RequestLicenceID, ProductID: test.RequestProductID, Nonce: test.RequestNonce}, test.At, 0)
			if test.ExpectedError == "" {
				if err != nil || status.Status != test.ExpectedStatus {
					t.Fatalf("expected status %q, got %+v / %v", test.ExpectedStatus, status, err)
				}
				return
			}
			assertCode(t, err, expectedCodes[test.ExpectedError])
		})
	}
}

func assertPublishedSigningInput(t *testing.T, payloadJSON, payloadBase64URL, input, prefix string) {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(payloadBase64URL)
	if err != nil || string(decoded) != payloadJSON {
		t.Fatalf("published payload encoding mismatch: %v", err)
	}
	if input != prefix+payloadBase64URL {
		t.Fatalf("published signing input mismatch\nwant: %q\n got: %q", prefix+payloadBase64URL, input)
	}
}

func TestPublishedRootTransitionVector(t *testing.T) {
	vector := loadTransitionVector(t)
	oldRoot, err := ParseRootPublicKey([]byte(vector.OldRootPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, _ := NewKeyring(oldRoot)
	applied, payload, err := ApplyTransition(bootstrap, vector.TransitionArtifact, vector.NotBefore)
	if err != nil || payload.TransitionID == "" {
		t.Fatalf("apply published transition: payload=%+v err=%v", payload, err)
	}
	for _, test := range vector.Cases {
		t.Run(test.Name, func(t *testing.T) {
			switch test.Name {
			case "expired_transition_install":
				_, _, err := ApplyTransition(bootstrap, vector.TransitionArtifact, test.At)
				assertCode(t, err, CodeTransitionExpired)
				return
			case "invalid_transition_signature":
				_, _, err := ApplyTransition(bootstrap, vector.InvalidTransitionArtifact, test.At)
				assertCode(t, err, CodeInvalidSignature)
				return
			}
			keyring := bootstrap
			if test.TransitionApplied {
				keyring = applied
			}
			artifact := []byte(vector.LicenceArtifacts[test.Artifact])
			_, err := VerifyLicence(keyring, artifact, "com.example.rotation", test.At)
			if test.Valid && err != nil {
				t.Fatalf("expected valid: %v", err)
			}
			if !test.Valid {
				assertCode(t, err, CodeUntrustedRoot)
			}
		})
	}
}

func VerifyLicenceError(keyring Keyring, raw []byte, product string, now time.Time) error {
	_, err := VerifyLicence(keyring, raw, product, now)
	return err
}

type transitionVector struct {
	OldRootPublicKey          string            `json:"old_root_public_key"`
	NewRootPublicKey          string            `json:"new_root_public_key"`
	NotBefore                 time.Time         `json:"not_before"`
	OverlapUntil              time.Time         `json:"overlap_until"`
	TransitionArtifact        string            `json:"transition_artifact"`
	InvalidTransitionArtifact string            `json:"invalid_transition_artifact"`
	LicenceArtifacts          map[string]string `json:"licence_artifacts"`
	Cases                     []struct {
		Artifact          string    `json:"artifact"`
		At                time.Time `json:"at"`
		Name              string    `json:"name"`
		TransitionApplied bool      `json:"transition_applied"`
		Valid             bool      `json:"valid"`
	} `json:"cases"`
}

func loadTransitionVector(t *testing.T) transitionVector {
	t.Helper()
	data, err := os.ReadFile("../../docs/root-transition-test-vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector transitionVector
	if err = json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func assertCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if err == nil || CodeOf(err) != code {
		t.Fatalf("expected %s, got %v (%s)", code, err, CodeOf(err))
	}
	var typed *Error
	if !errors.As(err, &typed) {
		t.Fatalf("error is not typed: %T", err)
	}
}

func TestBootstrapEncodings(t *testing.T) {
	raw := make([]byte, ed25519.PublicKeySize)
	for index := range raw {
		raw[index] = byte(index)
	}
	for _, encoded := range [][]byte{
		raw,
		[]byte(base64.RawURLEncoding.EncodeToString(raw)),
		[]byte(base64.URLEncoding.EncodeToString(raw)),
	} {
		parsed, err := ParseRootPublicKey(encoded)
		if err != nil || !parsed.Equal(ed25519.PublicKey(raw)) {
			t.Fatalf("parse encoding: %v", err)
		}
	}
}
