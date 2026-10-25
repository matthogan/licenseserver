package licencefmt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
)

const (
	licencePrefix    = "LIC1"
	issuerPrefix     = "ISC1"
	licenceContext   = "desktop-licence:v1\n"
	issuerContext    = "desktop-issuer:v1\n"
	statusContext    = "desktop-licence-status:v1\n"
	MaxArtifactBytes = 64 * 1024
)

var (
	ErrMalformed       = errors.New("malformed licence artifact")
	ErrSignature       = errors.New("invalid signature")
	ErrExpired         = errors.New("licence expired")
	ErrWrongProduct    = errors.New("licence is for another product")
	ErrIssuerAuthority = errors.New("issuer was not authorised at issuance time")
)

type IssuerCertificatePayload struct {
	SchemaVersion      int       `json:"schema_version"`
	IssuerKeyID        string    `json:"issuer_key_id"`
	Algorithm          string    `json:"algorithm"`
	PublicKey          string    `json:"public_key"`
	AuthorityNotBefore time.Time `json:"authority_not_before"`
	AuthorityNotAfter  time.Time `json:"authority_not_after"`
	Products           []string  `json:"products"`
}

func StatusSigningInput(keyID string, payload domain.LicenceStatusPayload) (string, []byte, error) {
	if keyID == "" || payload.SchemaVersion != 1 || payload.LicenceID == "" || payload.ProductID == "" || payload.Nonce == "" {
		return "", nil, ErrMalformed
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", nil, err
	}
	return statusContext + keyID + "\n" + base64.RawURLEncoding.EncodeToString(b), b, nil
}

// VerifyStatus authenticates a short-lived status statement and binds it to
// the caller's licence, product, and nonce. The clock skew only permits a
// recently issued response; it never extends ValidUntil.
func VerifyStatus(root ed25519.PublicKey, statement domain.SignedLicenceStatus, licenceID, productID, nonce string, now time.Time, clockSkew time.Duration) (domain.LicenceStatusPayload, error) {
	return verifyStatusWithCertificate(func(certificate string) (IssuerCertificatePayload, error) {
		return VerifyIssuerCertificate(root, certificate)
	}, statement, licenceID, productID, nonce, now, clockSkew)
}

func VerifyStatusKeyring(keyring TrustedKeyring, statement domain.SignedLicenceStatus, licenceID, productID, nonce string, now time.Time, clockSkew time.Duration) (domain.LicenceStatusPayload, error) {
	return verifyStatusWithCertificate(func(certificate string) (IssuerCertificatePayload, error) {
		payload, _, err := VerifyIssuerCertificateKeyring(keyring, certificate)
		return payload, err
	}, statement, licenceID, productID, nonce, now, clockSkew)
}

func verifyStatusWithCertificate(verifyCertificate func(string) (IssuerCertificatePayload, error), statement domain.SignedLicenceStatus, licenceID, productID, nonce string, now time.Time, clockSkew time.Duration) (domain.LicenceStatusPayload, error) {
	p := statement.Payload
	if statement.SchemaVersion != 1 || statement.IssuerKeyID == "" || p.LicenceID != licenceID || p.ProductID != productID || p.Nonce != nonce || p.SchemaVersion != 1 || !p.CheckedAt.Before(p.ValidUntil) || !validStatus(p.Status) || clockSkew < 0 {
		return domain.LicenceStatusPayload{}, ErrMalformed
	}
	cert, err := verifyCertificate(statement.IssuerCertificate)
	if err != nil {
		return domain.LicenceStatusPayload{}, err
	}
	if cert.IssuerKeyID != statement.IssuerKeyID || !allowsProduct(cert.Products, p.ProductID) || p.CheckedAt.Before(cert.AuthorityNotBefore) || p.CheckedAt.After(cert.AuthorityNotAfter) {
		return domain.LicenceStatusPayload{}, ErrIssuerAuthority
	}
	input, _, err := StatusSigningInput(statement.IssuerKeyID, p)
	if err != nil {
		return domain.LicenceStatusPayload{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(statement.Signature)
	pk, keyErr := base64.RawURLEncoding.DecodeString(cert.PublicKey)
	if err != nil || keyErr != nil || !ed25519.Verify(ed25519.PublicKey(pk), []byte(input), sig) {
		return domain.LicenceStatusPayload{}, ErrSignature
	}
	if now.Before(p.CheckedAt.Add(-clockSkew)) || !now.Before(p.ValidUntil) {
		return domain.LicenceStatusPayload{}, ErrExpired
	}
	return p, nil
}

func validStatus(status string) bool {
	return status == "active" || status == "revoked" || status == "expired" || status == "not_yet_valid" || status == "unknown"
}

type Artifact struct {
	SchemaVersion     int    `json:"schema_version"`
	Envelope          string `json:"envelope"`
	IssuerCertificate string `json:"issuer_certificate"`
}

func CreateIssuerCertificate(root ed25519.PrivateKey, p IssuerCertificatePayload) (string, error) {
	if len(root) != ed25519.PrivateKeySize || p.IssuerKeyID == "" || p.Algorithm != "Ed25519" {
		return "", ErrMalformed
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	sig := ed25519.Sign(root, []byte(issuerContext+encoded))
	return issuerPrefix + "." + encoded + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyIssuerCertificate(root ed25519.PublicKey, certificate string) (IssuerCertificatePayload, error) {
	var p IssuerCertificatePayload
	if len(root) != ed25519.PublicKeySize || len(certificate) > MaxArtifactBytes {
		return p, ErrMalformed
	}
	parts := strings.Split(certificate, ".")
	if len(parts) != 3 || parts[0] != issuerPrefix {
		return p, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return p, ErrMalformed
	}
	if !ed25519.Verify(root, []byte(issuerContext+parts[1]), sig) {
		return p, ErrSignature
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return p, ErrMalformed
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, ErrMalformed
	}
	pk, err := base64.RawURLEncoding.DecodeString(p.PublicKey)
	if err != nil || len(pk) != ed25519.PublicKeySize || p.SchemaVersion != 1 || p.Algorithm != "Ed25519" || p.IssuerKeyID == "" || strings.Contains(p.IssuerKeyID, ".") || !p.AuthorityNotBefore.Before(p.AuthorityNotAfter) {
		return p, ErrMalformed
	}
	return p, nil
}

func SignPayload(privateKey ed25519.PrivateKey, keyID string, payload domain.LicencePayload) (string, []byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize || keyID == "" {
		return "", nil, ErrMalformed
	}
	input, encoded, b, err := PayloadSigningInput(keyID, payload)
	if err != nil {
		return "", nil, err
	}
	sig := ed25519.Sign(privateKey, []byte(input))
	return AssembleEnvelope(keyID, encoded, sig), b, nil
}

func PayloadSigningInput(keyID string, payload domain.LicencePayload) (string, string, []byte, error) {
	if keyID == "" {
		return "", "", nil, ErrMalformed
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", "", nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	return licenceContext + keyID + "\n" + encoded, encoded, b, nil
}

func AssembleEnvelope(keyID, encoded string, signature []byte) string {
	return fmt.Sprintf("%s.%s.%s.%s", licencePrefix, keyID, encoded, base64.RawURLEncoding.EncodeToString(signature))
}

func VerifyArtifact(root ed25519.PublicKey, raw []byte, productID string, now time.Time) (domain.LicencePayload, error) {
	return verifyArtifact(func(certificate string) (IssuerCertificatePayload, error) {
		return VerifyIssuerCertificate(root, certificate)
	}, raw, productID, now, true)
}

func VerifyArtifactKeyring(keyring TrustedKeyring, raw []byte, productID string, now time.Time) (domain.LicencePayload, error) {
	return verifyArtifact(func(certificate string) (IssuerCertificatePayload, error) {
		payload, _, err := VerifyIssuerCertificateKeyring(keyring, certificate)
		return payload, err
	}, raw, productID, now, true)
}

// VerifyArtifactSignature authenticates an artifact without enforcing its
// not-before or expiry window. It is intended for inspection and recovery.
func VerifyArtifactSignature(root ed25519.PublicKey, raw []byte, productID string) (domain.LicencePayload, error) {
	return verifyArtifact(func(certificate string) (IssuerCertificatePayload, error) {
		return VerifyIssuerCertificate(root, certificate)
	}, raw, productID, time.Time{}, false)
}

func VerifyArtifactSignatureKeyring(keyring TrustedKeyring, raw []byte, productID string) (domain.LicencePayload, error) {
	return verifyArtifact(func(certificate string) (IssuerCertificatePayload, error) {
		payload, _, err := VerifyIssuerCertificateKeyring(keyring, certificate)
		return payload, err
	}, raw, productID, time.Time{}, false)
}

func verifyArtifact(verifyCertificate func(string) (IssuerCertificatePayload, error), raw []byte, productID string, now time.Time, enforceTime bool) (domain.LicencePayload, error) {
	var empty domain.LicencePayload
	if len(raw) > MaxArtifactBytes {
		return empty, ErrMalformed
	}
	var a Artifact
	if err := json.Unmarshal(raw, &a); err != nil || a.SchemaVersion != 1 {
		return empty, ErrMalformed
	}
	cert, err := verifyCertificate(a.IssuerCertificate)
	if err != nil {
		return empty, err
	}
	parts := strings.Split(a.Envelope, ".")
	if len(parts) != 4 || parts[0] != licencePrefix || parts[1] != cert.IssuerKeyID {
		return empty, ErrMalformed
	}
	pk, _ := base64.RawURLEncoding.DecodeString(cert.PublicKey)
	sig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return empty, ErrMalformed
	}
	if !ed25519.Verify(ed25519.PublicKey(pk), []byte(licenceContext+parts[1]+"\n"+parts[2]), sig) {
		return empty, ErrSignature
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return empty, ErrMalformed
	}
	var p domain.LicencePayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil || p.SchemaVersion != 1 || p.LicenceID == "" || p.ProductID == "" {
		return empty, ErrMalformed
	}
	if p.IssuedAt.Before(cert.AuthorityNotBefore) || p.IssuedAt.After(cert.AuthorityNotAfter) {
		return empty, ErrIssuerAuthority
	}
	if !allowsProduct(cert.Products, p.ProductID) {
		return empty, ErrWrongProduct
	}
	if productID != "" && p.ProductID != productID {
		return empty, ErrWrongProduct
	}
	if enforceTime && now.Before(p.NotBefore) {
		return empty, fmt.Errorf("not valid before %s", p.NotBefore.Format(time.RFC3339))
	}
	if enforceTime && p.ExpiresAt != nil && !now.Before(*p.ExpiresAt) {
		return empty, ErrExpired
	}
	return p, nil
}

func MarshalArtifact(envelope, cert string) ([]byte, error) {
	return json.MarshalIndent(Artifact{SchemaVersion: 1, Envelope: envelope, IssuerCertificate: cert}, "", "  ")
}

// PayloadBytes returns the exact payload bytes from an artifact. Callers must
// verify the artifact first; this helper deliberately performs no trust check.
func PayloadBytes(raw []byte) ([]byte, error) {
	var a Artifact
	if len(raw) > MaxArtifactBytes || json.Unmarshal(raw, &a) != nil {
		return nil, ErrMalformed
	}
	parts := strings.Split(a.Envelope, ".")
	if len(parts) != 4 || parts[0] != licencePrefix {
		return nil, ErrMalformed
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	return b, nil
}

func allowsProduct(products []string, product string) bool {
	for _, p := range products {
		if p == "*" || p == product {
			return true
		}
	}
	return false
}
