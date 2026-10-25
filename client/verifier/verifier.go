package verifier

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const (
	licencePrefix  = "LIC1"
	issuerPrefix   = "ISC1"
	licenceContext = "desktop-licence:v1\n"
	issuerContext  = "desktop-issuer:v1\n"
	statusContext  = "desktop-licence-status:v1\n"
)

type Options struct {
	// ProductID binds all licence verification performed by this verifier.
	// It must be non-empty; this prevents accidentally accepting a licence for
	// another application.
	ProductID string
	Clock     Clock
	ClockSkew time.Duration
}

// Verifier is immutable and safe for concurrent use. Create a new one from a
// KeyringStore snapshot after applying or reloading a transition.
type Verifier struct {
	keyring   Keyring
	productID string
	clock     Clock
	clockSkew time.Duration
}

func New(keyring Keyring, options Options) (*Verifier, error) {
	if strings.TrimSpace(options.ProductID) == "" || len(options.ProductID) > 256 || options.ClockSkew < 0 || options.ClockSkew > 10*time.Minute {
		return nil, fail(CodeMalformed, "new verifier", "invalid options", nil)
	}
	if err := validateKeyring(keyring, nil); err != nil {
		return nil, err
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	return &Verifier{keyring: cloneKeyring(keyring), productID: options.ProductID, clock: options.Clock, clockSkew: options.ClockSkew}, nil
}

func (v *Verifier) VerifyLicence(artifact []byte) (Licence, error) {
	return VerifyLicence(v.keyring, artifact, v.productID, v.clock.Now())
}

func (v *Verifier) VerifyIssuerCertificate(certificate string) (IssuerCertificate, TrustedRoot, error) {
	return VerifyIssuerCertificate(v.keyring, certificate)
}

func (v *Verifier) VerifySignedStatus(raw []byte, request StatusRequest) (Status, error) {
	return VerifySignedStatus(v.keyring, raw, request, v.clock.Now(), v.clockSkew)
}

func (v *Verifier) VerifyTransition(artifact string) (RootTransition, error) {
	return VerifyTransition(v.keyring, artifact, v.clock.Now())
}

// VerifyLicence authenticates and validates a licence at an explicitly
// supplied instant. Expiry is exclusive: a licence is expired when
// now >= expires_at.
func VerifyLicence(keyring Keyring, raw []byte, productID string, now time.Time) (Licence, error) {
	const operation = "verify licence"
	var artifact LicenceArtifact
	if err := decodeStrict(raw, MaxArtifactBytes, &artifact, operation); err != nil {
		return Licence{}, err
	}
	if artifact.SchemaVersion != 1 || len(artifact.Envelope) > MaxArtifactBytes || len(artifact.IssuerCertificate) > MaxArtifactBytes {
		return Licence{}, fail(CodeMalformed, operation, "invalid artifact envelope", nil)
	}
	certificate, _, err := VerifyIssuerCertificate(keyring, artifact.IssuerCertificate)
	if err != nil {
		return Licence{}, err
	}
	parts := strings.Split(artifact.Envelope, ".")
	if len(parts) != 4 || parts[0] != licencePrefix || parts[1] != certificate.IssuerKeyID || len(parts[2]) > MaxArtifactBytes {
		return Licence{}, fail(CodeMalformed, operation, "invalid LIC1 envelope", nil)
	}
	issuerKey, keyErr := base64.RawURLEncoding.DecodeString(certificate.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[3])
	if keyErr != nil || len(issuerKey) != ed25519.PublicKeySize || signatureErr != nil || len(signature) != ed25519.SignatureSize {
		return Licence{}, fail(CodeMalformed, operation, "invalid key or signature encoding", nil)
	}
	if !ed25519.Verify(ed25519.PublicKey(issuerKey), []byte(licenceContext+parts[1]+"\n"+parts[2]), signature) {
		return Licence{}, fail(CodeInvalidSignature, operation, "LIC1 signature did not verify", nil)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Licence{}, fail(CodeMalformed, operation, "invalid payload encoding", err)
	}
	var licence Licence
	if err = decodeStrict(payloadBytes, MaxArtifactBytes, &licence, operation); err != nil {
		return Licence{}, err
	}
	if err = validateLicence(licence); err != nil {
		return Licence{}, err
	}
	if licence.IssuedAt.Before(certificate.AuthorityNotBefore) || licence.IssuedAt.After(certificate.AuthorityNotAfter) {
		return Licence{}, fail(CodeIssuerUnauthorized, operation, "issuance was outside certificate authority", nil)
	}
	if !allowsProduct(certificate.Products, licence.ProductID) {
		return Licence{}, fail(CodeWrongProduct, operation, "issuer was not authorised for product", nil)
	}
	if productID == "" || licence.ProductID != productID {
		return Licence{}, fail(CodeWrongProduct, operation, "licence product does not match application", nil)
	}
	if now.Before(licence.NotBefore) {
		return Licence{}, fail(CodeNotYetValid, operation, "licence validity has not begun", nil)
	}
	if licence.ExpiresAt != nil && !now.Before(*licence.ExpiresAt) {
		return Licence{}, fail(CodeExpired, operation, "licence has expired", nil)
	}
	return licence, nil
}

// VerifyIssuerCertificate verifies an ISC1 certificate using every eligible
// root and returns the root that established trust.
func VerifyIssuerCertificate(keyring Keyring, certificate string) (IssuerCertificate, TrustedRoot, error) {
	const operation = "verify issuer certificate"
	if len(certificate) == 0 || len(certificate) > MaxArtifactBytes {
		code := CodeMalformed
		if len(certificate) > MaxArtifactBytes {
			code = CodeTooLarge
		}
		return IssuerCertificate{}, TrustedRoot{}, fail(code, operation, "invalid certificate size", nil)
	}
	parts := strings.Split(certificate, ".")
	if len(parts) != 3 || parts[0] != issuerPrefix {
		return IssuerCertificate{}, TrustedRoot{}, fail(CodeMalformed, operation, "invalid ISC1 envelope", nil)
	}
	payloadBytes, payloadErr := base64.RawURLEncoding.DecodeString(parts[1])
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
	if payloadErr != nil || signatureErr != nil || len(signature) != ed25519.SignatureSize {
		return IssuerCertificate{}, TrustedRoot{}, fail(CodeMalformed, operation, "invalid certificate encoding", nil)
	}
	var payload IssuerCertificate
	if err := decodeStrict(payloadBytes, MaxArtifactBytes, &payload, operation); err != nil {
		return IssuerCertificate{}, TrustedRoot{}, err
	}
	if err := validateIssuer(payload); err != nil {
		return IssuerCertificate{}, TrustedRoot{}, err
	}
	for _, root := range keyring.Roots {
		publicKey, valid := usableRootKey(root)
		if !valid {
			continue
		}
		if !ed25519.Verify(publicKey, []byte(issuerContext+parts[1]), signature) {
			continue
		}
		if root.AcceptCertificatesNotBefore != nil && payload.AuthorityNotBefore.Before(*root.AcceptCertificatesNotBefore) {
			return IssuerCertificate{}, TrustedRoot{}, fail(CodeUntrustedRoot, operation, "issuer authority predates root trust", nil)
		}
		if root.AcceptCertificatesBefore != nil && !payload.AuthorityNotBefore.Before(*root.AcceptCertificatesBefore) {
			return IssuerCertificate{}, TrustedRoot{}, fail(CodeUntrustedRoot, operation, "issuer authority begins after root cutover", nil)
		}
		return payload, root, nil
	}
	return IssuerCertificate{}, TrustedRoot{}, fail(CodeUntrustedRoot, operation, "certificate is not linked to a trusted root", nil)
}

// VerifySignedStatus authenticates a strict JSON status statement and binds
// it to the requesting licence, product, and nonce.
func VerifySignedStatus(keyring Keyring, raw []byte, request StatusRequest, now time.Time, clockSkew time.Duration) (Status, error) {
	const operation = "verify signed status"
	var statement SignedStatus
	if err := decodeStrict(raw, MaxStatusBytes, &statement, operation); err != nil {
		return Status{}, err
	}
	p := statement.Payload
	if statement.SchemaVersion != 1 || p.SchemaVersion != 1 || !validText(statement.IssuerKeyID, 128) ||
		!validText(request.LicenceID, 256) || !validText(request.ProductID, 256) || !validText(request.Nonce, 512) ||
		p.LicenceID != request.LicenceID || p.ProductID != request.ProductID || p.Nonce != request.Nonce ||
		!validStatus(p.Status) || p.CheckedAt.IsZero() || !p.CheckedAt.Before(p.ValidUntil) || clockSkew < 0 || clockSkew > 10*time.Minute {
		return Status{}, fail(CodeMalformed, operation, "status binding or validity is invalid", nil)
	}
	certificate, _, err := VerifyIssuerCertificate(keyring, statement.IssuerCertificate)
	if err != nil {
		return Status{}, err
	}
	if certificate.IssuerKeyID != statement.IssuerKeyID || !allowsProduct(certificate.Products, p.ProductID) ||
		p.CheckedAt.Before(certificate.AuthorityNotBefore) || p.CheckedAt.After(certificate.AuthorityNotAfter) {
		return Status{}, fail(CodeIssuerUnauthorized, operation, "status issuer was not authorised", nil)
	}
	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return Status{}, fail(CodeMalformed, operation, "status payload cannot be encoded", err)
	}
	input := statusContext + statement.IssuerKeyID + "\n" + base64.RawURLEncoding.EncodeToString(payloadJSON)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(statement.Signature)
	issuerKey, keyErr := base64.RawURLEncoding.DecodeString(certificate.PublicKey)
	if signatureErr != nil || len(signature) != ed25519.SignatureSize || keyErr != nil || len(issuerKey) != ed25519.PublicKeySize {
		return Status{}, fail(CodeMalformed, operation, "invalid status signature encoding", nil)
	}
	if !ed25519.Verify(ed25519.PublicKey(issuerKey), []byte(input), signature) {
		return Status{}, fail(CodeInvalidSignature, operation, "status signature did not verify", nil)
	}
	if now.Before(p.CheckedAt.Add(-clockSkew)) || !now.Before(p.ValidUntil) {
		return Status{}, fail(CodeExpired, operation, "status statement is outside its validity window", nil)
	}
	return p, nil
}

func validateLicence(licence Licence) error {
	if licence.SchemaVersion != 1 || !validText(licence.LicenceID, 256) || !validText(licence.ProductID, 256) ||
		!validText(licence.LicenceType, 64) || licence.IssuedAt.IsZero() || licence.NotBefore.IsZero() ||
		len(licence.SubjectRef) > 512 || len(licence.SeatModel) > 64 || licence.SeatCount < 0 ||
		len(licence.Entitlements) > MaxEntitlements || len(licence.Metadata) > MaxMetadataEntries {
		return fail(CodeMalformed, "verify licence", "invalid signed licence fields", nil)
	}
	if licence.ExpiresAt != nil && !licence.NotBefore.Before(*licence.ExpiresAt) {
		return fail(CodeMalformed, "verify licence", "invalid licence validity window", nil)
	}
	for _, entitlement := range licence.Entitlements {
		if !validText(entitlement, 256) {
			return fail(CodeMalformed, "verify licence", "invalid entitlement", nil)
		}
	}
	for key, value := range licence.Metadata {
		if !validText(key, 128) || len(value) > 2048 {
			return fail(CodeMalformed, "verify licence", "invalid metadata", nil)
		}
	}
	return nil
}

func validateIssuer(payload IssuerCertificate) error {
	publicKey, err := base64.RawURLEncoding.DecodeString(payload.PublicKey)
	if payload.SchemaVersion != 1 || payload.Algorithm != "Ed25519" || !validText(payload.IssuerKeyID, 128) ||
		strings.Contains(payload.IssuerKeyID, ".") || err != nil || len(publicKey) != ed25519.PublicKeySize ||
		payload.AuthorityNotBefore.IsZero() || !payload.AuthorityNotBefore.Before(payload.AuthorityNotAfter) ||
		len(payload.Products) == 0 || len(payload.Products) > MaxProducts {
		return fail(CodeMalformed, "verify issuer certificate", "invalid certificate payload", nil)
	}
	for _, product := range payload.Products {
		if !validText(product, 256) {
			return fail(CodeMalformed, "verify issuer certificate", "invalid product authority", nil)
		}
	}
	return nil
}

func usableRootKey(root TrustedRoot) (ed25519.PublicKey, bool) {
	if root.Status == RootCompromised || root.Status == RootRetired || root.Algorithm != "Ed25519" {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(root.PublicKey)
	if err != nil || len(decoded) != ed25519.PublicKeySize || root.KeyID != RootKeyID(ed25519.PublicKey(decoded)) {
		return nil, false
	}
	return ed25519.PublicKey(decoded), true
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func validStatus(status string) bool {
	switch status {
	case "active", "revoked", "expired", "not_yet_valid", "unknown":
		return true
	default:
		return false
	}
}

func allowsProduct(products []string, product string) bool {
	for _, allowed := range products {
		if allowed == "*" || allowed == product {
			return true
		}
	}
	return false
}
