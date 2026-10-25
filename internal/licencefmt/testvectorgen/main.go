// Command testvectorgen deterministically extends the published LIC1 vector.
// Every generated private key is derived from a public test-only label and
// must never be used outside interoperability tests.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
)

func main() {
	output := flag.String("output", "docs/licence-test-vector-v1.json", "existing vector file to extend deterministically")
	flag.Parse()
	if err := generate(*output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var vector map[string]any
	if err = json.Unmarshal(raw, &vector); err != nil {
		return err
	}
	vector["schema_version"] = 1
	vector["vector_version"] = "1.1.0"
	vector["description"] = "Deterministic Ed25519 LIC1/ISC1/status interoperability vectors; every key is test-only."
	vector["encoding"] = map[string]any{
		"base64url":            "RFC 4648 URL alphabet, no padding",
		"json":                 "UTF-8 compact JSON; preserve the published bytes exactly when reproducing signatures",
		"timestamp":            "RFC 3339 UTC",
		"signature_algorithm":  "Ed25519",
		"licence_domain":       "desktop-licence:v1\\n",
		"issuer_domain":        "desktop-issuer:v1\\n",
		"signed_status_domain": "desktop-licence-status:v1\\n",
	}

	licenceEnvelope, _ := vector["licence_envelope"].(string)
	issuerCertificate, _ := vector["issuer_certificate"].(string)
	licenceParts := strings.Split(licenceEnvelope, ".")
	issuerParts := strings.Split(issuerCertificate, ".")
	if len(licenceParts) != 4 || len(issuerParts) != 3 {
		return fmt.Errorf("existing vector contains malformed envelopes")
	}
	licencePayload, err := base64.RawURLEncoding.DecodeString(licenceParts[2])
	if err != nil {
		return err
	}
	issuerPayload, err := base64.RawURLEncoding.DecodeString(issuerParts[1])
	if err != nil {
		return err
	}
	vector["licence_payload_json"] = string(licencePayload)
	vector["licence_signature_base64url"] = licenceParts[3]
	vector["licence_signing_input"] = "desktop-licence:v1\n" + licenceParts[1] + "\n" + licenceParts[2]
	vector["issuer_certificate_payload_json"] = string(issuerPayload)
	vector["issuer_certificate_payload_base64url"] = issuerParts[1]
	vector["issuer_certificate_signature_base64url"] = issuerParts[2]
	vector["issuer_certificate_signing_input"] = "desktop-issuer:v1\n" + issuerParts[1]

	rootPrivate := deterministicPrivate("authority-root")
	issuerPrivate := deterministicPrivate("authority-issuer")
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	issuerPublic := issuerPrivate.Public().(ed25519.PublicKey)
	authorityStart := mustTime("2026-08-14T12:00:00Z")
	authorityEnd := mustTime("2027-08-15T12:00:00Z")
	certificatePayload := licencefmt.IssuerCertificatePayload{
		SchemaVersion:      1,
		IssuerKeyID:        "issuer-authority-vector-v1",
		Algorithm:          "Ed25519",
		PublicKey:          base64.RawURLEncoding.EncodeToString(issuerPublic),
		AuthorityNotBefore: authorityStart,
		AuthorityNotAfter:  authorityEnd,
		Products:           []string{"com.example.test"},
	}
	certificate, err := licencefmt.CreateIssuerCertificate(rootPrivate, certificatePayload)
	if err != nil {
		return err
	}
	certificateParts := strings.Split(certificate, ".")
	certificatePayloadJSON, _ := base64.RawURLEncoding.DecodeString(certificateParts[1])
	sharedIssuer := map[string]any{
		"root_public_key":                        base64.RawURLEncoding.EncodeToString(rootPublic),
		"issuer_public_key":                      base64.RawURLEncoding.EncodeToString(issuerPublic),
		"issuer_certificate":                     certificate,
		"issuer_certificate_payload_json":        string(certificatePayloadJSON),
		"issuer_certificate_payload_base64url":   certificateParts[1],
		"issuer_certificate_signature_base64url": certificateParts[2],
		"issuer_certificate_signing_input":       "desktop-issuer:v1\n" + certificateParts[1],
	}

	outsideIssuedAt := mustTime("2027-08-16T12:00:00Z")
	outsidePayload := domain.LicencePayload{
		SchemaVersion: 1,
		LicenceID:     "lic_outside_authority_vector",
		ProductID:     "com.example.test",
		LicenceType:   "perpetual",
		IssuedAt:      outsideIssuedAt,
		NotBefore:     outsideIssuedAt,
	}
	outsideEnvelope, outsidePayloadJSON, err := licencefmt.SignPayload(issuerPrivate, certificatePayload.IssuerKeyID, outsidePayload)
	if err != nil {
		return err
	}
	outsideArtifactJSON, err := licencefmt.MarshalArtifact(outsideEnvelope, certificate)
	if err != nil {
		return err
	}
	outsideParts := strings.Split(outsideEnvelope, ".")
	outside := cloneMap(sharedIssuer)
	outside["name"] = "issued_after_issuer_authority"
	outside["expected_error"] = "issuer_unauthorized"
	outside["verify_at"] = outsideIssuedAt.Format(time.RFC3339)
	outside["licence_artifact_json"] = string(outsideArtifactJSON)
	outside["licence_artifact"] = decodeObject(outsideArtifactJSON)
	outside["licence_payload_json"] = string(outsidePayloadJSON)
	outside["licence_payload_base64url"] = outsideParts[2]
	outside["licence_signature_base64url"] = outsideParts[3]
	outside["licence_signing_input"] = "desktop-licence:v1\n" + outsideParts[1] + "\n" + outsideParts[2]
	vector["outside_authority_case"] = outside

	checkedAt := mustTime("2026-08-16T12:00:00Z")
	validUntil := checkedAt.Add(5 * time.Minute)
	statusPayload := domain.LicenceStatusPayload{
		SchemaVersion: 1,
		LicenceID:     "lic_status_vector",
		ProductID:     "com.example.test",
		Status:        "active",
		CheckedAt:     checkedAt,
		ValidUntil:    validUntil,
		Nonce:         "0123456789abcdef0123456789abcdef",
	}
	statusInput, statusPayloadJSON, err := licencefmt.StatusSigningInput(certificatePayload.IssuerKeyID, statusPayload)
	if err != nil {
		return err
	}
	statusSignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, []byte(statusInput)))
	statement := domain.SignedLicenceStatus{
		SchemaVersion:     1,
		Payload:           statusPayload,
		IssuerKeyID:       certificatePayload.IssuerKeyID,
		Signature:         statusSignature,
		IssuerCertificate: certificate,
	}
	statementJSON, _ := json.Marshal(statement)
	invalidStatement := statement
	invalidStatement.Signature = corrupt(statusSignature)
	invalidStatementJSON, _ := json.Marshal(invalidStatement)
	status := cloneMap(sharedIssuer)
	status["request"] = domain.LicenceStatusRequest{LicenceID: statusPayload.LicenceID, ProductID: statusPayload.ProductID, Nonce: statusPayload.Nonce}
	status["payload_json"] = string(statusPayloadJSON)
	status["payload_base64url"] = base64.RawURLEncoding.EncodeToString(statusPayloadJSON)
	status["signature_base64url"] = statusSignature
	status["signing_input"] = statusInput
	status["statement"] = statement
	status["statement_json"] = string(statementJSON)
	status["invalid_signature_statement"] = invalidStatement
	status["invalid_signature_statement_json"] = string(invalidStatementJSON)
	status["cases"] = []map[string]any{
		{"name": "valid", "at": checkedAt.Format(time.RFC3339), "request_licence_id": statusPayload.LicenceID, "request_product_id": statusPayload.ProductID, "request_nonce": statusPayload.Nonce, "statement": "valid", "expected_status": "active"},
		{"name": "expired", "at": validUntil.Format(time.RFC3339), "request_licence_id": statusPayload.LicenceID, "request_product_id": statusPayload.ProductID, "request_nonce": statusPayload.Nonce, "statement": "valid", "expected_error": "expired"},
		{"name": "wrong_nonce", "at": checkedAt.Format(time.RFC3339), "request_licence_id": statusPayload.LicenceID, "request_product_id": statusPayload.ProductID, "request_nonce": "fedcba9876543210fedcba9876543210", "statement": "valid", "expected_error": "malformed"},
		{"name": "wrong_product", "at": checkedAt.Format(time.RFC3339), "request_licence_id": statusPayload.LicenceID, "request_product_id": "com.example.other", "request_nonce": statusPayload.Nonce, "statement": "valid", "expected_error": "malformed"},
		{"name": "invalid_signature", "at": checkedAt.Format(time.RFC3339), "request_licence_id": statusPayload.LicenceID, "request_product_id": statusPayload.ProductID, "request_nonce": statusPayload.Nonce, "statement": "invalid_signature", "expected_error": "invalid_signature"},
	}
	vector["signed_status_vectors"] = status

	encoded, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o644)
}

func deterministicPrivate(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("licenceserver:licence-test-vector:v1:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func decodeObject(data []byte) map[string]any {
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		panic(err)
	}
	return object
}

func cloneMap(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func corrupt(signature string) string {
	if strings.HasSuffix(signature, "A") {
		return signature[:len(signature)-1] + "B"
	}
	return signature[:len(signature)-1] + "A"
}
