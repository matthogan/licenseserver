package exportdata

import (
	"encoding/json"
	"testing"
	"time"
)

func TestV1LicenceJSONContract(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	record := Licence{
		SchemaVersion: 1, LicenceID: "lic_1", ProductID: "product", LicenceType: "perpetual",
		IssuerKeyID: "issuer", IssuedAt: at, NotBefore: at, Status: "active",
		PayloadSHA256: "abcd", SignedLicenceArtifact: json.RawMessage(`{"licence":"signed"}`), CreatedAt: at,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"licence_id":"lic_1","product_id":"product","licence_type":"perpetual","issuer_key_id":"issuer","issued_at":"2030-01-02T03:04:05Z","not_before":"2030-01-02T03:04:05Z","status":"active","payload_sha256":"abcd","signed_licence_artifact":{"licence":"signed"},"created_at":"2030-01-02T03:04:05Z"}`
	if string(encoded) != want {
		t.Fatalf("v1 JSON changed\nwant: %s\n got: %s", want, encoded)
	}
}

func TestVersionConstantsArePinned(t *testing.T) {
	if SchemaVersion != 1 || FormatVersion != "1.0.0" || FormatName != "licd-public-data-export" {
		t.Fatalf("unexpected version contract: %d %q %q", SchemaVersion, FormatVersion, FormatName)
	}
}
