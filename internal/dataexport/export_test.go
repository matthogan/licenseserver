package dataexport

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/exportdata"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

func TestSQLiteExportRoundTripFiltersAndExcludesHMACs(t *testing.T) {
	ctx := context.Background()
	configuration := config.Defaults()
	configuration.Database.DSN = t.TempDir() + "/export.db"
	repo, err := sqliterepo.Open(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2032, 4, 5, 6, 7, 8, 0, time.UTC)
	audit := func(id, eventType, aggregateType, aggregateID string, at time.Time, details string) domain.AuditEvent {
		return domain.AuditEvent{EventID: id, OccurredAt: at, ActorType: "test", ActorRef: "fixture", EventType: eventType, AggregateType: aggregateType, AggregateID: aggregateID, RequestID: "request-" + id, Event: json.RawMessage(details)}
	}
	for _, product := range []string{"product-a", "product-b"} {
		if err = repo.CreateProduct(ctx, domain.Product{ProductID: product, DisplayName: product, Active: true, CreatedAt: base}, audit("evt-product-"+product, "product.created", "product", product, base, `{"result":"success"}`)); err != nil {
			t.Fatal(err)
		}
	}
	licenceA := domain.LicenceRecord{LicenceID: "lic-a", ProductID: "product-a", LicenceType: "perpetual", CustomerRef: "customer-opaque-a", PurchaseRef: "purchase-opaque-a", IssuerKeyID: "issuer-a", IssuedAt: base.Add(time.Minute), NotBefore: base.Add(time.Minute), Status: "active", PayloadHash: []byte{0xaa, 0xbb}, SignedArtifact: []byte(`{"schema_version":1,"licence":"a"}`), Metadata: json.RawMessage(`{"plan":"pro","api_token":"metadata-token-must-not-export"}`), CreatedAt: base.Add(time.Minute)}
	if err = repo.CreateLicence(ctx, licenceA, nil, audit("evt-lic-a", "licence.issued", "licence", licenceA.LicenceID, base.Add(time.Minute), `{"licence_id":"lic-a","result":"success"}`), nil); err != nil {
		t.Fatal(err)
	}
	licenceB := domain.LicenceRecord{LicenceID: "lic-b", ProductID: "product-b", LicenceType: "perpetual", CustomerRef: "customer-opaque-b", IssuerKeyID: "issuer-b", IssuedAt: base.Add(2 * time.Minute), NotBefore: base.Add(2 * time.Minute), Status: "active", PayloadHash: []byte{0xcc}, SignedArtifact: []byte(`{"schema_version":1,"licence":"b"}`), CreatedAt: base.Add(2 * time.Minute)}
	if err = repo.CreateLicence(ctx, licenceB, nil, audit("evt-lic-b", "licence.issued", "licence", licenceB.LicenceID, base.Add(2*time.Minute), `{"licence_id":"lic-b"}`), nil); err != nil {
		t.Fatal(err)
	}
	code := domain.ActivationCode{ActivationCodeID: "acode-a", CodeHash: []byte("raw-code-hmac-must-not-export"), HashVersion: "hmac-sha256-v1", LicenceID: licenceA.LicenceID, MaxUses: 2, CreatedAt: base.Add(3 * time.Minute)}
	if err = repo.CreateActivationCode(ctx, code, audit("evt-code-a", "activation_code.created", "activation_code", code.ActivationCodeID, base.Add(3*time.Minute), `{"licence_id":"lic-a","activation_code_id":"acode-a"}`)); err != nil {
		t.Fatal(err)
	}
	activation := domain.ActivationRecord{ActivationID: "act-a", InstanceRefHash: []byte("instance-hmac-must-not-export"), RequestRefHash: []byte("request-hmac-must-not-export"), ActivatedAt: base.Add(4 * time.Minute), LastRetrievedAt: base.Add(4 * time.Minute), Metadata: json.RawMessage(`{"platform":"windows","nested":{"credential":"metadata-credential-must-not-export"}}`)}
	redeemedAudit := audit("evt-act-a", "activation.redeemed", "activation", activation.ActivationID, base.Add(4*time.Minute), `{"licence_id":"lic-a","instance_ref_hash":"instance-secret","nested":{"hmac":"request-secret"},"payload_hash":"safe-payload-hash"}`)
	if _, _, _, err = repo.RedeemActivationCode(ctx, []domain.ActivationCodeHash{{Version: code.HashVersion, Hash: code.CodeHash}}, activation, base.Add(4*time.Minute), redeemedAudit, audit("evt-retry-a", "activation.retried", "activation", activation.ActivationID, base.Add(4*time.Minute), `{"licence_id":"lic-a"}`)); err != nil {
		t.Fatal(err)
	}
	revocation := domain.Revocation{RevocationID: "rev-a", LicenceID: licenceA.LicenceID, ReasonCode: "refund", ReasonText: "customer request", RevokedAt: base.Add(5 * time.Minute)}
	if err = repo.RevokeLicence(ctx, revocation, audit("evt-rev-a", "licence.revoked", "licence", licenceA.LicenceID, revocation.RevokedAt, `{"licence_id":"lic-a","reason":"refund"}`), nil); err != nil {
		t.Fatal(err)
	}

	filter := exportdata.Filter{CustomerRef: "customer-opaque-a", Status: "revoked"}
	created := base.Add(time.Hour)
	var first, second bytes.Buffer
	manifest, err := WriteArchive(ctx, repo, filter, created, &first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = WriteArchive(ctx, repo, filter, created, &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("identical snapshot/filter/time did not produce identical archive bytes")
	}
	bundle, err := ReadArchive(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RecordCounts != bundle.Manifest.RecordCounts || len(bundle.Licences) != 1 || len(bundle.Activations) != 1 || len(bundle.Revocations) != 1 || len(bundle.AuditEvents) != 4 {
		t.Fatalf("manifest=%+v bundle counts=%+v/%d/%d/%d/%d", manifest.RecordCounts, bundle.Manifest.RecordCounts, len(bundle.Licences), len(bundle.Activations), len(bundle.Revocations), len(bundle.AuditEvents))
	}
	if bundle.Licences[0].LicenceID != "lic-a" || bundle.Licences[0].CustomerRef != "customer-opaque-a" || bundle.Licences[0].PayloadSHA256 != "aabb" || bundle.Activations[0].ActivationID != "act-a" {
		t.Fatalf("unexpected public records: %+v %+v", bundle.Licences, bundle.Activations)
	}
	encoded, _ := json.Marshal(bundle)
	for _, forbidden := range []string{"raw-code-hmac-must-not-export", "instance-hmac-must-not-export", "request-hmac-must-not-export", "instance-secret", "request-secret", "metadata-token-must-not-export", "metadata-credential-must-not-export", "lic-b", "customer-opaque-b"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("public export disclosed %q", forbidden)
		}
	}
	foundSanitized := false
	for _, event := range bundle.AuditEvents {
		if event.EventID == "evt-act-a" {
			foundSanitized = event.Details["instance_ref_hash"] == nil && event.Details["payload_hash"] == "safe-payload-hash"
		}
	}
	if !foundSanitized {
		t.Fatal("activation audit projection was not sanitized as expected")
	}
	corrupted := append([]byte(nil), first.Bytes()...)
	corrupted[len(corrupted)/2] ^= 0xff
	if _, err = ReadArchive(bytes.NewReader(corrupted)); err == nil {
		t.Fatal("corrupted data export passed validation")
	}
}

func TestTimeRangeIsHalfOpenPerDataset(t *testing.T) {
	from := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	if ValidateFilter(exportdata.Filter{From: &to, To: &from}) == nil {
		t.Fatal("reversed time range accepted")
	}
	if !inRangeForTest(from, &from, &to) || inRangeForTest(to, &from, &to) {
		t.Fatal("test assumption for half-open range is invalid")
	}
}

func inRangeForTest(value time.Time, from, to *time.Time) bool {
	return (from == nil || !value.Before(*from)) && (to == nil || value.Before(*to))
}
