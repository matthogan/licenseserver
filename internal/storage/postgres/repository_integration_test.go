package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/exportdata"
	"github.com/matthogan/licenceserver/internal/config"
	dataexporter "github.com/matthogan/licenceserver/internal/dataexport"
	"github.com/matthogan/licenceserver/internal/domain"
)

func TestRepositoryContract(t *testing.T) {
	dsn := os.Getenv("LICD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LICD_TEST_POSTGRES_DSN is not configured")
	}
	t.Setenv("LICD_TEST_DATABASE_URL", dsn)
	c := config.Defaults()
	c.Database.Driver, c.Database.DSN, c.Database.DSNEnv = "postgres", "", "LICD_TEST_DATABASE_URL"
	c.Database.Postgres.MinConnections = 0
	repo, err := Open(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	ctx := context.Background()
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	audit := func(kind, aggregate, id string) domain.AuditEvent {
		body, _ := json.Marshal(map[string]string{"result": "success"})
		return domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "test", EventType: kind, AggregateType: aggregate, AggregateID: id, Event: body}
	}
	product := domain.Product{ProductID: "postgres-product", DisplayName: "PostgreSQL Product", DefaultTrialSeconds: 3600, Active: true, CreatedAt: now}
	if err = repo.CreateProduct(ctx, product, audit("product.created", "product", product.ProductID)); err != nil {
		t.Fatal(err)
	}
	if loaded, loadErr := repo.GetProduct(ctx, product.ProductID); loadErr != nil || !loaded.Active {
		t.Fatalf("product=%+v err=%v", loaded, loadErr)
	}
	licence := domain.LicenceRecord{LicenceID: "lic-postgres", ProductID: product.ProductID, LicenceType: "perpetual", IssuerKeyID: "issuer", IssuedAt: now, NotBefore: now, Status: "active", PayloadHash: []byte{1}, SignedArtifact: []byte(`{"artifact":true}`), CreatedAt: now}
	outbox := domain.OutboxEvent{EventID: uuid.NewString(), EventType: "licence.issued", Event: json.RawMessage(`{"schema_version":1}`), CreatedAt: now}
	if err = repo.CreateLicence(ctx, licence, nil, audit("licence.issued", "licence", licence.LicenceID), &outbox); err != nil {
		t.Fatal(err)
	}
	code := domain.ActivationCode{ActivationCodeID: "acode-postgres", CodeHash: []byte("hash"), HashVersion: "hmac-sha256-v1", LicenceID: licence.LicenceID, MaxUses: 1, CreatedAt: now}
	if err = repo.CreateActivationCode(ctx, code, audit("activation_code.created", "activation_code", code.ActivationCodeID)); err != nil {
		t.Fatal(err)
	}
	record := domain.ActivationRecord{ActivationID: "act-postgres", InstanceRefHash: []byte("instance"), RequestRefHash: []byte("request"), ActivatedAt: now, LastRetrievedAt: now}
	if _, _, _, err = repo.RedeemActivationCode(ctx, []domain.ActivationCodeHash{{Version: code.HashVersion, Hash: code.CodeHash}}, record, now, audit("activation.redeemed", "activation", record.ActivationID), audit("activation.retried", "activation", record.ActivationID)); err != nil {
		t.Fatal(err)
	}
	if err = repo.Verify(ctx, true); err != nil {
		t.Fatal(err)
	}
	if count, consumeErr := repo.ConsumeRateLimit(ctx, "test:opaque", now.Truncate(time.Minute), now.Add(time.Hour), 2); consumeErr != nil || count != 1 {
		t.Fatalf("rate count=%d err=%v", count, consumeErr)
	}
	var archive bytes.Buffer
	manifest, err := dataexporter.WriteArchive(ctx, repo, exportdata.Filter{LicenceID: licence.LicenceID}, now.Add(time.Hour), &archive)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := dataexporter.ReadArchive(bytes.NewReader(archive.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != exportdata.SchemaVersion || len(bundle.Licences) != 1 || len(bundle.Activations) != 1 || bundle.Licences[0].LicenceID != licence.LicenceID {
		t.Fatalf("manifest=%+v licences=%+v activations=%+v", manifest, bundle.Licences, bundle.Activations)
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"instance", "request", "hash_version", "code_hash"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("PostgreSQL public export disclosed %q", forbidden)
		}
	}
	if err = repo.RevokeActivation(ctx, record.ActivationID, "retention-test", now.Add(time.Minute), audit("activation.revoked", "activation", record.ActivationID)); err != nil {
		t.Fatal(err)
	}
	policy, err := repo.SetRetentionPolicy(ctx, domain.RetentionPolicy{Category: domain.RetentionRevokedActivations, RetainForSeconds: 1, CreatedAt: now.Add(2 * time.Minute), CreatedBy: "postgres-test"}, audit("data.retention_policy_created", "retention_policy", domain.RetentionRevokedActivations))
	if err != nil || policy.Version < 1 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	retentionRequest := domain.RetentionApplyRequest{Reason: "postgres contract", AcknowledgeImmutable: true}
	retentionPlan, err := repo.PlanRetention(ctx, retentionRequest, now.Add(time.Hour))
	if err != nil || !retentionPlan.Executable || retentionPlan.Counts.Activations != 1 {
		t.Fatalf("retention plan=%+v err=%v", retentionPlan, err)
	}
	if _, err = repo.ApplyRetention(ctx, retentionRequest, now.Add(time.Hour), audit("data.retention_applied", "retention", "active")); err != nil {
		t.Fatal(err)
	}
}
