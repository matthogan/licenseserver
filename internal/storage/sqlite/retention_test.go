package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/failurepoint"
	"github.com/matthogan/licenceserver/internal/retention"
)

func TestDeletionPlanHoldsExportProofRollbackAndTombstone(t *testing.T) {
	ctx := context.Background()
	repo, licence, now := retentionFixture(t)
	defer repo.Close()
	audit := func(eventType string) domain.AuditEvent {
		return domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "test", EventType: eventType, AggregateType: "data_scope", AggregateID: "redacted", Event: json.RawMessage(`{"result":"success"}`)}
	}
	hold := domain.LegalHold{HoldID: "hold-test", Scope: domain.DataScope{CustomerRef: licence.CustomerRef}, Reason: "litigation", CreatedAt: now, CreatedBy: "test"}
	if err := repo.CreateLegalHold(ctx, hold, audit("data.legal_hold_created")); err != nil {
		t.Fatal(err)
	}
	request := domain.DataDeletionRequest{Scope: domain.DataScope{LicenceID: licence.LicenceID}, Reason: "customer request", RequireExport: true, AcknowledgeImmutable: true}
	plan, err := repo.PlanDataDeletion(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Executable || !hasBlocker(plan, "legal_hold") || !hasBlocker(plan, "verified_export_required") || plan.Counts.Licences != 1 || plan.Counts.Activations != 1 {
		t.Fatalf("unexpected blocked plan: %+v", plan)
	}
	filterJSON := json.RawMessage(`{"licence_id":"lic-retention"}`)
	proof := domain.DataExportProof{SHA256: strings.Repeat("a", 64), CreatedAt: now, FilterJSON: filterJSON, RecordCounts: json.RawMessage(`{"licences":1}`)}
	if err = repo.RecordDataExportProof(ctx, proof, audit("data.exported")); err != nil {
		t.Fatal(err)
	}
	request.ExportSHA256 = proof.SHA256
	if _, err = repo.ReleaseLegalHold(ctx, hold.HoldID, "test", now, audit("data.legal_hold_released")); err != nil {
		t.Fatal(err)
	}
	plan, err = repo.PlanDataDeletion(ctx, request, now)
	if err != nil || !plan.Executable || len(plan.Blockers) != 0 || plan.Counts.Tombstones != 1 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}

	crashContext := failurepoint.With(ctx, failurepoint.DuringDBTransaction)
	if _, err = repo.DeleteData(crashContext, request, now, audit("data.deleted")); err == nil {
		t.Fatal("injected transaction failure was ignored")
	}
	if _, err = repo.GetLicence(ctx, licence.LicenceID); err != nil {
		t.Fatalf("failed transaction deleted licence: %v", err)
	}
	if tombstones, listErr := repo.ListSuppressionTombstones(ctx); listErr != nil || len(tombstones) != 0 {
		t.Fatalf("failed transaction persisted tombstones: %+v err=%v", tombstones, listErr)
	}

	plan, err = repo.DeleteData(ctx, request, now, audit("data.deleted"))
	if err != nil || plan.Counts.Licences != 1 || plan.Counts.Activations != 1 {
		t.Fatalf("delete plan=%+v err=%v", plan, err)
	}
	if _, err = repo.GetLicence(ctx, licence.LicenceID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted licence lookup err=%v", err)
	}
	tombstones, err := repo.ListSuppressionTombstones(ctx)
	if err != nil || len(tombstones) != 1 || tombstones[0].SubjectDigest != retention.Digest("licence", licence.LicenceID) {
		t.Fatalf("tombstones=%+v err=%v", tombstones, err)
	}
	encoded, _ := json.Marshal(tombstones)
	if strings.Contains(string(encoded), licence.LicenceID) || strings.Contains(string(encoded), licence.CustomerRef) {
		t.Fatalf("tombstone retained customer identifiers: %s", encoded)
	}
	pending, err := repo.PendingOutbox(ctx, 100)
	if err != nil || len(pending) != 1 || pending[0].EventType != "data.suppressed" || strings.Contains(string(pending[0].Event), licence.LicenceID) {
		t.Fatalf("suppression outbox=%+v err=%v", pending, err)
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestVersionedRetentionPolicyPlansAndApplies(t *testing.T) {
	ctx := context.Background()
	repo, licence, now := retentionFixture(t)
	defer repo.Close()
	audit := func(kind string) domain.AuditEvent {
		return domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "test", EventType: kind, Event: json.RawMessage(`{"result":"success"}`)}
	}
	first, err := repo.SetRetentionPolicy(ctx, domain.RetentionPolicy{Category: domain.RetentionRevokedLicences, RetainForSeconds: 3600, CreatedAt: now, CreatedBy: "test"}, audit("data.retention_policy_created"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.SetRetentionPolicy(ctx, domain.RetentionPolicy{Category: domain.RetentionRevokedLicences, RetainForSeconds: 1, CreatedAt: now.Add(time.Second), CreatedBy: "test"}, audit("data.retention_policy_created"))
	if err != nil || first.Version != 1 || second.Version != 2 {
		t.Fatalf("versions=%d/%d err=%v", first.Version, second.Version, err)
	}
	policies, err := repo.ListRetentionPolicies(ctx)
	if err != nil || len(policies) != 2 || policies[0].Active || !policies[1].Active || policies[1].Version != 2 {
		t.Fatalf("policies=%+v err=%v", policies, err)
	}
	request := domain.RetentionApplyRequest{Reason: "scheduled retention", AcknowledgeImmutable: true}
	plan, err := repo.PlanRetention(ctx, request, now.Add(2*time.Hour))
	if err != nil || !plan.Executable || plan.Counts.Licences != 1 || plan.PolicyVersions[domain.RetentionRevokedLicences] != 2 {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if _, err = repo.ApplyRetention(ctx, request, now.Add(2*time.Hour), audit("data.retention_applied")); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.GetLicence(ctx, licence.LicenceID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("retention did not delete licence: %v", err)
	}
}

func TestDeletionAfterCommitFailureLeavesAuditableCommittedState(t *testing.T) {
	ctx := context.Background()
	repo, licence, now := retentionFixture(t)
	defer repo.Close()
	request := domain.DataDeletionRequest{Scope: domain.DataScope{LicenceID: licence.LicenceID}, Reason: "post-commit test", AcknowledgeImmutable: true}
	audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "test", EventType: "data.deleted", Event: json.RawMessage(`{"result":"success"}`)}
	if _, err := repo.DeleteData(failurepoint.With(ctx, failurepoint.AfterDBCommit), request, now, audit); err == nil {
		t.Fatal("after-commit failure was not surfaced")
	}
	if _, err := repo.GetLicence(ctx, licence.LicenceID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("committed deletion was not preserved: %v", err)
	}
	if tombstones, err := repo.ListSuppressionTombstones(ctx); err != nil || len(tombstones) != 1 {
		t.Fatalf("committed tombstone missing: %+v err=%v", tombstones, err)
	}
	if err := repo.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
}

func retentionFixture(t *testing.T) (*Repository, domain.LicenceRecord, time.Time) {
	t.Helper()
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = t.TempDir() + "/retention.db"
	repo, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	now := time.Date(2035, 5, 6, 7, 8, 9, 0, time.UTC)
	audit := func(kind, aggregate, id string) domain.AuditEvent {
		return domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now.Add(-2 * time.Hour), ActorType: "test", EventType: kind, AggregateType: aggregate, AggregateID: id, Event: json.RawMessage(`{"result":"success"}`)}
	}
	product := domain.Product{ProductID: "retention-product", DisplayName: "Retention", Active: true, CreatedAt: now.Add(-48 * time.Hour)}
	if err = repo.CreateProduct(ctx, product, audit("product.created", "product", product.ProductID)); err != nil {
		t.Fatal(err)
	}
	licence := domain.LicenceRecord{LicenceID: "lic-retention", ProductID: product.ProductID, LicenceType: "perpetual", CustomerRef: "opaque-customer-retention", IssuerKeyID: "issuer", IssuedAt: now.Add(-48 * time.Hour), NotBefore: now.Add(-48 * time.Hour), Status: "active", PayloadHash: []byte{1}, SignedArtifact: json.RawMessage(`{"signed":true}`), CreatedAt: now.Add(-48 * time.Hour)}
	if err = repo.CreateLicence(ctx, licence, nil, audit("licence.issued", "licence", licence.LicenceID), nil); err != nil {
		t.Fatal(err)
	}
	code := domain.ActivationCode{ActivationCodeID: "acode-retention", CodeHash: []byte("retention-code-hash"), HashVersion: "hmac-sha256-v1", LicenceID: licence.LicenceID, MaxUses: 1, CreatedAt: now.Add(-24 * time.Hour)}
	if err = repo.CreateActivationCode(ctx, code, audit("activation_code.created", "activation_code", code.ActivationCodeID)); err != nil {
		t.Fatal(err)
	}
	activation := domain.ActivationRecord{ActivationID: "act-retention", InstanceRefHash: []byte("instance"), RequestRefHash: []byte("request"), ActivatedAt: now.Add(-23 * time.Hour), LastRetrievedAt: now.Add(-23 * time.Hour)}
	if _, _, _, err = repo.RedeemActivationCode(ctx, []domain.ActivationCodeHash{{Version: code.HashVersion, Hash: code.CodeHash}}, activation, activation.ActivatedAt, audit("activation.redeemed", "activation", activation.ActivationID), audit("activation.retried", "activation", activation.ActivationID)); err != nil {
		t.Fatal(err)
	}
	revocation := domain.Revocation{RevocationID: "rev-retention", LicenceID: licence.LicenceID, ReasonCode: "customer_request", RevokedAt: now.Add(-2 * time.Hour)}
	if err = repo.RevokeLicence(ctx, revocation, audit("licence.revoked", "licence", licence.LicenceID), nil); err != nil {
		t.Fatal(err)
	}
	licence.Status = "revoked"
	return repo, licence, now
}

func hasBlocker(plan domain.DataDeletionPlan, code string) bool {
	for _, blocker := range plan.Blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}
