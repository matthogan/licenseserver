package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	archivefs "github.com/matthogan/licenceserver/internal/archive/filesystem"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/licensing"
	"github.com/matthogan/licenceserver/internal/retention"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

type RebuildReport struct {
	SourceEvents int `json:"source_events"`
	Products     int `json:"products"`
	Licences     int `json:"licences"`
	Revocations  int `json:"revocations"`
	Suppressions int `json:"suppressions"`
}

func Rebuild(ctx context.Context, archiveDir, output string, root ed25519.PublicKey) (int, error) {
	store, err := archivefs.New(archiveDir)
	if err != nil {
		return 0, err
	}
	report, err := RebuildFromStore(ctx, store, output, root)
	return report.Licences, err
}

func RebuildFromStore(ctx context.Context, store domain.ArchiveStore, output string, root ed25519.PublicKey) (RebuildReport, error) {
	return RebuildFromStoreKeyring(ctx, store, output, licencefmt.NewFixedKeyring(root))
}

func RebuildFromStoreKeyring(ctx context.Context, store domain.ArchiveStore, output string, keyring licencefmt.TrustedKeyring) (RebuildReport, error) {
	var report RebuildReport
	if _, err := os.Stat(output); err == nil {
		return report, fmt.Errorf("refusing to overwrite %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, err
	}
	events, err := store.ListEvents(ctx)
	if err != nil {
		return report, err
	}
	report.SourceEvents = len(events)
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID < events[j].EventID
		}
		return events[i].OccurredAt.Before(events[j].OccurredAt)
	})
	var tombstones []domain.SuppressionTombstone
	licenceSuppressions := map[string]struct{}{}
	for _, event := range events {
		if event.EventType != "data.suppressed" || event.Suppression == nil {
			continue
		}
		tombstones = append(tombstones, *event.Suppression)
		if event.Suppression.SubjectType == "licence" {
			licenceSuppressions[event.Suppression.SubjectDigest] = struct{}{}
		}
	}
	cfg := config.Defaults()
	cfg.Database.DSN = output
	repo, err := sqliterepo.Open(cfg)
	if err != nil {
		return report, err
	}
	ok := false
	defer func() {
		repo.Close()
		if !ok {
			_ = os.Remove(output)
		}
	}()
	if err = repo.Migrate(ctx); err != nil {
		return report, err
	}
	for _, e := range events {
		if e.EventType == "data.suppressed" {
			continue
		}
		if _, suppressed := licenceSuppressions[retention.Digest("licence", e.LicenceID)]; suppressed {
			report.Suppressions++
			continue
		}
		if e.EventType == "licence.revoked" {
			if e.Revocation == nil {
				return report, fmt.Errorf("event %s has no revocation payload", e.EventID)
			}
			auditJSON, _ := json.Marshal(map[string]string{"source_archive_event": e.EventID})
			audit := domain.AuditEvent{EventID: "rebuild_" + e.EventID, OccurredAt: e.OccurredAt, ActorType: "recovery", EventType: "licence.revocation_rebuilt", AggregateType: "licence", AggregateID: e.LicenceID, Event: auditJSON}
			if err = repo.RevokeLicence(ctx, *e.Revocation, audit, nil); err != nil {
				return report, fmt.Errorf("event %s revocation: %w", e.EventID, err)
			}
			report.Revocations++
			continue
		}
		if e.EventType != "licence.issued" {
			return report, fmt.Errorf("event %s has unsupported type %s", e.EventID, e.EventType)
		}
		artifact, err := base64.RawURLEncoding.DecodeString(e.SignedLicenceArtifact)
		if err != nil {
			return report, fmt.Errorf("event %s artifact encoding: %w", e.EventID, err)
		}
		payload, err := licencefmt.VerifyArtifactSignatureKeyring(keyring, artifact, "")
		if err != nil {
			return report, fmt.Errorf("event %s licence verification: %w", e.EventID, err)
		}
		if payload.LicenceID != e.LicenceID || payload.ProductID != e.ProductID {
			return report, fmt.Errorf("event %s metadata does not match signed licence", e.EventID)
		}
		payloadBytes, err := licencefmt.PayloadBytes(artifact)
		if err != nil {
			return report, err
		}
		sum := sha256.Sum256(payloadBytes)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), e.PayloadHash) {
			return report, fmt.Errorf("event %s payload hash mismatch", e.EventID)
		}
		if _, err = repo.GetProduct(ctx, payload.ProductID); errors.Is(err, domain.ErrNotFound) {
			err = repo.CreateProduct(ctx, domain.Product{ProductID: payload.ProductID, DisplayName: payload.ProductID, DefaultTrialSeconds: int64(30 * 24 * time.Hour / time.Second), Active: false, CreatedAt: e.OccurredAt}, domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: e.OccurredAt, ActorType: "system", ActorRef: "recovery", EventType: "product.rebuilt", AggregateType: "product", AggregateID: payload.ProductID, Event: json.RawMessage(`{"result":"success"}`)})
			if err == nil {
				report.Products++
			}
		}
		if err != nil {
			return report, err
		}
		request := licensing.IssueLicenceRequest{ProductID: payload.ProductID, LicenceType: payload.LicenceType, CustomerRef: e.CustomerRef, PurchaseRef: e.PurchaseRef, ExpiresAt: payload.ExpiresAt, MaxMajorVersion: payload.MaxMajorVersion, MaintenanceUntil: payload.MaintenanceUntil, SeatModel: payload.SeatModel, SeatCount: payload.SeatCount, Entitlements: payload.Entitlements, Metadata: payload.Metadata}
		metadata, _ := json.Marshal(request)
		rec := domain.LicenceRecord{LicenceID: payload.LicenceID, ProductID: payload.ProductID, LicenceType: payload.LicenceType, CustomerRef: e.CustomerRef, PurchaseRef: e.PurchaseRef, IssuerKeyID: e.IssuerKeyID, IssuedAt: payload.IssuedAt, NotBefore: payload.NotBefore, ExpiresAt: payload.ExpiresAt, Status: "active", PayloadHash: sum[:], SignedArtifact: artifact, Metadata: metadata, CreatedAt: e.OccurredAt}
		eventJSON, _ := json.Marshal(map[string]string{"source_archive_event": e.EventID})
		audit := domain.AuditEvent{EventID: "rebuild_" + e.EventID, OccurredAt: e.OccurredAt, ActorType: "recovery", EventType: "licence.rebuilt", AggregateType: "licence", AggregateID: e.LicenceID, Event: eventJSON}
		if err = repo.CreateLicence(ctx, rec, nil, audit, nil); err != nil {
			if errors.Is(err, domain.ErrConflict) {
				continue
			}
			return report, err
		}
		report.Licences++
	}
	if len(tombstones) > 0 {
		details, _ := json.Marshal(map[string]any{"result": "success", "source": "immutable_archive", "tombstones": len(tombstones)})
		audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: time.Now().UTC(), ActorType: "recovery", ActorRef: "archive-rebuild", EventType: "data.suppressions_applied", AggregateType: "database", AggregateID: "rebuilt", Event: details}
		if _, err = repo.ApplySuppressionTombstones(ctx, tombstones, time.Now().UTC(), audit); err != nil {
			return report, fmt.Errorf("apply archive suppressions: %w", err)
		}
	}
	if err = repo.VerifyAudit(ctx); err != nil {
		return report, err
	}
	if err = repo.Verify(ctx, true); err != nil {
		return report, err
	}
	ok = true
	return report, nil
}
