package recovery

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/domain"
)

// ApplyArchiveSuppressions reapplies every digest-only tombstone from the
// independent immutable archive to a restored physical database. This must run
// before a point-in-time restore is promoted for service.
func ApplyArchiveSuppressions(ctx context.Context, repo domain.Repository, store domain.ArchiveStore, actor string, now time.Time) (domain.DeletionCounts, error) {
	events, err := store.ListEvents(ctx)
	if err != nil {
		return domain.DeletionCounts{}, err
	}
	byDigest := map[string]domain.SuppressionTombstone{}
	for _, event := range events {
		if event.EventType == "data.suppressed" && event.Suppression != nil {
			byDigest[event.Suppression.SubjectType+"\x00"+event.Suppression.SubjectDigest] = *event.Suppression
		}
	}
	if len(byDigest) == 0 {
		return domain.DeletionCounts{}, nil
	}
	tombstones := make([]domain.SuppressionTombstone, 0, len(byDigest))
	for _, tombstone := range byDigest {
		tombstones = append(tombstones, tombstone)
	}
	payload, _ := json.Marshal(map[string]any{"result": "success", "source": "immutable_archive", "tombstones": len(tombstones)})
	audit := domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: now, ActorType: "recovery", ActorRef: actor, EventType: "data.suppressions_applied", AggregateType: "database", AggregateID: "restored", Event: payload}
	return repo.ApplySuppressionTombstones(ctx, tombstones, now, audit)
}
