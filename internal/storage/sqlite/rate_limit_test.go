package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/config"
	"github.com/matthogan/licenceserver/internal/domain"
)

func TestRateLimitPersistsAndCoordinatesRepositories(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "rate.db")
	r1, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()
	if err = r1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	start := time.Now().UTC().Truncate(time.Minute)
	expires := start.Add(time.Hour)

	for i := 1; i <= 3; i++ {
		repo := r1
		if i%2 == 0 {
			repo = r2
		}
		count, consumeErr := repo.ConsumeRateLimit(ctx, "trial.ip:opaque", start, expires, 100)
		if consumeErr != nil {
			t.Fatal(consumeErr)
		}
		if count != i {
			t.Fatalf("count=%d, want %d", count, i)
		}
	}

	const workers = 20
	counts := make(chan int, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			repo := r1
			if i%2 == 0 {
				repo = r2
			}
			count, consumeErr := repo.ConsumeRateLimit(ctx, "trial.ip:opaque", start, expires, 100)
			if consumeErr != nil {
				errs <- consumeErr
				return
			}
			counts <- count
		}(i)
	}
	wg.Wait()
	close(errs)
	for consumeErr := range errs {
		t.Fatal(consumeErr)
	}
	close(counts)
	seen := map[int]bool{}
	for count := range counts {
		seen[count] = true
	}
	for want := 4; want <= 3+workers; want++ {
		if !seen[want] {
			t.Fatal(fmt.Sprintf("missing atomic counter value %d", want))
		}
	}

	r1.Close()
	r1, err = Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()
	count, err := r1.ConsumeRateLimit(ctx, "trial.ip:opaque", start, expires, 100)
	if err != nil {
		t.Fatal(err)
	}
	if count != 24 {
		t.Fatalf("count after reopen=%d, want 24", count)
	}
}

func TestConcurrentAuditOnlyWritesRemainLinear(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(t.TempDir(), "audit.db")
	r1, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Close()
	if err = r1.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	r2, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Close()
	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			repo := r1
			if i%2 == 0 {
				repo = r2
			}
			payload, _ := json.Marshal(map[string]any{"result": "success", "worker": i})
			errs <- repo.AppendAudit(ctx, domain.AuditEvent{EventID: uuid.NewString(), OccurredAt: time.Now().UTC(), ActorType: "test", EventType: "admin.request", Event: payload})
		}(i)
	}
	wg.Wait()
	close(errs)
	for writeErr := range errs {
		if writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	if err = r1.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = r1.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != workers {
		t.Fatalf("events=%d, want %d", count, workers)
	}
}
