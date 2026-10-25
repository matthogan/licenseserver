// Package failurepoint provides context-scoped, deterministic crash-window
// injection for tests. Production requests have no injector and pay only a
// context lookup; no environment variable or remote input can enable it.
package failurepoint

import (
	"context"
	"fmt"
	"sync"
)

const (
	BeforeDBTransaction = "before_db_transaction"
	DuringDBTransaction = "during_db_transaction"
	AfterDBCommit       = "after_db_commit"
	AfterArchiveUpload  = "after_archive_upload"
)

type contextKey struct{}

type injector struct {
	mu     sync.Mutex
	points map[string]int
}

func With(ctx context.Context, points ...string) context.Context {
	values := make(map[string]int, len(points))
	for _, point := range points {
		values[point]++
	}
	return context.WithValue(ctx, contextKey{}, &injector{points: values})
}

func Check(ctx context.Context, point string) error {
	value, _ := ctx.Value(contextKey{}).(*injector)
	if value == nil {
		return nil
	}
	value.mu.Lock()
	defer value.mu.Unlock()
	if value.points[point] == 0 {
		return nil
	}
	value.points[point]--
	return fmt.Errorf("injected failure at %s", point)
}
