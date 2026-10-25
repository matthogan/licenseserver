package filesystem

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/retention"
)

func TestCorruptArchiveEventFailsVerification(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "licence-events", "2026", "08", "18")
	if err = os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "evt_corrupt.json"), []byte(`{"schema_version":1,"event_id":"different"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = store.Verify(context.Background()); err == nil {
		t.Fatal("archive verification accepted corrupt event")
	}
}

func TestSuppressionArchiveEventRejectsCustomerData(t *testing.T) {
	at := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	tombstone := domain.SuppressionTombstone{SchemaVersion: 1, SubjectType: "licence", SubjectDigest: retention.Digest("licence", "lic-private"), DeletedAt: at, ReasonCode: "manual_deletion"}
	event := domain.ArchiveEvent{SchemaVersion: 1, EventID: "suppress-test", EventType: "data.suppressed", OccurredAt: at, Suppression: &tombstone}
	encoded, _ := json.Marshal(event)
	if _, err := decodeEvent(encoded); err != nil {
		t.Fatal(err)
	}
	event.CustomerRef = "must-not-be-retained"
	encoded, _ = json.Marshal(event)
	if _, err := decodeEvent(encoded); err == nil {
		t.Fatal("suppression event containing customer data was accepted")
	}
}

func FuzzArchiveEventParserFailsClosed(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"event_id":"evt","event_type":"licence.issued","licence_id":"lic","product_id":"product","payload_hash":"hash","signed_licence_artifact":"artifact","issuer_key_id":"issuer"}`))
	f.Add([]byte(`{"schema_version":999}`))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = decodeEvent(data)
	})
}
