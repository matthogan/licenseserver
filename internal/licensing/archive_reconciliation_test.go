package licensing

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDeepArchiveReconciliationAndSafeRepair(t *testing.T) {
	ctx := context.Background()
	fixture := newFailureFixture(t)
	issued, err := fixture.service.IssueLicence(ctx, fixture.request, "test", "issue")
	if err != nil {
		t.Fatal(err)
	}
	if err = fixture.service.Revoke(ctx, issued.LicenceID, "support", "requested", "test", "revoke"); err != nil {
		t.Fatal(err)
	}
	events, err := fixture.archive.ListEvents(ctx)
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	for _, event := range events {
		if err = removeArchiveEventFile(fixture, event.EventID); err != nil {
			t.Fatal(err)
		}
	}
	report, err := fixture.service.ReconcileArchiveDeep(ctx, false, "test", "report")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.MissingFromArchive) != 1 || len(report.RevocationMismatches) != 1 || report.QueuedRepairs != 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	repaired, err := fixture.service.ReconcileArchiveDeep(ctx, true, "test", "repair")
	if err != nil {
		t.Fatal(err)
	}
	if repaired.QueuedRepairs != 2 {
		t.Fatalf("repair report: %+v", repaired)
	}
	clean, err := fixture.service.ReconcileArchiveDeep(ctx, false, "test", "verify")
	if err != nil || len(clean.MissingFromArchive) != 0 || len(clean.MissingFromDatabase) != 0 || len(clean.HashMismatches) != 0 || len(clean.RevocationMismatches) != 0 {
		t.Fatalf("post-repair report=%+v err=%v", clean, err)
	}

	ghost := events[0]
	ghost.EventID = "evt_ghost"
	ghost.LicenceID = "lic_ghost"
	ghost.EventType = "licence.issued"
	ghost.Revocation = nil
	if err = fixture.archive.PutEvent(ctx, ghost); err != nil {
		t.Fatal(err)
	}
	withGhost, err := fixture.service.ReconcileArchiveDeep(ctx, false, "test", "ghost")
	if err != nil || len(withGhost.MissingFromDatabase) != 1 || withGhost.MissingFromDatabase[0] != "lic_ghost" {
		t.Fatalf("missing-from-database report=%+v err=%v", withGhost, err)
	}
}

func removeArchiveEventFile(fixture *failureFixture, eventID string) error {
	return filepath.Walk(fixture.archiveDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == eventID+".json" {
			return os.Remove(path)
		}
		return nil
	})
}
