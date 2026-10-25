package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/retention"
)

type Store struct{ root string }

const (
	maxArchiveEventBytes = 1024 * 1024
	maxArchiveEvents     = 1000000
)

func New(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("archive directory is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0o750); err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}

func (s *Store) PutEvent(_ context.Context, e domain.ArchiveEvent) error {
	if e.EventID == "" || strings.ContainsAny(e.EventID, "/\\") {
		return errors.New("invalid archive event ID")
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Join(s.root, "licence-events", e.OccurredAt.UTC().Format("2006"), e.OccurredAt.UTC().Format("01"), e.OccurredAt.UTC().Format("02"))
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, e.EventID+".json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, fs.ErrExist) {
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if bytes.Equal(existing, b) {
			return nil
		}
		return fmt.Errorf("archive event %s already exists with different content", e.EventID)
	}
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func (s *Store) Verify(_ context.Context) error {
	_, err := s.ListEvents(context.Background())
	return err
}

func (s *Store) ListEvents(_ context.Context) ([]domain.ArchiveEvent, error) {
	var events []domain.ArchiveEvent
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}
		if info.Size() > maxArchiveEventBytes {
			return fmt.Errorf("%s: archive event exceeds size limit", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		e, err := decodeEvent(b)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if filepath.Base(path) != e.EventID+".json" {
			return fmt.Errorf("%s: event ID/file name mismatch", path)
		}
		events = append(events, e)
		if len(events) > maxArchiveEvents {
			return errors.New("archive event count exceeds safety limit")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return events, nil
}

func decodeEvent(data []byte) (domain.ArchiveEvent, error) {
	var event domain.ArchiveEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return event, err
	}
	if event.SchemaVersion != 1 || event.EventID == "" {
		return event, errors.New("invalid archive event")
	}
	switch event.EventType {
	case "licence.issued":
		if event.LicenceID == "" || event.ProductID == "" || event.PayloadHash == "" || event.SignedLicenceArtifact == "" || event.IssuerKeyID == "" {
			return event, errors.New("invalid licence-issued archive event")
		}
	case "licence.revoked":
		if event.LicenceID == "" || event.Revocation == nil || event.Revocation.LicenceID != event.LicenceID {
			return event, errors.New("invalid licence-revoked archive event")
		}
	case "data.suppressed":
		if event.LicenceID != "" || event.ProductID != "" || event.CustomerRef != "" || event.PurchaseRef != "" || event.PayloadHash != "" || event.SignedLicenceArtifact != "" || event.IssuerKeyID != "" || event.Revocation != nil || event.Suppression == nil || retention.ValidateTombstone(*event.Suppression) != nil || !event.OccurredAt.Equal(event.Suppression.DeletedAt) {
			return event, errors.New("invalid data-suppressed archive event")
		}
	default:
		return event, errors.New("unsupported archive event type")
	}
	return event, nil
}
