package archive

import (
	"context"
	"errors"

	"github.com/matthogan/licenceserver/internal/domain"
)

type Disabled struct{}

func (Disabled) PutEvent(context.Context, domain.ArchiveEvent) error {
	return errors.New("archive is disabled")
}
func (Disabled) ListEvents(context.Context) ([]domain.ArchiveEvent, error) {
	return nil, errors.New("archive is disabled")
}
func (Disabled) Verify(context.Context) error { return errors.New("archive is disabled") }
