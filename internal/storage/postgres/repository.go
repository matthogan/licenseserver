package postgres

import (
	"context"

	"github.com/matthogan/licenceserver/internal/config"
	shared "github.com/matthogan/licenceserver/internal/storage/sqlite"
)

type Repository = shared.Repository

func Open(ctx context.Context, c config.Config) (*Repository, error) {
	return shared.OpenPostgres(ctx, c)
}
