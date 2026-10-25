package sqlite

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/matthogan/licenceserver/internal/config"
)

// OpenPostgres builds the shared SQL repository over pgx's database/sql
// adapter. Domain and transaction behavior remain identical to SQLite while
// placeholder binding, migrations, integrity checks, and audit ordering are
// selected by dialect.
func OpenPostgres(ctx context.Context, c config.Config) (*Repository, error) {
	dsn := c.DatabaseDSN()
	if dsn == "" {
		return nil, errors.New("empty PostgreSQL connection string")
	}
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*connConfig)
	db.SetMaxOpenConns(int(c.Database.Postgres.MaxConnections))
	db.SetMaxIdleConns(int(c.Database.Postgres.MinConnections))
	db.SetConnMaxLifetime(c.Database.Postgres.MaxConnLifetime)
	r := &Repository{db: &database{DB: db, dialect: dialectPostgres}}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err = r.Ping(pingCtx); err != nil {
		db.Close()
		return nil, err
	}
	return r, nil
}
