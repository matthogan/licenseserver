package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

const (
	dialectSQLite   = "sqlite"
	dialectPostgres = "postgres"
)

type database struct {
	*sql.DB
	dialect string
}

type transaction struct {
	*sql.Tx
	dialect string
}

func (d *database) BeginTx(ctx context.Context, opts *sql.TxOptions) (*transaction, error) {
	tx, err := d.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &transaction{Tx: tx, dialect: d.dialect}, nil
}
func (d *database) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, bind(query, d.dialect), args...)
}
func (d *database) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, bind(query, d.dialect), args...)
}
func (d *database) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, bind(query, d.dialect), args...)
}
func (t *transaction) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return t.Tx.ExecContext(ctx, bind(query, t.dialect), args...)
}
func (t *transaction) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return t.Tx.QueryContext(ctx, bind(query, t.dialect), args...)
}
func (t *transaction) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return t.Tx.QueryRowContext(ctx, bind(query, t.dialect), args...)
}

func bind(query, dialect string) string {
	if dialect != dialectPostgres {
		return query
	}
	var out strings.Builder
	out.Grow(len(query) + 16)
	index := 1
	for _, r := range query {
		if r == '?' {
			out.WriteString(fmt.Sprintf("$%d", index))
			index++
		} else {
			out.WriteRune(r)
		}
	}
	bound := out.String()
	bound = strings.ReplaceAll(bound, "MIN(rate_limit_counters.request_count+1, $4)", "LEAST(rate_limit_counters.request_count+1, $4)")
	bound = strings.ReplaceAll(bound, "julianday(expires_at)>julianday($2)", "expires_at>$2")
	return bound
}
