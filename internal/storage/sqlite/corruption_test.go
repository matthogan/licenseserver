package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/matthogan/licenceserver/internal/config"
)

func TestCorruptDatabaseFailsClosed(t *testing.T) {
	ctx := context.Background()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(t.TempDir(), "corrupt.db")
	repo, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(cfg.Database.DSN, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteAt([]byte("destroyed-sqlite-header"), 0)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("corrupt database: write=%v close=%v", err, closeErr)
	}
	repo, err = Open(cfg)
	if err != nil {
		return
	}
	defer repo.Close()
	if err = repo.Verify(ctx, true); err == nil {
		t.Fatal("deep verification accepted a corrupt database")
	}
}
