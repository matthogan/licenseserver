package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotatingWriterBoundsBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "licd.log")
	w, err := NewRotatingWriter(path, 1024, 2, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err = w.Write(bytes.Repeat([]byte{'x'}, 700)); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "licd.log.") {
			backups++
		}
	}
	if backups != 2 {
		t.Fatalf("backups=%d, want 2", backups)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 1024 {
		t.Fatalf("active log size=%d", info.Size())
	}
}
