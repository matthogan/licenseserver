package secretvalue

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEnvironmentOrProtectedFile(t *testing.T) {
	name := "LICD_TEST_SECRET_VALUE"
	t.Setenv(name, "direct-secret")
	if value, err := String(name); err != nil || value != "direct-secret" {
		t.Fatalf("direct value=%q err=%v", value, err)
	}
	os.Unsetenv(name)
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name+"_FILE", file)
	if value, err := String(name); err != nil || value != "file-secret" {
		t.Fatalf("file value=%q err=%v", value, err)
	}
	t.Setenv(name, "ambiguous")
	if _, err := Read(name); err == nil {
		t.Fatal("accepted simultaneous direct and file secret")
	}
}
