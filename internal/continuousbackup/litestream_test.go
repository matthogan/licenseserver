package continuousbackup

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/matthogan/licenceserver/internal/config"
	sqliterepo "github.com/matthogan/licenceserver/internal/storage/sqlite"
	"go.yaml.in/yaml/v3"
)

func TestRenderConfigEnforcesSSEKMSWithoutEmbeddingCredentials(t *testing.T) {
	c := config.Defaults()
	c.Backup.Continuous.Enabled = true
	c.Backup.Continuous.ReplicaURL = "s3://licd-backup/production/licensing.db"
	c.Backup.Continuous.S3.Region = "eu-west-1"
	c.Backup.Continuous.S3.Encryption.Mode = "sse-kms"
	c.Backup.Continuous.S3.Encryption.KMSKeyIDEnv = "LICD_BACKUP_KMS_KEY_ID"
	b, err := RenderConfig(c, filepath.Join(t.TempDir(), "licensing.db"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, expected := range []string{"sse-kms-key-id: ${LICD_BACKUP_KMS_KEY_ID}", "sync-interval: 1s", "retention: 720h0m0s", "validation:"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("config missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "access-key") || strings.Contains(text, "secret-access") {
		t.Fatalf("credentials written to config:\n%s", text)
	}
	var decoded map[string]any
	if err = yaml.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestManagedLifecycleAndRestore(t *testing.T) {
	binary := buildFakeLitestream(t)
	dir := t.TempDir()
	c := config.Defaults()
	c.Database.DSN = filepath.Join(dir, "source.db")
	c.Backup.Continuous.Enabled = true
	c.Backup.Continuous.Binary = binary
	c.Backup.Continuous.ConfigFile = filepath.Join(dir, "managed-litestream.yml")
	c.Backup.Continuous.ReplicaURL = "s3://licd-backups/test/licensing.db"
	c.Backup.Continuous.S3.Encryption.KMSKeyID = "alias/licd-test"
	c.Backup.Continuous.HealthCheckInterval = 100 * time.Millisecond
	c.Backup.Continuous.MaxBackupAge = time.Minute
	repo, err := sqliterepo.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	m := New(c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err = m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !m.Ready() && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if h := m.Health(); !m.Ready() {
		t.Fatalf("backup did not become ready: %+v", h)
	}
	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err = m.Stop(stopCtx); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FAKE_LITESTREAM_SOURCE", c.Database.DSN)
	output := filepath.Join(dir, "restored.db")
	plan, err := Restore(context.Background(), c, output, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != "planned" || len(plan.Plan) == 0 {
		t.Fatalf("plan=%+v", plan)
	}
	result, err := Restore(context.Background(), c, output, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "restored" {
		t.Fatalf("result=%+v", result)
	}
	if _, err = os.Stat(output); err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(context.Background(), c, output, nil, false); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("got %v", err)
	}
	points, err := RestorePoints(context.Background(), c)
	if err != nil || len(points) != 1 {
		t.Fatalf("points=%+v err=%v", points, err)
	}
}

func buildFakeLitestream(t *testing.T) string {
	t.Helper()
	name := "fakelitestream"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	output := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", output, "./testdata/fakelitestream")
	cmd.Dir = "."
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake Litestream: %v\n%s", err, b)
	}
	return output
}

func TestRealLitestreamConfiguration(t *testing.T) {
	binary := os.Getenv("LICD_TEST_LITESTREAM_BINARY")
	if binary == "" {
		t.Skip("set LICD_TEST_LITESTREAM_BINARY to validate against a real Litestream binary")
	}
	c := config.Defaults()
	c.Backup.Continuous.Enabled = true
	c.Backup.Continuous.Binary = binary
	c.Backup.Continuous.ReplicaURL = "s3://licd-config-validation/test/licensing.db"
	c.Backup.Continuous.S3.Region = "eu-west-1"
	c.Backup.Continuous.S3.Encryption.KMSKeyID = "alias/licd-test"
	database := filepath.Join(t.TempDir(), "licensing.db")
	path := filepath.Join(t.TempDir(), "litestream.yml")
	if err := WriteConfig(path, c, database); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckVersion(context.Background(), binary); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "databases", "-config", path, "-json")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real Litestream rejected generated config: %v\n%s", err, out)
	}
	c.Backup.Continuous.S3.Encryption.Mode = "sse-c"
	c.Backup.Continuous.S3.Encryption.KMSKeyID = ""
	c.Backup.Continuous.S3.Encryption.CustomerKeyEnv = "LICD_TEST_REAL_SSE_C_KEY"
	t.Setenv("LICD_TEST_REAL_SSE_C_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	sseCPath := filepath.Join(t.TempDir(), "litestream-sse-c.yml")
	if err := WriteConfig(sseCPath, c, database); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(binary, "databases", "-config", sseCPath, "-json")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real Litestream rejected SSE-C config: %v\n%s", err, out)
	}
}

func TestRenderConfigSSECUsesEnvironmentReference(t *testing.T) {
	c := config.Defaults()
	c.Backup.Continuous.S3.Encryption.Mode = "sse-c"
	c.Backup.Continuous.S3.Encryption.CustomerKeyEnv = "LICD_BACKUP_SSE_C_KEY"
	b, err := RenderConfig(c, "/data/licensing.db")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "sse-customer-key: ${LICD_BACKUP_SSE_C_KEY}") {
		t.Fatalf("%s", b)
	}
}

func TestCompareVersion(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"0.5.11", "0.5.12", -1}, {"0.5.12", "0.5.12", 0}, {"0.6.0", "0.5.12", 1}} {
		if got := compareVersion(tc.a, tc.b); got != tc.want {
			t.Fatalf("compareVersion(%q,%q)=%d", tc.a, tc.b, got)
		}
	}
}

func TestWriteConfigRefusesUnmanagedFileAndReplacesManagedFile(t *testing.T) {
	c := config.Defaults()
	c.Backup.Continuous.ReplicaURL = "s3://bucket/path"
	c.Backup.Continuous.S3.Encryption.KMSKeyID = "alias/test"
	path := filepath.Join(t.TempDir(), "litestream.yml")
	if err := os.WriteFile(path, []byte("user-owned: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteConfig(path, c, "/data/one.db"); err == nil || !strings.Contains(err.Error(), "unmanaged") {
		t.Fatalf("got %v", err)
	}
	if err := os.WriteFile(path, []byte(generatedHeader+"old: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteConfig(path, c, "/data/two.db"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "/data/two.db") {
		t.Fatalf("%s", b)
	}
}
