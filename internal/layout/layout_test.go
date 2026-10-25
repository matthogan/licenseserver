package layout

import (
	"path/filepath"
	"testing"

	"github.com/matthogan/licenceserver/internal/config"
)

func TestEnsureCreatesCompleteConfiguredLayout(t *testing.T) {
	root := t.TempDir()
	cfg := config.Defaults()
	cfg.Database.DSN = filepath.Join(root, "data", "licensing.db")
	cfg.Signer.KeyDirectory = filepath.Join(root, "config", "secrets")
	cfg.Signer.RootPublicKeyFile = filepath.Join(root, "config", "root.pub")
	cfg.Signer.IssuerCertificateFile = filepath.Join(root, "config", "secrets", "issuer.cert")
	cfg.Archive.Directory = filepath.Join(root, "data", "archive")
	cfg.Backup.Continuous.ConfigFile = filepath.Join(root, "data", "backup", "litestream.yml")
	cfg.Logging.Output = filepath.Join(root, "logs", "licd.log")
	configPath := filepath.Join(root, "config", "config.yaml")
	if err := Ensure(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	if err := Check(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{
		filepath.Join(root, "data", "backups"):   false,
		filepath.Join(root, "data", "restores"):  false,
		filepath.Join(root, "data", "archive"):   false,
		filepath.Join(root, "config", "secrets"): true,
		filepath.Join(root, "data", "backup"):    false,
		filepath.Join(root, "logs"):              false,
	}
	for _, directory := range Directories(configPath, cfg) {
		if sensitive, ok := wanted[directory.Path]; ok {
			if sensitive != directory.Sensitive {
				t.Fatalf("directory %s sensitive=%v", directory.Path, directory.Sensitive)
			}
			delete(wanted, directory.Path)
		}
	}
	if len(wanted) != 0 {
		t.Fatalf("managed directories missing: %v", wanted)
	}
}
