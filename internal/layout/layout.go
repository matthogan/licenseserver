package layout

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/matthogan/licenceserver/internal/config"
)

type Directory struct {
	Path      string      `json:"path"`
	Mode      os.FileMode `json:"-"`
	Sensitive bool        `json:"sensitive"`
}

func Directories(configPath string, cfg config.Config) []Directory {
	paths := map[string]Directory{}
	add := func(raw string, mode os.FileMode, sensitive bool) {
		if raw == "" || raw == "." {
			return
		}
		absolute, err := filepath.Abs(filepath.Clean(raw))
		if err != nil {
			return
		}
		key := strings.ToLower(absolute)
		if current, exists := paths[key]; exists {
			if sensitive && !current.Sensitive {
				current.Sensitive, current.Mode = true, 0o700
				paths[key] = current
			}
			return
		}
		paths[key] = Directory{Path: absolute, Mode: mode, Sensitive: sensitive}
	}
	if configPath != "" {
		add(filepath.Dir(configPath), 0o750, false)
	}
	add(cfg.SignerKeyDirectory(), 0o700, true)
	add(filepath.Dir(cfg.Signer.RootPublicKeyFile), 0o750, false)
	add(filepath.Dir(cfg.Signer.IssuerCertificateFile), 0o750, false)
	if cfg.TLS.Enabled {
		add(filepath.Dir(cfg.TLS.CertificateFile), 0o750, false)
		add(filepath.Dir(cfg.TLS.PrivateKeyFile), 0o750, false)
	}
	if cfg.AdminTLS.Enabled {
		add(filepath.Dir(cfg.AdminTLS.CertificateFile), 0o750, false)
		add(filepath.Dir(cfg.AdminTLS.PrivateKeyFile), 0o750, false)
	}
	if cfg.Database.Driver == "sqlite" && cfg.Database.DSN != ":memory:" && !strings.HasPrefix(cfg.Database.DSN, "file:") {
		data := filepath.Dir(cfg.Database.DSN)
		add(data, 0o750, false)
		add(filepath.Join(data, "backups"), 0o750, false)
		add(filepath.Join(data, "restores"), 0o750, false)
		if runtime.GOOS == "windows" {
			add(filepath.Join(data, "logs"), 0o750, false)
		} else if filepath.Clean(data) == "/var/lib/licd" {
			add("/var/log/licd", 0o750, false)
		} else {
			add(filepath.Join(data, "logs"), 0o750, false)
		}
	}
	if cfg.Archive.Provider == "filesystem" {
		add(cfg.Archive.Directory, 0o750, false)
	}
	if cfg.Backup.Continuous.ConfigFile != "" {
		add(filepath.Dir(cfg.Backup.Continuous.ConfigFile), 0o750, false)
	}
	if cfg.RecoveryDrill.Enabled && cfg.RecoveryDrill.ReportDirectory != "" {
		add(cfg.RecoveryDrill.ReportDirectory, 0o750, false)
	}
	if cfg.Logging.Output != "" && cfg.Logging.Output != "stdout" && cfg.Logging.Output != "stderr" {
		add(filepath.Dir(cfg.Logging.Output), 0o750, false)
	}
	if cfg.Server.AdminTransport == "unix" {
		add(filepath.Dir(cfg.Server.AdminSocket), 0o750, false)
	}
	out := make([]Directory, 0, len(paths))
	for _, directory := range paths {
		out = append(out, directory)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func Ensure(configPath string, cfg config.Config) error {
	directories := Directories(configPath, cfg)
	for _, directory := range directories {
		if err := os.MkdirAll(directory.Path, directory.Mode); err != nil {
			return fmt.Errorf("create managed directory %s: %w", directory.Path, err)
		}
	}
	// Harden children before parents so Windows ACL changes cannot prevent the
	// installer from finishing creation of the tree.
	sort.SliceStable(directories, func(i, j int) bool { return len(directories[i].Path) > len(directories[j].Path) })
	for _, directory := range directories {
		if err := hardenDirectory(directory); err != nil {
			return err
		}
	}
	return Check(configPath, cfg)
}

func Check(configPath string, cfg config.Config) error {
	for _, directory := range Directories(configPath, cfg) {
		info, err := os.Stat(directory.Path)
		if err != nil {
			return fmt.Errorf("managed directory %s: %w", directory.Path, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("managed path %s is not a directory", directory.Path)
		}
		if err = checkDirectorySecurity(directory, info); err != nil {
			return err
		}
	}
	return nil
}
