package secretvalue

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxSecretBytes = 64 * 1024

// Read resolves NAME or NAME_FILE, never both. File indirection supports
// Docker/Kubernetes secret mounts without putting secret bytes in YAML or
// process arguments.
func Read(name string) ([]byte, error) {
	direct, directSet := os.LookupEnv(name)
	file, fileSet := os.LookupEnv(name + "_FILE")
	if directSet && fileSet {
		return nil, fmt.Errorf("%s and %s_FILE are mutually exclusive", name, name)
	}
	if directSet {
		return []byte(direct), nil
	}
	if !fileSet || strings.TrimSpace(file) == "" {
		return nil, nil
	}
	if !filepath.IsAbs(file) {
		return nil, fmt.Errorf("%s_FILE must contain an absolute path", name)
	}
	info, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("read %s_FILE: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s_FILE must reference a regular file", name)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s_FILE permissions must not grant group or other access", name)
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSecretBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecretBytes {
		return nil, errors.New("secret file exceeds 64 KiB")
	}
	b = []byte(strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"))
	return b, nil
}

func String(name string) (string, error) {
	b, err := Read(name)
	return string(b), err
}
