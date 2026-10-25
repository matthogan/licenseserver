//go:build !windows

package layout

import (
	"fmt"
	"os"
)

func hardenDirectory(directory Directory) error {
	if err := os.Chmod(directory.Path, directory.Mode); err != nil {
		return fmt.Errorf("set managed directory permissions on %s: %w", directory.Path, err)
	}
	return nil
}

func checkDirectorySecurity(directory Directory, info os.FileInfo) error {
	mode := info.Mode().Perm()
	if mode&0o002 != 0 || directory.Sensitive && mode&0o077 != 0 {
		return fmt.Errorf("managed directory %s has unsafe permissions %04o", directory.Path, mode)
	}
	return nil
}
