//go:build windows

package continuousbackup

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func signalGraceful(_ *os.Process) error {
	return errors.New("Windows child processes do not support POSIX shutdown signals")
}
func requiresFinalSync() bool { return true }
func replaceFile(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
