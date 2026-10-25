//go:build !windows

package continuousbackup

import (
	"os"
	"syscall"
)

func signalGraceful(process *os.Process) error { return process.Signal(syscall.SIGTERM) }
func requiresFinalSync() bool                  { return false }
func replaceFile(source, target string) error  { return os.Rename(source, target) }
