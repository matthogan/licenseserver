//go:build !windows

package admintransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

type cleanupListener struct {
	net.Listener
	path string
}

func (l *cleanupListener) Close() error {
	err := l.Listener.Close()
	removeErr := os.Remove(l.path)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(err, removeErr)
}

func listenUnix(path string, mode uint32) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket admin path %s", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("admin socket %s is already active", path)
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, os.FileMode(mode)); err != nil {
		l.Close()
		os.Remove(path)
		return nil, err
	}
	return &cleanupListener{Listener: l, path: path}, nil
}
func dialUnix(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
func listenPipe(string, string) (net.Listener, error) {
	return nil, errors.New("named pipes are only supported on Windows")
}
func dialPipe(context.Context, string) (net.Conn, error) {
	return nil, errors.New("named pipes are only supported on Windows")
}
func validatePipeSDDL(string) error { return errors.New("named pipes are only supported on Windows") }
