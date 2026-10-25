package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type RotatingWriter struct {
	mu         sync.Mutex
	path       string
	maxSize    int64
	maxBackups int
	maxAge     time.Duration
	file       *os.File
	size       int64
	now        func() time.Time
}

func NewRotatingWriter(path string, maxSize int64, maxBackups int, maxAge time.Duration) (*RotatingWriter, error) {
	if !filepath.IsAbs(path) || maxSize < 1024 || maxBackups < 1 || maxAge <= 0 {
		return nil, errors.New("invalid rotating log configuration")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	w := &RotatingWriter{path: path, maxSize: maxSize, maxBackups: maxBackups, maxAge: maxAge, now: func() time.Time { return time.Now().UTC() }}
	if err := w.open(); err != nil {
		return nil, err
	}
	if err := w.cleanup(); err != nil {
		w.file.Close()
		return nil, err
	}
	return w, nil
}

func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	if w.size > 0 && w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file, w.size = f, info.Size()
	return nil
}

func (w *RotatingWriter) rotate() error {
	if err := w.file.Sync(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	stamp := w.now().UTC().Format("20060102T150405.000000000Z")
	var target string
	for sequence := 0; ; sequence++ {
		target = fmt.Sprintf("%s.%s.%03d", w.path, stamp, sequence)
		if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
			break
		} else if err != nil {
			return err
		}
	}
	if err := os.Rename(w.path, target); err != nil {
		return err
	}
	if err := w.open(); err != nil {
		return err
	}
	return w.cleanup()
}

func (w *RotatingWriter) cleanup() error {
	dir := filepath.Dir(w.path)
	prefix := filepath.Base(w.path) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type backup struct {
		path string
		mod  time.Time
	}
	var backups []backup
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		backups = append(backups, backup{path: filepath.Join(dir, entry.Name()), mod: info.ModTime()})
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].mod.Equal(backups[j].mod) {
			return backups[i].path > backups[j].path
		}
		return backups[i].mod.After(backups[j].mod)
	})
	cutoff := w.now().Add(-w.maxAge)
	var joined error
	for index, backup := range backups {
		if index >= w.maxBackups || backup.mod.Before(cutoff) {
			joined = errors.Join(joined, os.Remove(backup.path))
		}
	}
	return joined
}

var _ io.WriteCloser = (*RotatingWriter)(nil)
