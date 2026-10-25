package verifier

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// StoreOptions controls keyring persistence. Clock defaults to UTC system
// time. FileMode may only remove permissions from the secure 0600 default.
type StoreOptions struct {
	Clock    Clock
	FileMode fs.FileMode
}

// KeyringStore serializes writers and exposes copy-on-read snapshots. A
// failed disk write never changes the in-memory keyring.
type KeyringStore struct {
	mu        sync.RWMutex
	path      string
	bootstrap ed25519.PublicKey
	clock     Clock
	fileMode  fs.FileMode
	keyring   Keyring
}

// OpenKeyringStore loads a strict persisted keyring and verifies every root is
// linked to embeddedRoot. If the file does not exist, a bootstrap keyring is
// atomically created. No private key is stored.
func OpenKeyringStore(path string, embeddedRoot []byte, options StoreOptions) (*KeyringStore, error) {
	const operation = "open keyring store"
	if stringsTrim(path) == "" {
		return nil, fail(CodePersistence, operation, "path is required", nil)
	}
	root, err := ParseRootPublicKey(embeddedRoot)
	if err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fail(CodePersistence, operation, "path cannot be resolved", err)
	}
	if options.Clock == nil {
		options.Clock = systemClock{}
	}
	mode := options.FileMode.Perm()
	if mode == 0 {
		mode = 0o600
	}
	if mode&0o077 != 0 {
		return nil, fail(CodePersistence, operation, "keyring mode must not grant group or other access", nil)
	}
	store := &KeyringStore{path: absolute, bootstrap: root, clock: options.Clock, fileMode: mode}
	data, readErr := readKeyringFile(absolute)
	if errors.Is(readErr, os.ErrNotExist) {
		keyring, createErr := NewKeyring(root)
		if createErr != nil {
			return nil, createErr
		}
		if createErr = store.write(keyring); createErr != nil {
			return nil, createErr
		}
		store.keyring = keyring
		return store, nil
	}
	if readErr != nil {
		return nil, fail(CodePersistence, operation, "keyring cannot be read", readErr)
	}
	keyring, err := decodePersistedKeyring(data, root)
	if err != nil {
		return nil, err
	}
	store.keyring = keyring
	return store, nil
}

func (s *KeyringStore) Path() string { return s.path }

func (s *KeyringStore) Snapshot() Keyring {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneKeyring(s.keyring)
}

// Reload parses and validates the entire disk file before swapping the live
// snapshot. Readers see either the old or the new complete keyring.
func (s *KeyringStore) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := readKeyringFile(s.path)
	if err != nil {
		return fail(CodePersistence, "reload keyring", "keyring cannot be read", err)
	}
	keyring, err := decodePersistedKeyring(data, s.bootstrap)
	if err != nil {
		return err
	}
	s.keyring = keyring
	return nil
}

func (s *KeyringStore) Verifier(options Options) (*Verifier, error) {
	if options.Clock == nil {
		options.Clock = s.clock
	}
	return New(s.Snapshot(), options)
}

func (s *KeyringStore) ApplyTransition(artifact string) (RootTransition, error) {
	var applied RootTransition
	err := s.mutate("apply transition", func(current Keyring) (Keyring, error) {
		next, payload, err := ApplyTransition(current, artifact, s.clock.Now())
		applied = payload
		return next, err
	})
	return applied, err
}

func (s *KeyringStore) RollbackTransition(transitionID, reason string, compromiseNew bool) error {
	return s.mutate("rollback transition", func(current Keyring) (Keyring, error) {
		return RollbackTransition(current, transitionID, reason, compromiseNew, s.clock.Now())
	})
}

func (s *KeyringStore) MarkCompromised(keyID, reason string) error {
	return s.mutate("compromise root", func(current Keyring) (Keyring, error) {
		return MarkCompromised(current, keyID, reason, s.clock.Now())
	})
}

func (s *KeyringStore) mutate(operation string, change func(Keyring) (Keyring, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := change(cloneKeyring(s.keyring))
	if err != nil {
		return err
	}
	next.Revision = s.keyring.Revision + 1
	if err = validateKeyring(next, s.bootstrap); err != nil {
		return err
	}
	if err = s.write(next); err != nil {
		return fail(CodePersistence, operation, "atomic keyring replacement failed", err)
	}
	s.keyring = next
	return nil
}

func (s *KeyringStore) write(keyring Keyring) error {
	data, err := json.MarshalIndent(keyring, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > MaxKeyringBytes {
		return fmt.Errorf("keyring exceeds %d bytes", MaxKeyringBytes)
	}
	directory := filepath.Dir(s.path)
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".keyring-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(s.fileMode); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, s.path)
}

func readKeyringFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("keyring path is not a regular file")
	}
	if info.Size() > MaxKeyringBytes {
		return nil, fail(CodeTooLarge, "read keyring", "persisted keyring exceeds limit", nil)
	}
	return os.ReadFile(path)
}

func decodePersistedKeyring(data []byte, bootstrap ed25519.PublicKey) (Keyring, error) {
	var keyring Keyring
	if err := decodeStrict(data, MaxKeyringBytes, &keyring, "load keyring"); err != nil {
		return Keyring{}, err
	}
	if err := validateKeyring(keyring, bootstrap); err != nil {
		return Keyring{}, err
	}
	return cloneKeyring(keyring), nil
}

func stringsTrim(value string) string {
	for len(value) > 0 && (value[0] == ' ' || value[0] == '\t' || value[0] == '\r' || value[0] == '\n') {
		value = value[1:]
	}
	for len(value) > 0 {
		last := value[len(value)-1]
		if last != ' ' && last != '\t' && last != '\r' && last != '\n' {
			break
		}
		value = value[:len(value)-1]
	}
	return value
}
