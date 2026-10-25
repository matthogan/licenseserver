package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"
)

// RootKeyID is the protocol's full SHA-256 identifier for an Ed25519 root.
func RootKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ParseRootPublicKey accepts an embedded raw 32-byte Ed25519 public key,
// unpadded/padded base64url, hexadecimal, or PKIX PUBLIC KEY PEM.
func ParseRootPublicKey(data []byte) (ed25519.PublicKey, error) {
	const operation = "parse bootstrap root"
	if len(data) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), data...), nil
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || len(trimmed) > 4096 {
		return nil, fail(CodeMalformed, operation, "invalid root key size", nil)
	}
	if block, rest := pem.Decode(trimmed); block != nil && len(bytes.TrimSpace(rest)) == 0 {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			if key, ok := parsed.(ed25519.PublicKey); ok && len(key) == ed25519.PublicKeySize {
				return append(ed25519.PublicKey(nil), key...), nil
			}
		}
		return nil, fail(CodeMalformed, operation, "PEM is not an Ed25519 public key", err)
	}
	decoders := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, decode := range decoders {
		decoded, err := decode(string(trimmed))
		if err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, fail(CodeMalformed, operation, "unsupported root key encoding", nil)
}

// NewKeyring creates a revision-one keyring from an embedded/bootstrap root.
func NewKeyring(publicKey ed25519.PublicKey) (Keyring, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Keyring{}, fail(CodeMalformed, "new keyring", "root must be an Ed25519 public key", nil)
	}
	encoded := base64.RawURLEncoding.EncodeToString(publicKey)
	return Keyring{
		SchemaVersion: 1,
		Revision:      1,
		Roots: []TrustedRoot{{
			KeyID:     RootKeyID(publicKey),
			Algorithm: "Ed25519",
			PublicKey: encoded,
			Status:    RootActive,
		}},
	}, nil
}

// NewKeyringFromEmbedded parses a key in any ParseRootPublicKey encoding.
func NewKeyringFromEmbedded(data []byte) (Keyring, error) {
	key, err := ParseRootPublicKey(data)
	if err != nil {
		return Keyring{}, err
	}
	return NewKeyring(key)
}

// MarshalKeyring returns the stable public JSON representation.
func MarshalKeyring(keyring Keyring) ([]byte, error) {
	if err := validateKeyring(keyring, nil); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(keyring, "", "  ")
	if err != nil {
		return nil, fail(CodeMalformed, "marshal keyring", "keyring cannot be encoded", err)
	}
	return append(data, '\n'), nil
}

// UnmarshalKeyring strictly parses a public keyring. To load persisted state,
// prefer OpenKeyringStore, which also verifies reachability from the embedded
// bootstrap root.
func UnmarshalKeyring(data []byte) (Keyring, error) {
	var keyring Keyring
	if err := decodeStrict(data, MaxKeyringBytes, &keyring, "unmarshal keyring"); err != nil {
		return Keyring{}, err
	}
	if err := validateKeyring(keyring, nil); err != nil {
		return Keyring{}, err
	}
	return cloneKeyring(keyring), nil
}

// MarkCompromised disables a root immediately while retaining its metadata
// for diagnostics. If it was the only usable root, subsequent verification
// correctly fails closed.
func MarkCompromised(keyring Keyring, keyID, reason string, now time.Time) (Keyring, error) {
	if !validText(keyID, 128) || !validReason(reason) || now.IsZero() {
		return Keyring{}, fail(CodeMalformed, "compromise root", "invalid root, reason, or time", nil)
	}
	out := cloneKeyring(keyring)
	found := false
	for i := range out.Roots {
		if out.Roots[i].KeyID != keyID {
			continue
		}
		if out.Roots[i].Status == RootCompromised {
			return Keyring{}, fail(CodeStateConflict, "compromise root", "root is already compromised", nil)
		}
		out.Roots[i].Status = RootCompromised
		out.Roots[i].StateReason = strings.TrimSpace(reason)
		changed := now.UTC()
		out.Roots[i].StateChangedAt = &changed
		found = true
		break
	}
	if !found {
		return Keyring{}, fail(CodeStateConflict, "compromise root", "root is not present", nil)
	}
	out.Revision = keyring.Revision + 1
	return out, nil
}

func validateKeyring(keyring Keyring, bootstrap ed25519.PublicKey) error {
	const operation = "validate keyring"
	if keyring.SchemaVersion != 1 || keyring.Revision == 0 || len(keyring.Roots) == 0 || len(keyring.Roots) > MaxRoots || len(keyring.Transitions) > MaxRoots-1 {
		return fail(CodeMalformed, operation, "invalid schema, revision, or collection size", nil)
	}
	roots := make(map[string]TrustedRoot, len(keyring.Roots))
	for _, root := range keyring.Roots {
		decoded, err := base64.RawURLEncoding.DecodeString(root.PublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || root.Algorithm != "Ed25519" || root.KeyID != RootKeyID(ed25519.PublicKey(decoded)) {
			return fail(CodeMalformed, operation, "invalid root metadata", nil)
		}
		switch root.Status {
		case RootActive, RootLegacy, RootRetired, RootCompromised:
		default:
			return fail(CodeMalformed, operation, "invalid root status", nil)
		}
		if _, duplicate := roots[root.KeyID]; duplicate || len(root.StateReason) > 512 {
			return fail(CodeMalformed, operation, "duplicate root or invalid state reason", nil)
		}
		if root.AcceptCertificatesNotBefore != nil && root.AcceptCertificatesBefore != nil && !root.AcceptCertificatesNotBefore.Before(*root.AcceptCertificatesBefore) {
			return fail(CodeMalformed, operation, "invalid root authority window", nil)
		}
		roots[root.KeyID] = root
	}
	reachable := make(map[string]bool)
	if bootstrap != nil {
		bootstrapID := RootKeyID(bootstrap)
		root, exists := roots[bootstrapID]
		if !exists || root.PublicKey != base64.RawURLEncoding.EncodeToString(bootstrap) {
			return fail(CodeUntrustedRoot, operation, "keyring does not contain the embedded bootstrap root", nil)
		}
		reachable[bootstrapID] = true
	}
	transitionIDs := make(map[string]struct{}, len(keyring.Transitions))
	parsed := make([]RootTransition, 0, len(keyring.Transitions))
	for _, record := range keyring.Transitions {
		if _, duplicate := transitionIDs[record.TransitionID]; duplicate || record.AppliedAt.IsZero() || len(record.StateReason) > 512 {
			return fail(CodeMalformed, operation, "invalid transition record", nil)
		}
		transitionIDs[record.TransitionID] = struct{}{}
		switch record.State {
		case TransitionApplied, TransitionRolledBack:
		default:
			return fail(CodeMalformed, operation, "invalid transition state", nil)
		}
		payload, err := verifyTransitionSignatures(record.Artifact)
		if err != nil || payload.TransitionID != record.TransitionID || payload.OldRootKeyID != record.OldRootKeyID || payload.NewRootKeyID != record.NewRootKeyID {
			return fail(CodeMalformed, operation, "transition record does not match signed artifact", err)
		}
		if _, exists := roots[payload.OldRootKeyID]; !exists {
			return fail(CodeMalformed, operation, "transition old root is absent", nil)
		}
		if root, exists := roots[payload.NewRootKeyID]; !exists || root.PublicKey != payload.NewRootPublicKey {
			return fail(CodeMalformed, operation, "transition new root is absent or mismatched", nil)
		}
		parsed = append(parsed, payload)
	}
	if bootstrap != nil {
		for changed := true; changed; {
			changed = false
			for _, transition := range parsed {
				if reachable[transition.OldRootKeyID] && !reachable[transition.NewRootKeyID] {
					reachable[transition.NewRootKeyID] = true
					changed = true
				}
			}
		}
		for keyID := range roots {
			if !reachable[keyID] {
				return fail(CodeUntrustedRoot, operation, "root is not linked to the embedded bootstrap root", nil)
			}
		}
	}
	return nil
}

func cloneKeyring(source Keyring) Keyring {
	data, _ := json.Marshal(source)
	var clone Keyring
	_ = json.Unmarshal(data, &clone)
	return clone
}

func validReason(reason string) bool {
	trimmed := strings.TrimSpace(reason)
	return trimmed != "" && len(trimmed) <= 512 && !strings.ContainsAny(trimmed, "\x00\r\n")
}
