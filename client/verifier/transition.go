package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const (
	transitionPrefix  = "RKT1"
	transitionContext = "desktop-root-transition:v1\n"
)

// InspectTransition strictly parses and validates the canonical RKT1 payload
// and signature encodings. It does not establish trust or check time.
func InspectTransition(artifact string) (RootTransition, error) {
	const operation = "inspect transition"
	if len(artifact) == 0 || len(artifact) > MaxTransitionBytes || artifact != strings.TrimSpace(artifact) {
		code := CodeMalformed
		if len(artifact) > MaxTransitionBytes {
			code = CodeTooLarge
		}
		return RootTransition{}, fail(code, operation, "invalid transition size or whitespace", nil)
	}
	parts := strings.Split(artifact, ".")
	if len(parts) != 4 || parts[0] != transitionPrefix {
		return RootTransition{}, fail(CodeMalformed, operation, "invalid RKT1 envelope", nil)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return RootTransition{}, fail(CodeMalformed, operation, "invalid transition payload encoding", err)
	}
	var payload RootTransition
	if err = decodeStrict(payloadBytes, MaxTransitionBytes, &payload, operation); err != nil {
		return RootTransition{}, err
	}
	canonical, marshalErr := json.Marshal(payload)
	if marshalErr != nil || !bytes.Equal(canonical, payloadBytes) {
		return RootTransition{}, fail(CodeMalformed, operation, "transition payload is not canonical JSON", marshalErr)
	}
	if err = validateTransition(payload); err != nil {
		return RootTransition{}, err
	}
	for _, encoded := range parts[2:] {
		signature, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		if decodeErr != nil || len(signature) != ed25519.SignatureSize {
			return RootTransition{}, fail(CodeMalformed, operation, "invalid transition signature encoding", decodeErr)
		}
	}
	return payload, nil
}

// VerifyTransition establishes continuity from an active root, verifies both
// signatures, and enforces not_before <= now < expires_at.
func VerifyTransition(keyring Keyring, artifact string, now time.Time) (RootTransition, error) {
	const operation = "verify transition"
	payload, err := verifyTransitionSignatures(artifact)
	if err != nil {
		return RootTransition{}, err
	}
	trusted := false
	for _, root := range keyring.Roots {
		if root.KeyID == payload.OldRootKeyID && root.Status == RootActive && root.PublicKey == payload.OldRootPublicKey {
			trusted = true
			break
		}
	}
	if !trusted {
		return RootTransition{}, fail(CodeUntrustedRoot, operation, "old root is not the active trust anchor", nil)
	}
	if now.Before(payload.NotBefore) {
		return RootTransition{}, fail(CodeTransitionInactive, operation, "transition is not active", nil)
	}
	if !now.Before(payload.ExpiresAt) {
		return RootTransition{}, fail(CodeTransitionExpired, operation, "transition installation window has expired", nil)
	}
	return payload, nil
}

func verifyTransitionSignatures(artifact string) (RootTransition, error) {
	payload, err := InspectTransition(artifact)
	if err != nil {
		return RootTransition{}, err
	}
	parts := strings.Split(artifact, ".")
	oldPublic, _ := base64.RawURLEncoding.DecodeString(payload.OldRootPublicKey)
	newPublic, _ := base64.RawURLEncoding.DecodeString(payload.NewRootPublicKey)
	oldSignature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	newSignature, _ := base64.RawURLEncoding.DecodeString(parts[3])
	if !ed25519.Verify(ed25519.PublicKey(oldPublic), []byte(transitionContext+"old\n"+parts[1]), oldSignature) ||
		!ed25519.Verify(ed25519.PublicKey(newPublic), []byte(transitionContext+"new\n"+parts[1]), newSignature) {
		return RootTransition{}, fail(CodeInvalidSignature, "verify transition", "one or both RKT1 signatures did not verify", nil)
	}
	return payload, nil
}

// ApplyTransition returns a changed copy and leaves the input untouched.
func ApplyTransition(keyring Keyring, artifact string, now time.Time) (Keyring, RootTransition, error) {
	if len(keyring.Roots) >= MaxRoots {
		return Keyring{}, RootTransition{}, fail(CodeStateConflict, "apply transition", "maximum root history reached", nil)
	}
	payload, err := VerifyTransition(keyring, artifact, now)
	if err != nil {
		return Keyring{}, RootTransition{}, err
	}
	for _, record := range keyring.Transitions {
		if record.TransitionID == payload.TransitionID || record.NewRootKeyID == payload.NewRootKeyID {
			return Keyring{}, RootTransition{}, fail(CodeStateConflict, "apply transition", "transition or new root already exists", nil)
		}
	}
	out := cloneKeyring(keyring)
	foundOld := false
	for i := range out.Roots {
		if out.Roots[i].KeyID == payload.OldRootKeyID {
			cutoff := payload.OverlapUntil
			out.Roots[i].Status = RootLegacy
			out.Roots[i].AcceptCertificatesBefore = &cutoff
			foundOld = true
		}
	}
	if !foundOld {
		return Keyring{}, RootTransition{}, fail(CodeUntrustedRoot, "apply transition", "old root disappeared", nil)
	}
	start := payload.NotBefore
	out.Roots = append(out.Roots, TrustedRoot{
		KeyID:                       payload.NewRootKeyID,
		Algorithm:                   "Ed25519",
		PublicKey:                   payload.NewRootPublicKey,
		Status:                      RootActive,
		AcceptCertificatesNotBefore: &start,
	})
	out.Transitions = append(out.Transitions, TransitionRecord{
		TransitionID: payload.TransitionID,
		OldRootKeyID: payload.OldRootKeyID,
		NewRootKeyID: payload.NewRootKeyID,
		Artifact:     artifact,
		State:        TransitionApplied,
		AppliedAt:    now.UTC(),
	})
	out.Revision = keyring.Revision + 1
	return out, payload, nil
}

// RollbackTransition restores the old root during the signed overlap period.
// compromiseNew permanently excludes the new root; otherwise it is retired.
func RollbackTransition(keyring Keyring, transitionID, reason string, compromiseNew bool, now time.Time) (Keyring, error) {
	if !validText(transitionID, 128) || !validReason(reason) || now.IsZero() {
		return Keyring{}, fail(CodeMalformed, "rollback transition", "invalid transition, reason, or time", nil)
	}
	out := cloneKeyring(keyring)
	recordIndex := -1
	var payload RootTransition
	for i := range out.Transitions {
		if out.Transitions[i].TransitionID != transitionID {
			continue
		}
		if out.Transitions[i].State != TransitionApplied {
			return Keyring{}, fail(CodeStateConflict, "rollback transition", "transition is not applied", nil)
		}
		var err error
		payload, err = verifyTransitionSignatures(out.Transitions[i].Artifact)
		if err != nil {
			return Keyring{}, err
		}
		recordIndex = i
		break
	}
	if recordIndex < 0 {
		return Keyring{}, fail(CodeStateConflict, "rollback transition", "transition is not present", nil)
	}
	if !now.Before(payload.OverlapUntil) {
		return Keyring{}, fail(CodeStateConflict, "rollback transition", "overlap period has ended", nil)
	}
	oldFound, newFound := false, false
	for i := range out.Roots {
		switch out.Roots[i].KeyID {
		case payload.OldRootKeyID:
			out.Roots[i].Status = RootActive
			out.Roots[i].AcceptCertificatesBefore = nil
			out.Roots[i].StateReason = strings.TrimSpace(reason)
			changed := now.UTC()
			out.Roots[i].StateChangedAt = &changed
			oldFound = true
		case payload.NewRootKeyID:
			out.Roots[i].Status = RootRetired
			if compromiseNew {
				out.Roots[i].Status = RootCompromised
			}
			out.Roots[i].StateReason = strings.TrimSpace(reason)
			changed := now.UTC()
			out.Roots[i].StateChangedAt = &changed
			newFound = true
		}
	}
	if !oldFound || !newFound {
		return Keyring{}, fail(CodeStateConflict, "rollback transition", "transition roots are incomplete", nil)
	}
	changed := now.UTC()
	out.Transitions[recordIndex].State = TransitionRolledBack
	out.Transitions[recordIndex].ChangedAt = &changed
	out.Transitions[recordIndex].StateReason = strings.TrimSpace(reason)
	out.Revision = keyring.Revision + 1
	return out, nil
}

func validateTransition(payload RootTransition) error {
	oldPublic, oldErr := base64.RawURLEncoding.DecodeString(payload.OldRootPublicKey)
	newPublic, newErr := base64.RawURLEncoding.DecodeString(payload.NewRootPublicKey)
	if payload.SchemaVersion != 1 || payload.Algorithm != "Ed25519" || !validText(payload.TransitionID, 128) || strings.Contains(payload.TransitionID, ".") ||
		!validReason(payload.Reason) || oldErr != nil || newErr != nil || len(oldPublic) != ed25519.PublicKeySize || len(newPublic) != ed25519.PublicKeySize ||
		payload.OldRootKeyID != RootKeyID(ed25519.PublicKey(oldPublic)) || payload.NewRootKeyID != RootKeyID(ed25519.PublicKey(newPublic)) || payload.OldRootKeyID == payload.NewRootKeyID ||
		payload.CreatedAt.IsZero() || payload.NotBefore.Before(payload.CreatedAt) || !payload.NotBefore.Before(payload.OverlapUntil) || !payload.OverlapUntil.Before(payload.ExpiresAt) {
		return fail(CodeMalformed, "inspect transition", "invalid signed transition fields", nil)
	}
	return nil
}
