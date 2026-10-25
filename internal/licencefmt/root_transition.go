package licencefmt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	rootTransitionPrefix  = "RKT1"
	rootTransitionContext = "desktop-root-transition:v1\n"
)

var (
	ErrUntrustedRoot      = errors.New("untrusted root")
	ErrTransitionExpired  = errors.New("root transition expired")
	ErrTransitionInactive = errors.New("root transition is not yet active")
)

// RootTransitionPayload is the canonical JSON payload carried by an RKT1
// artefact. Both roots sign the same encoded bytes: the old signature grants
// continuity and the new signature proves possession of the successor key.
type RootTransitionPayload struct {
	SchemaVersion    int       `json:"schema_version"`
	TransitionID     string    `json:"transition_id"`
	Algorithm        string    `json:"algorithm"`
	OldRootKeyID     string    `json:"old_root_key_id"`
	OldRootPublicKey string    `json:"old_root_public_key"`
	NewRootKeyID     string    `json:"new_root_key_id"`
	NewRootPublicKey string    `json:"new_root_public_key"`
	CreatedAt        time.Time `json:"created_at"`
	NotBefore        time.Time `json:"not_before"`
	OverlapUntil     time.Time `json:"overlap_until"`
	ExpiresAt        time.Time `json:"expires_at"`
	Reason           string    `json:"reason"`
}

type RootTransitionInspection struct {
	Payload             RootTransitionPayload `json:"payload"`
	OldSignaturePresent bool                  `json:"old_signature_present"`
	NewSignaturePresent bool                  `json:"new_signature_present"`
}

type TrustedRoot struct {
	KeyID                       string     `json:"key_id"`
	Algorithm                   string     `json:"algorithm"`
	PublicKey                   string     `json:"public_key"`
	Status                      string     `json:"status"`
	AcceptCertificatesNotBefore *time.Time `json:"accept_certificates_not_before,omitempty"`
	AcceptCertificatesBefore    *time.Time `json:"accept_certificates_before,omitempty"`
}

// TrustedKeyring is a deterministic, serializable client trust store. A
// retired routine root remains usable only for issuer certificates whose
// authority began before its cutover. Compromised and retired roots are not
// included by callers.
type TrustedKeyring struct {
	SchemaVersion int           `json:"schema_version"`
	Roots         []TrustedRoot `json:"roots"`
}

func RootKeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func NewFixedKeyring(publicKey ed25519.PublicKey) TrustedKeyring {
	return TrustedKeyring{SchemaVersion: 1, Roots: []TrustedRoot{{KeyID: RootKeyID(publicKey), Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Status: "active"}}}
}

func CreateRootTransition(oldPrivate, newPrivate ed25519.PrivateKey, payload RootTransitionPayload) (string, error) {
	if len(oldPrivate) != ed25519.PrivateKeySize || len(newPrivate) != ed25519.PrivateKeySize {
		return "", ErrMalformed
	}
	oldPublic := oldPrivate.Public().(ed25519.PublicKey)
	newPublic := newPrivate.Public().(ed25519.PublicKey)
	payload.OldRootKeyID = RootKeyID(oldPublic)
	payload.OldRootPublicKey = base64.RawURLEncoding.EncodeToString(oldPublic)
	payload.NewRootKeyID = RootKeyID(newPublic)
	payload.NewRootPublicKey = base64.RawURLEncoding.EncodeToString(newPublic)
	if err := validateRootTransitionPayload(payload); err != nil {
		return "", err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(b)
	oldSignature := ed25519.Sign(oldPrivate, []byte(rootTransitionContext+"old\n"+encoded))
	newSignature := ed25519.Sign(newPrivate, []byte(rootTransitionContext+"new\n"+encoded))
	return strings.Join([]string{rootTransitionPrefix, encoded, base64.RawURLEncoding.EncodeToString(oldSignature), base64.RawURLEncoding.EncodeToString(newSignature)}, "."), nil
}

func InspectRootTransition(artifact string) (RootTransitionInspection, error) {
	var inspection RootTransitionInspection
	if len(artifact) > MaxArtifactBytes {
		return inspection, ErrMalformed
	}
	parts := strings.Split(strings.TrimSpace(artifact), ".")
	if len(parts) != 4 || parts[0] != rootTransitionPrefix {
		return inspection, ErrMalformed
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(b, &inspection.Payload) != nil {
		return RootTransitionInspection{}, ErrMalformed
	}
	canonical, marshalErr := json.Marshal(inspection.Payload)
	if marshalErr != nil || !bytes.Equal(canonical, b) {
		return RootTransitionInspection{}, ErrMalformed
	}
	if err = validateRootTransitionPayload(inspection.Payload); err != nil {
		return RootTransitionInspection{}, err
	}
	oldSignature, oldErr := base64.RawURLEncoding.DecodeString(parts[2])
	newSignature, newErr := base64.RawURLEncoding.DecodeString(parts[3])
	inspection.OldSignaturePresent = oldErr == nil && len(oldSignature) == ed25519.SignatureSize
	inspection.NewSignaturePresent = newErr == nil && len(newSignature) == ed25519.SignatureSize
	if !inspection.OldSignaturePresent || !inspection.NewSignaturePresent {
		return RootTransitionInspection{}, ErrMalformed
	}
	return inspection, nil
}

// VerifyRootTransition requires the caller's existing trust anchor to exactly
// match the old root embedded in the artefact, then verifies both signatures
// and the installation window.
func VerifyRootTransition(trustedOld ed25519.PublicKey, artifact string, now time.Time) (RootTransitionPayload, error) {
	p, err := VerifyRootTransitionSignatures(trustedOld, artifact)
	if err != nil {
		return RootTransitionPayload{}, err
	}
	if now.Before(p.NotBefore) {
		return RootTransitionPayload{}, ErrTransitionInactive
	}
	if !now.Before(p.ExpiresAt) {
		return RootTransitionPayload{}, ErrTransitionExpired
	}
	return p, nil
}

func VerifyRootTransitionSignatures(trustedOld ed25519.PublicKey, artifact string) (RootTransitionPayload, error) {
	inspection, err := InspectRootTransition(artifact)
	if err != nil {
		return RootTransitionPayload{}, err
	}
	p := inspection.Payload
	oldPublic, _ := base64.RawURLEncoding.DecodeString(p.OldRootPublicKey)
	newPublic, _ := base64.RawURLEncoding.DecodeString(p.NewRootPublicKey)
	if len(trustedOld) != ed25519.PublicKeySize || !trustedOld.Equal(ed25519.PublicKey(oldPublic)) || RootKeyID(trustedOld) != p.OldRootKeyID {
		return RootTransitionPayload{}, ErrUntrustedRoot
	}
	parts := strings.Split(strings.TrimSpace(artifact), ".")
	oldSignature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	newSignature, _ := base64.RawURLEncoding.DecodeString(parts[3])
	if !ed25519.Verify(ed25519.PublicKey(oldPublic), []byte(rootTransitionContext+"old\n"+parts[1]), oldSignature) ||
		!ed25519.Verify(ed25519.PublicKey(newPublic), []byte(rootTransitionContext+"new\n"+parts[1]), newSignature) {
		return RootTransitionPayload{}, ErrSignature
	}
	return p, nil
}

// VerifyRootTransitionFromAnchor validates a persisted dual-signed edge from
// either endpoint. It is intended for restart/keyring-chain validation after
// operators have deliberately changed the configured public trust anchor.
func VerifyRootTransitionFromAnchor(trusted ed25519.PublicKey, artifact string) (RootTransitionPayload, error) {
	inspection, err := InspectRootTransition(artifact)
	if err != nil {
		return RootTransitionPayload{}, err
	}
	p := inspection.Payload
	oldPublic, _ := base64.RawURLEncoding.DecodeString(p.OldRootPublicKey)
	newPublic, _ := base64.RawURLEncoding.DecodeString(p.NewRootPublicKey)
	if len(trusted) != ed25519.PublicKeySize || (!trusted.Equal(ed25519.PublicKey(oldPublic)) && !trusted.Equal(ed25519.PublicKey(newPublic))) {
		return RootTransitionPayload{}, ErrUntrustedRoot
	}
	parts := strings.Split(strings.TrimSpace(artifact), ".")
	oldSignature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	newSignature, _ := base64.RawURLEncoding.DecodeString(parts[3])
	if !ed25519.Verify(ed25519.PublicKey(oldPublic), []byte(rootTransitionContext+"old\n"+parts[1]), oldSignature) ||
		!ed25519.Verify(ed25519.PublicKey(newPublic), []byte(rootTransitionContext+"new\n"+parts[1]), newSignature) {
		return RootTransitionPayload{}, ErrSignature
	}
	return p, nil
}

// ApplyRootTransition returns a new keyring and leaves the input untouched.
// The old root is bounded at the end of overlap for newly-created issuer
// authorities; historical certificates remain verifiable after cutover.
func (k TrustedKeyring) ApplyRootTransition(artifact string, now time.Time) (TrustedKeyring, RootTransitionPayload, error) {
	if k.SchemaVersion != 1 || len(k.Roots) == 0 || len(k.Roots) >= 8 {
		return TrustedKeyring{}, RootTransitionPayload{}, ErrMalformed
	}
	inspection, err := InspectRootTransition(artifact)
	if err != nil {
		return TrustedKeyring{}, RootTransitionPayload{}, err
	}
	var oldPublic ed25519.PublicKey
	for _, root := range k.Roots {
		if root.KeyID == inspection.Payload.OldRootKeyID && (root.Status == "active" || root.Status == "overlap") {
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(root.PublicKey)
			if decodeErr == nil && len(decoded) == ed25519.PublicKeySize {
				oldPublic = ed25519.PublicKey(decoded)
			}
			break
		}
	}
	if oldPublic == nil {
		return TrustedKeyring{}, RootTransitionPayload{}, ErrUntrustedRoot
	}
	p, err := VerifyRootTransition(oldPublic, artifact, now)
	if err != nil {
		return TrustedKeyring{}, RootTransitionPayload{}, err
	}
	out := TrustedKeyring{SchemaVersion: 1, Roots: append([]TrustedRoot(nil), k.Roots...)}
	foundNew := false
	for i := range out.Roots {
		switch out.Roots[i].KeyID {
		case p.OldRootKeyID:
			cutoff := p.OverlapUntil
			out.Roots[i].AcceptCertificatesBefore = &cutoff
			out.Roots[i].Status = "legacy"
		case p.NewRootKeyID:
			if out.Roots[i].PublicKey != p.NewRootPublicKey {
				return TrustedKeyring{}, RootTransitionPayload{}, ErrUntrustedRoot
			}
			start := p.NotBefore
			out.Roots[i].AcceptCertificatesNotBefore = &start
			out.Roots[i].Status = "active"
			foundNew = true
		}
	}
	if !foundNew {
		start := p.NotBefore
		out.Roots = append(out.Roots, TrustedRoot{KeyID: p.NewRootKeyID, Algorithm: "Ed25519", PublicKey: p.NewRootPublicKey, Status: "active", AcceptCertificatesNotBefore: &start})
	}
	return out, p, nil
}

func VerifyIssuerCertificateKeyring(keyring TrustedKeyring, certificate string) (IssuerCertificatePayload, TrustedRoot, error) {
	var empty IssuerCertificatePayload
	for _, root := range keyring.Roots {
		if root.Status == "compromised" || root.Status == "retired" {
			continue
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(root.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize || root.KeyID != RootKeyID(ed25519.PublicKey(publicKey)) || root.Algorithm != "Ed25519" {
			continue
		}
		payload, err := VerifyIssuerCertificate(ed25519.PublicKey(publicKey), certificate)
		if err != nil {
			continue
		}
		if root.AcceptCertificatesNotBefore != nil && payload.AuthorityNotBefore.Before(*root.AcceptCertificatesNotBefore) {
			return empty, TrustedRoot{}, ErrUntrustedRoot
		}
		if root.AcceptCertificatesBefore != nil && !payload.AuthorityNotBefore.Before(*root.AcceptCertificatesBefore) {
			return empty, TrustedRoot{}, ErrUntrustedRoot
		}
		return payload, root, nil
	}
	return empty, TrustedRoot{}, ErrUntrustedRoot
}

func validateRootTransitionPayload(p RootTransitionPayload) error {
	oldPublic, oldErr := base64.RawURLEncoding.DecodeString(p.OldRootPublicKey)
	newPublic, newErr := base64.RawURLEncoding.DecodeString(p.NewRootPublicKey)
	if p.SchemaVersion != 1 || p.Algorithm != "Ed25519" || p.TransitionID == "" || len(p.TransitionID) > 128 || strings.ContainsAny(p.TransitionID, ".\r\n") ||
		strings.TrimSpace(p.Reason) == "" || len(p.Reason) > 512 || oldErr != nil || newErr != nil || len(oldPublic) != ed25519.PublicKeySize || len(newPublic) != ed25519.PublicKeySize ||
		p.OldRootKeyID != RootKeyID(ed25519.PublicKey(oldPublic)) || p.NewRootKeyID != RootKeyID(ed25519.PublicKey(newPublic)) || p.OldRootKeyID == p.NewRootKeyID ||
		p.CreatedAt.IsZero() || p.NotBefore.Before(p.CreatedAt) || !p.NotBefore.Before(p.OverlapUntil) || p.ExpiresAt.Before(p.OverlapUntil) || p.ExpiresAt.Equal(p.OverlapUntil) {
		return fmt.Errorf("%w: invalid root transition payload", ErrMalformed)
	}
	return nil
}
