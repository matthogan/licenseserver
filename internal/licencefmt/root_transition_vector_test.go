package licencefmt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPublishedRootTransitionVectors(t *testing.T) {
	var vector struct {
		SchemaVersion             int               `json:"schema_version"`
		OldRootPublicKey          string            `json:"old_root_public_key"`
		TransitionArtifact        string            `json:"transition_artifact"`
		InvalidTransitionArtifact string            `json:"invalid_transition_artifact"`
		NotBefore                 time.Time         `json:"not_before"`
		ExpiresAt                 time.Time         `json:"expires_at"`
		LicenceArtifacts          map[string]string `json:"licence_artifacts"`
		Cases                     []struct {
			Name              string    `json:"name"`
			At                time.Time `json:"at"`
			Artifact          string    `json:"artifact"`
			TransitionApplied bool      `json:"transition_applied"`
			Valid             bool      `json:"valid"`
			Error             string    `json:"error"`
		} `json:"cases"`
	}
	raw, err := os.ReadFile("../../docs/root-transition-test-vectors-v1.json")
	if err != nil || json.Unmarshal(raw, &vector) != nil || vector.SchemaVersion != 1 {
		t.Fatalf("load published vector: %v", err)
	}
	oldPublic, err := base64.RawURLEncoding.DecodeString(vector.OldRootPublicKey)
	if err != nil || len(oldPublic) != ed25519.PublicKeySize {
		t.Fatal("invalid vector old root")
	}
	fixed := NewFixedKeyring(ed25519.PublicKey(oldPublic))
	applied, _, err := fixed.ApplyRootTransition(vector.TransitionArtifact, vector.NotBefore)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range vector.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if test.Artifact == "" {
				var transitionErr error
				if test.Name == "expired_transition_install" {
					_, transitionErr = VerifyRootTransition(ed25519.PublicKey(oldPublic), vector.TransitionArtifact, test.At)
					if !errors.Is(transitionErr, ErrTransitionExpired) {
						t.Fatalf("error=%v", transitionErr)
					}
				} else {
					_, transitionErr = VerifyRootTransition(ed25519.PublicKey(oldPublic), vector.InvalidTransitionArtifact, test.At)
					if !errors.Is(transitionErr, ErrSignature) {
						t.Fatalf("error=%v", transitionErr)
					}
				}
				return
			}
			keyring := fixed
			if test.TransitionApplied {
				keyring = applied
			}
			_, verifyErr := VerifyArtifactKeyring(keyring, []byte(vector.LicenceArtifacts[test.Artifact]), "com.example.rotation", test.At)
			if test.Valid && verifyErr != nil {
				t.Fatalf("valid vector rejected: %v", verifyErr)
			}
			if !test.Valid && verifyErr == nil {
				t.Fatal("invalid vector accepted")
			}
			if test.Error == ErrUntrustedRoot.Error() && !errors.Is(verifyErr, ErrUntrustedRoot) {
				t.Fatalf("expected untrusted root, got %v", verifyErr)
			}
		})
	}
}
