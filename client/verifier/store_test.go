package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestKeyringStoreApplyReloadRollbackAndCompromise(t *testing.T) {
	vector := loadTransitionVector(t)
	clockTime := vector.NotBefore.Add(3 * time.Hour)
	clock := ClockFunc(func() time.Time { return clockTime })
	path := filepath.Join(t.TempDir(), "state", "keyring.json")
	store, err := OpenKeyringStore(path, []byte(vector.OldRootPublicKey), StoreOptions{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	if store.Snapshot().Revision != 1 {
		t.Fatal("bootstrap revision was not persisted")
	}
	transition, err := store.ApplyTransition(vector.TransitionArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if store.Snapshot().Revision != 2 {
		t.Fatal("apply was not atomic revision two")
	}
	reopened, err := OpenKeyringStore(path, []byte(vector.OldRootPublicKey), StoreOptions{Clock: clock})
	if err != nil {
		t.Fatalf("reopen applied keyring: %v", err)
	}
	client, err := reopened.Verifier(Options{ProductID: "com.example.rotation"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.VerifyLicence([]byte(vector.LicenceArtifacts["overlap_new"])); err != nil {
		t.Fatalf("new-root licence after reopen: %v", err)
	}
	if err = reopened.RollbackTransition(transition.TransitionID, "new root rollout fault", true); err != nil {
		t.Fatal(err)
	}
	rolled := reopened.Snapshot()
	if rolled.Revision != 3 || rootStatus(rolled, transition.NewRootKeyID) != RootCompromised || rootStatus(rolled, transition.OldRootKeyID) != RootActive {
		t.Fatalf("unexpected rollback state: %+v", rolled)
	}
	if err = reopened.MarkCompromised(transition.OldRootKeyID, "old root incident"); err != nil {
		t.Fatal(err)
	}
	failedClosed, _ := reopened.Verifier(Options{ProductID: "com.example.rotation"})
	_, err = failedClosed.VerifyLicence([]byte(vector.LicenceArtifacts["overlap_old"]))
	assertCode(t, err, CodeUntrustedRoot)
}

func TestStoreRejectsTamperedAndOversizedStateWithoutSwap(t *testing.T) {
	vector := loadTransitionVector(t)
	path := filepath.Join(t.TempDir(), "keyring.json")
	store, err := OpenKeyringStore(path, []byte(vector.OldRootPublicKey), StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	original := store.Snapshot()
	if err = os.WriteFile(path, []byte(`{"schema_version":1,"revision":99,"roots":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = store.Reload(); err == nil {
		t.Fatal("tampered keyring was accepted")
	}
	if store.Snapshot().Revision != original.Revision || len(store.Snapshot().Roots) != 1 {
		t.Fatal("failed reload changed live snapshot")
	}
}

func TestStrictLimitsAndTypedErrors(t *testing.T) {
	root := make([]byte, ed25519.PublicKeySize)
	keyring, _ := NewKeyring(ed25519.PublicKey(root))
	duplicate := []byte(`{"schema_version":1,"schema_version":1,"envelope":"x","issuer_certificate":"x"}`)
	_, err := VerifyLicence(keyring, duplicate, "product", time.Unix(0, 0))
	assertCode(t, err, CodeMalformed)
	unknown := []byte(`{"schema_version":1,"envelope":"x","issuer_certificate":"x","surprise":true}`)
	_, err = VerifyLicence(keyring, unknown, "product", time.Unix(0, 0))
	assertCode(t, err, CodeMalformed)
	oversized := make([]byte, MaxArtifactBytes+1)
	_, err = VerifyLicence(keyring, oversized, "product", time.Unix(0, 0))
	assertCode(t, err, CodeTooLarge)
	invalidUTF8 := []byte{'{', '"', 0xff, '"', ':', '1', '}'}
	_, err = VerifyLicence(keyring, invalidUTF8, "product", time.Unix(0, 0))
	assertCode(t, err, CodeMalformed)
}

func TestConcurrentSnapshotsRemainComplete(t *testing.T) {
	vector := loadTransitionVector(t)
	clock := ClockFunc(func() time.Time { return vector.NotBefore.Add(time.Hour) })
	store, err := OpenKeyringStore(filepath.Join(t.TempDir(), "keyring.json"), []byte(vector.OldRootPublicKey), StoreOptions{Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for count := 0; count < 100; count++ {
				snapshot := store.Snapshot()
				if len(snapshot.Roots) != 1 && len(snapshot.Roots) != 2 {
					t.Errorf("partial snapshot: %+v", snapshot)
				}
			}
		}()
	}
	if _, err = store.ApplyTransition(vector.TransitionArtifact); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
}

func TestSignedStatusStableAPI(t *testing.T) {
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(rand.Reader)
	issuerPublic, issuerPrivate, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	certificatePayload := IssuerCertificate{SchemaVersion: 1, IssuerKeyID: "status-issuer", Algorithm: "Ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic), AuthorityNotBefore: now.Add(-time.Hour), AuthorityNotAfter: now.Add(time.Hour), Products: []string{"product"}}
	certificateJSON, _ := json.Marshal(certificatePayload)
	certificateEncoded := base64.RawURLEncoding.EncodeToString(certificateJSON)
	certificateSignature := ed25519.Sign(rootPrivate, []byte(issuerContext+certificateEncoded))
	certificate := issuerPrefix + "." + certificateEncoded + "." + base64.RawURLEncoding.EncodeToString(certificateSignature)
	payload := Status{SchemaVersion: 1, LicenceID: "licence", ProductID: "product", Status: "active", CheckedAt: now, ValidUntil: now.Add(time.Minute), Nonce: "random-nonce"}
	payloadJSON, _ := json.Marshal(payload)
	input := statusContext + "status-issuer\n" + base64.RawURLEncoding.EncodeToString(payloadJSON)
	statement := SignedStatus{SchemaVersion: 1, Payload: payload, IssuerKeyID: "status-issuer", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerPrivate, []byte(input))), IssuerCertificate: certificate}
	raw, _ := json.Marshal(statement)
	keyring, _ := NewKeyring(rootPublic)
	verified, err := VerifySignedStatus(keyring, raw, StatusRequest{LicenceID: "licence", ProductID: "product", Nonce: "random-nonce"}, now, 0)
	if err != nil || verified.Status != "active" {
		t.Fatalf("status verification: %+v %v", verified, err)
	}
	statement.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	raw, _ = json.Marshal(statement)
	_, err = VerifySignedStatus(keyring, raw, StatusRequest{LicenceID: "licence", ProductID: "product", Nonce: "random-nonce"}, now, 0)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("typed status signature error: %v", err)
	}
}

func rootStatus(keyring Keyring, keyID string) RootStatus {
	for _, root := range keyring.Roots {
		if root.KeyID == keyID {
			return root.Status
		}
	}
	return ""
}

func FuzzStrictLicenceParser(f *testing.F) {
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"schema_version":1,"schema_version":1}`))
	root := make([]byte, ed25519.PublicKeySize)
	keyring, _ := NewKeyring(ed25519.PublicKey(root))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > MaxArtifactBytes+1 {
			t.Skip()
		}
		_, _ = VerifyLicence(keyring, raw, "product", time.Unix(0, 0))
	})
}
