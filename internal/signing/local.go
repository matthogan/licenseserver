package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/matthogan/licenceserver/internal/licencefmt"
)

type Local struct {
	keyID              string
	private            ed25519.PrivateKey
	certificate        string
	certificatePayload licencefmt.IssuerCertificatePayload
}

func Load(privateKeyFile, certificateFile string) (*Local, error) {
	certRaw, err := os.ReadFile(certificateFile)
	if err != nil {
		return nil, fmt.Errorf("read issuer certificate: %w", err)
	}
	return LoadCertificate(privateKeyFile, string(certRaw))
}

// LoadCertificate loads private key material from a protected local file and
// binds it to a persisted public issuer certificate.
func LoadCertificate(privateKeyFile, certificate string) (*Local, error) {
	keyRaw, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read issuer key: %w", err)
	}
	key, err := decodeKey(keyRaw, ed25519.PrivateKeySize)
	if err != nil {
		return nil, fmt.Errorf("decode issuer key: %w", err)
	}
	cert := strings.TrimSpace(certificate)
	// The key ID is authenticated by the root during client verification; extracting it here avoids requiring the root online.
	parts := strings.Split(cert, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed issuer certificate")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var cp licencefmt.IssuerCertificatePayload
	if err := jsonUnmarshal(payload, &cp); err != nil {
		return nil, err
	}
	if !ed25519.PublicKey(key[32:]).Equal(mustDecodePublic(cp.PublicKey)) {
		return nil, errors.New("issuer private key does not match certificate")
	}
	return &Local{keyID: cp.IssuerKeyID, private: ed25519.PrivateKey(key), certificate: cert, certificatePayload: cp}, nil
}

func (l *Local) KeyID() string                                           { return l.keyID }
func (l *Local) Algorithm() string                                       { return "Ed25519" }
func (l *Local) Certificate() string                                     { return l.certificate }
func (l *Local) CertificatePayload() licencefmt.IssuerCertificatePayload { return l.certificatePayload }
func (l *Local) PrivateKey() ed25519.PrivateKey                          { return l.private }
func (l *Local) PublicKey() []byte {
	return append([]byte(nil), l.private.Public().(ed25519.PublicKey)...)
}
func (l *Local) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(l.private, message), nil
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func WriteKey(path string, key []byte, mode os.FileMode) error {
	return os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(key)+"\n"), mode)
}

func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := decodeKey(b, ed25519.PublicKeySize)
	return ed25519.PublicKey(k), err
}

func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := decodeKey(b, ed25519.PrivateKeySize)
	return ed25519.PrivateKey(k), err
}

func decodeKey(raw []byte, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("expected base64url key containing %d bytes", size)
	}
	return b, nil
}

func mustDecodePublic(s string) ed25519.PublicKey {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return ed25519.PublicKey(b)
}
