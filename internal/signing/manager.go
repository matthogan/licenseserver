package signing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
)

var ErrNoActiveIssuer = errors.New("no active issuer is available")
var ErrSignerUnavailable = errors.New("signer unavailable")

type SignedLicence struct {
	Envelope     string
	PayloadBytes []byte
	Certificate  string
	IssuerKeyID  string
}

func (m *Manager) SignStatus(ctx context.Context, payload domain.LicenceStatusPayload, now time.Time) (domain.SignedLicenceStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return domain.SignedLicenceStatus{}, ErrNoActiveIssuer
	}
	cert := m.active.CertificatePayload()
	if now.Before(cert.AuthorityNotBefore) || now.After(cert.AuthorityNotAfter) {
		return domain.SignedLicenceStatus{}, fmt.Errorf("%w: authority window does not include current time", ErrSignerUnavailable)
	}
	if m.certificateAuthority != nil {
		if err := m.certificateAuthority(ctx, m.active.Certificate(), now); err != nil {
			return domain.SignedLicenceStatus{}, fmt.Errorf("%w: %v", ErrSignerUnavailable, err)
		}
	}
	if payload.ValidUntil.After(cert.AuthorityNotAfter) {
		payload.ValidUntil = cert.AuthorityNotAfter
	}
	if !payload.CheckedAt.Before(payload.ValidUntil) {
		return domain.SignedLicenceStatus{}, fmt.Errorf("%w: issuer authority expires before the status response", ErrSignerUnavailable)
	}
	input, _, err := licencefmt.StatusSigningInput(m.active.KeyID(), payload)
	if err != nil {
		return domain.SignedLicenceStatus{}, err
	}
	if len(input) > 4096 {
		return domain.SignedLicenceStatus{}, domain.ErrPayloadTooLarge
	}
	sig, err := m.active.Sign(ctx, []byte(input))
	if err != nil {
		return domain.SignedLicenceStatus{}, fmt.Errorf("%w: %v", ErrSignerUnavailable, err)
	}
	return domain.SignedLicenceStatus{SchemaVersion: 1, Payload: payload, IssuerKeyID: m.active.KeyID(), Signature: base64.RawURLEncoding.EncodeToString(sig), IssuerCertificate: m.active.Certificate()}, nil
}

type Signer interface {
	KeyID() string
	Algorithm() string
	Certificate() string
	CertificatePayload() licencefmt.IssuerCertificatePayload
	PublicKey() []byte
	Sign(context.Context, []byte) ([]byte, error)
}

// Manager serializes lifecycle transitions against issuance. Once a
// transition commits, no later issuance can use the previous signer.
type Manager struct {
	mu                   sync.RWMutex
	active               Signer
	certificateAuthority func(context.Context, string, time.Time) error
}

func NewManager(active Signer) *Manager { return &Manager{active: active} }

func (m *Manager) Sign(ctx context.Context, payload domain.LicencePayload, now time.Time) (SignedLicence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return SignedLicence{}, ErrNoActiveIssuer
	}
	cert := m.active.CertificatePayload()
	if now.Before(cert.AuthorityNotBefore) || now.After(cert.AuthorityNotAfter) {
		return SignedLicence{}, fmt.Errorf("%w: authority window does not include current time", ErrSignerUnavailable)
	}
	if m.certificateAuthority != nil {
		if err := m.certificateAuthority(ctx, m.active.Certificate(), now); err != nil {
			return SignedLicence{}, fmt.Errorf("%w: %v", ErrSignerUnavailable, err)
		}
	}
	input, encoded, payloadBytes, err := licencefmt.PayloadSigningInput(m.active.KeyID(), payload)
	if err != nil {
		return SignedLicence{}, err
	}
	if len(input) > 4096 {
		return SignedLicence{}, domain.ErrPayloadTooLarge
	}
	signature, err := m.active.Sign(ctx, []byte(input))
	if err != nil {
		return SignedLicence{}, fmt.Errorf("%w: %v", ErrSignerUnavailable, err)
	}
	envelope := licencefmt.AssembleEnvelope(m.active.KeyID(), encoded, signature)
	return SignedLicence{Envelope: envelope, PayloadBytes: payloadBytes, Certificate: m.active.Certificate(), IssuerKeyID: m.active.KeyID()}, nil
}

// Transition holds the exclusive issuance lock while durable state changes.
// The in-memory signer is replaced only after persist succeeds.
func (m *Manager) Transition(next Signer, persist func() error) error {
	return m.Mutate(func(Signer) error { return persist() }, func(Signer) Signer { return next })
}

// Mutate serializes any issuer metadata change against signing and optionally
// changes the active signer after the durable mutation succeeds.
func (m *Manager) Mutate(persist func(Signer) error, update func(Signer) Signer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := persist(m.active); err != nil {
		return err
	}
	m.active = update(m.active)
	return nil
}

func (m *Manager) Current() (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return "", false
	}
	return m.active.KeyID(), true
}

func (m *Manager) SetCertificateAuthorityCheck(check func(context.Context, string, time.Time) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.certificateAuthority = check
}

func (m *Manager) Healthy(now time.Time) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active == nil {
		return ErrNoActiveIssuer
	}
	cert := m.active.CertificatePayload()
	if now.Before(cert.AuthorityNotBefore) || now.After(cert.AuthorityNotAfter) {
		return errors.New("active issuer is outside its authority window")
	}
	if m.certificateAuthority != nil {
		if err := m.certificateAuthority(context.Background(), m.active.Certificate(), now); err != nil {
			return err
		}
	}
	return nil
}
