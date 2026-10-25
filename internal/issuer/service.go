package issuer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/rootkey"
	"github.com/matthogan/licenceserver/internal/signing"
)

type Service struct {
	repo        domain.Repository
	signers     *signing.Manager
	root        ed25519.PublicKey
	keyDir      string
	now         func() time.Time
	provider    string
	kmsRegion   string
	kmsEndpoint string
}

type LocalFiles struct {
	PrivateKeyFile  string `json:"private_key_file"`
	CertificateFile string `json:"certificate_file"`
	Replaces        string `json:"replaces,omitempty"`
}

func New(repo domain.Repository, signers *signing.Manager, root ed25519.PublicKey, keyDirectory string) (*Service, error) {
	if len(root) != ed25519.PublicKeySize {
		return nil, errors.New("trusted root public key is required for issuer lifecycle")
	}
	abs, err := filepath.Abs(keyDirectory)
	if err != nil {
		return nil, err
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve signer key directory: %w", err)
	}
	return &Service{repo: repo, signers: signers, root: append(ed25519.PublicKey(nil), root...), keyDir: abs, provider: "file", now: func() time.Time { return time.Now().UTC() }}, nil
}

func NewWithKMS(repo domain.Repository, signers *signing.Manager, root ed25519.PublicKey, certificateDirectory, region, endpoint string) (*Service, error) {
	s, err := New(repo, signers, root, certificateDirectory)
	if err != nil {
		return nil, err
	}
	s.provider, s.kmsRegion, s.kmsEndpoint = "aws-kms", region, endpoint
	return s, nil
}

// Initialize restores the active signer from the registry. On a new database,
// it bootstraps the configured signer as the first active issuer.
func (s *Service) Initialize(ctx context.Context, privateKeyFile, certificateFile string) error {
	key, err := s.repo.GetActiveIssuer(ctx)
	if err == nil {
		privateRef := key.PrivateKeyRef
		local, loadErr := s.loadSigner(ctx, privateRef, key.IssuerCertificate)
		if loadErr != nil {
			return fmt.Errorf("load registered active issuer %s: %w", key.IssuerKeyID, loadErr)
		}
		validated, loadErr := s.record(ctx, local, privateRef, key.RegisteredAt, domain.IssuerStatusActive)
		if loadErr != nil {
			return fmt.Errorf("validate registered active issuer %s: %w", key.IssuerKeyID, loadErr)
		}
		if validated.IssuerKeyID != key.IssuerKeyID || !ed25519.PublicKey(validated.PublicKey).Equal(ed25519.PublicKey(key.PublicKey)) {
			return fmt.Errorf("registered active issuer %s metadata does not match its certificate", key.IssuerKeyID)
		}
		return s.signers.Transition(local, func() error { return nil })
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	privateRef := privateKeyFile
	if s.provider == "file" {
		privateRef, err = s.resolveProtectedFile(privateKeyFile, "issuer private key")
		if err != nil {
			return err
		}
	}
	certRef, err := s.resolveProtectedFile(certificateFile, "issuer certificate")
	if err != nil {
		return err
	}
	certRaw, err := os.ReadFile(certRef)
	if err != nil {
		return err
	}
	local, err := s.loadSigner(ctx, privateRef, string(certRaw))
	if err != nil {
		return err
	}
	now := s.now()
	rec, err := s.record(ctx, local, privateRef, now, domain.IssuerStatusActive)
	if err != nil {
		return err
	}
	rec.ActivatedAt = &now
	audit := newAudit("issuer_key.activated", rec.IssuerKeyID, "bootstrap", "", map[string]any{"issuer_key_id": rec.IssuerKeyID, "source": "configuration"}, now)
	return s.signers.Transition(local, func() error { return s.repo.RegisterIssuer(ctx, rec, audit) })
}

func (s *Service) Register(ctx context.Context, files LocalFiles, actor, requestID string) (domain.IssuerKey, error) {
	_, rec, err := s.loadCandidate(ctx, files, domain.IssuerStatusStaged)
	if err != nil {
		return rec, err
	}
	audit := newAudit("issuer_key.registered", rec.IssuerKeyID, actor, requestID, publicEvent(rec, "registered"), rec.RegisteredAt)
	err = s.signers.Mutate(func(signing.Signer) error { return s.repo.RegisterIssuer(ctx, rec, audit) }, func(active signing.Signer) signing.Signer { return active })
	return decorate(rec), err
}

func (s *Service) Rotate(ctx context.Context, files LocalFiles, actor, requestID string) (domain.IssuerKey, error) {
	local, rec, err := s.loadCandidate(ctx, files, domain.IssuerStatusStaged)
	if err != nil {
		return rec, err
	}
	if rec.RegisteredAt.Before(rec.AuthorityNotBefore) || rec.RegisteredAt.After(rec.AuthorityNotAfter) {
		return rec, fmt.Errorf("%w: issuer authority does not include current time", domain.ErrInvalid)
	}
	err = s.signers.Mutate(func(current signing.Signer) error {
		if files.Replaces != "" && current != nil {
			return fmt.Errorf("%w: recovery rotation requires issuance to be stopped first", domain.ErrConflict)
		}
		events := []domain.AuditEvent{newAudit("issuer_key.registered", rec.IssuerKeyID, actor, requestID, publicEvent(rec, "registered"), rec.RegisteredAt)}
		if current != nil && current.KeyID() != rec.IssuerKeyID {
			events = append(events, newAudit("issuer_key.retired", current.KeyID(), actor, requestID, map[string]string{"issuer_key_id": current.KeyID(), "reason": "superseded by rotation", "replacement": rec.IssuerKeyID}, rec.RegisteredAt))
		}
		eventType := "issuer_key.activated"
		if files.Replaces != "" {
			eventType = "issuer_key.recovered"
		}
		events = append(events, newAudit(eventType, rec.IssuerKeyID, actor, requestID, map[string]string{"issuer_key_id": rec.IssuerKeyID, "replaces": files.Replaces}, rec.RegisteredAt))
		return s.repo.RotateIssuer(ctx, rec, files.Replaces, events)
	}, func(signing.Signer) signing.Signer { return local })
	if err != nil {
		return rec, err
	}
	return decorate(s.mustGet(ctx, rec.IssuerKeyID)), nil
}

func (s *Service) Activate(ctx context.Context, id, actor, requestID string) (domain.IssuerKey, error) {
	rec, err := s.repo.GetIssuer(ctx, id)
	if err != nil {
		return rec, err
	}
	privateRef := rec.PrivateKeyRef
	local, err := s.loadSigner(ctx, privateRef, rec.IssuerCertificate)
	if err != nil {
		return rec, err
	}
	if _, err = s.record(ctx, local, privateRef, rec.RegisteredAt, rec.Status); err != nil {
		return rec, err
	}
	now := s.now()
	if now.Before(rec.AuthorityNotBefore) || now.After(rec.AuthorityNotAfter) {
		return rec, fmt.Errorf("%w: issuer authority does not include current time", domain.ErrInvalid)
	}
	err = s.signers.Mutate(func(current signing.Signer) error {
		events := make([]domain.AuditEvent, 0, 2)
		if current != nil && current.KeyID() != id {
			events = append(events, newAudit("issuer_key.retired", current.KeyID(), actor, requestID, map[string]string{"issuer_key_id": current.KeyID(), "reason": "superseded by activation", "replacement": id}, now))
		}
		events = append(events, newAudit("issuer_key.activated", id, actor, requestID, map[string]string{"issuer_key_id": id}, now))
		return s.repo.ActivateIssuer(ctx, id, events)
	}, func(signing.Signer) signing.Signer { return local })
	if err != nil {
		return rec, err
	}
	return decorate(s.mustGet(ctx, id)), nil
}

func (s *Service) SetStatus(ctx context.Context, id, status, reason string, allowNoActive bool, actor, requestID string) (domain.IssuerKey, error) {
	if status != domain.IssuerStatusRetired && status != domain.IssuerStatusLost && status != domain.IssuerStatusCompromised {
		return domain.IssuerKey{}, domain.ErrInvalid
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return domain.IssuerKey{}, fmt.Errorf("%w: reason is required", domain.ErrInvalid)
	}
	rec, err := s.repo.GetIssuer(ctx, id)
	if err != nil {
		return rec, err
	}
	now := s.now()
	eventType := "issuer_key." + status
	audit := newAudit(eventType, id, actor, requestID, map[string]string{"issuer_key_id": id, "previous_status": rec.Status, "reason": reason}, now)
	disable := false
	err = s.signers.Mutate(func(current signing.Signer) error {
		disable = current != nil && current.KeyID() == id
		explicit := allowNoActive
		if disable && (status == domain.IssuerStatusLost || status == domain.IssuerStatusCompromised) {
			explicit = true
		}
		return s.repo.SetIssuerStatus(ctx, id, status, reason, explicit, audit)
	}, func(current signing.Signer) signing.Signer {
		if disable {
			return nil
		}
		return current
	})
	if err != nil {
		return rec, err
	}
	return decorate(s.mustGet(ctx, id)), nil
}

func (s *Service) List(ctx context.Context) ([]domain.IssuerKey, error) {
	keys, err := s.repo.ListIssuers(ctx)
	for i := range keys {
		keys[i] = decorate(keys[i])
	}
	return keys, err
}

func (s *Service) Get(ctx context.Context, id string) (domain.IssuerKey, error) {
	key, err := s.repo.GetIssuer(ctx, id)
	return decorate(key), err
}

func (s *Service) loadCandidate(ctx context.Context, files LocalFiles, status string) (signing.Signer, domain.IssuerKey, error) {
	privateRef := files.PrivateKeyFile
	var err error
	if s.provider == "file" {
		privateRef, err = s.resolveProtectedFile(files.PrivateKeyFile, "issuer private key")
		if err != nil {
			return nil, domain.IssuerKey{}, err
		}
	}
	certRef, err := s.resolveProtectedFile(files.CertificateFile, "issuer certificate")
	if err != nil {
		return nil, domain.IssuerKey{}, err
	}
	certRaw, err := os.ReadFile(certRef)
	if err != nil {
		return nil, domain.IssuerKey{}, err
	}
	local, err := s.loadSigner(ctx, privateRef, string(certRaw))
	if err != nil {
		return nil, domain.IssuerKey{}, err
	}
	rec, err := s.record(ctx, local, privateRef, s.now(), status)
	return local, rec, err
}

func (s *Service) loadSigner(ctx context.Context, privateRef, certificate string) (signing.Signer, error) {
	if s.provider == "aws-kms" {
		return signing.LoadKMS(ctx, privateRef, s.kmsRegion, s.kmsEndpoint, certificate)
	}
	resolved, err := s.resolveProtectedFile(privateRef, "issuer private key")
	if err != nil {
		return nil, err
	}
	return signing.LoadCertificate(resolved, certificate)
}

func (s *Service) record(ctx context.Context, local signing.Signer, privateRef string, registered time.Time, status string) (domain.IssuerKey, error) {
	payload, err := s.verifyIssuerCertificate(ctx, local.Certificate())
	if err != nil {
		return domain.IssuerKey{}, fmt.Errorf("issuer certificate is not authenticated by trusted root keyring: %w", err)
	}
	if len(payload.Products) == 0 {
		return domain.IssuerKey{}, errors.New("issuer certificate authorises no products")
	}
	if !ed25519.PublicKey(local.PublicKey()).Equal(ed25519.PublicKey(mustDecode(payload.PublicKey))) {
		return domain.IssuerKey{}, errors.New("issuer public metadata does not match private key")
	}
	return domain.IssuerKey{IssuerKeyID: payload.IssuerKeyID, Algorithm: payload.Algorithm, PublicKey: local.PublicKey(), IssuerCertificate: local.Certificate(), AuthorityNotBefore: payload.AuthorityNotBefore, AuthorityNotAfter: payload.AuthorityNotAfter, Products: append([]string(nil), payload.Products...), Status: status, PrivateKeyRef: privateRef, RegisteredAt: registered}, nil
}

func (s *Service) verifyIssuerCertificate(ctx context.Context, certificate string) (licencefmt.IssuerCertificatePayload, error) {
	roots, err := s.repo.ListRootKeys(ctx)
	if err != nil {
		return licencefmt.IssuerCertificatePayload{}, err
	}
	if len(roots) > 0 {
		if verifyErr := rootkey.VerifyIssuanceCertificate(ctx, s.repo, certificate, s.now()); verifyErr != nil {
			return licencefmt.IssuerCertificatePayload{}, verifyErr
		}
		payload, _, verifyErr := licencefmt.VerifyIssuerCertificateKeyring(rootkey.KeyringFromRoots(roots), certificate)
		return payload, verifyErr
	}
	return licencefmt.VerifyIssuerCertificate(s.root, certificate)
}

func (s *Service) resolveProtectedFile(path, label string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s path is required", label)
	}
	if !filepath.IsAbs(path) {
		direct, absErr := filepath.Abs(path)
		if absErr != nil {
			return "", absErr
		}
		if rel, relErr := filepath.Rel(s.keyDir, direct); relErr == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = direct
		} else {
			path = filepath.Join(s.keyDir, path)
		}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", label, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(s.keyDir, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s must be inside signer.key_directory", domain.ErrInvalid, label)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file", label)
	}
	if runtime.GOOS != "windows" && strings.Contains(label, "private") && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s permissions must not grant group or other access", label)
	}
	return resolved, nil
}

func (s *Service) mustGet(ctx context.Context, id string) domain.IssuerKey {
	key, _ := s.repo.GetIssuer(ctx, id)
	return key
}

func decorate(key domain.IssuerKey) domain.IssuerKey {
	if len(key.PublicKey) > 0 {
		sum := sha256.Sum256(key.PublicKey)
		key.Fingerprint = strings.ToUpper(hex.EncodeToString(sum[:8]))
	}
	return key
}

func publicEvent(key domain.IssuerKey, action string) map[string]any {
	return map[string]any{"issuer_key_id": key.IssuerKeyID, "fingerprint": decorate(key).Fingerprint, "authority_not_before": key.AuthorityNotBefore, "authority_not_after": key.AuthorityNotAfter, "products": key.Products, "action": action}
}

func newAudit(eventType, id, actor, requestID string, event any, now time.Time) domain.AuditEvent {
	if actor == "" {
		actor = "local-admin"
	}
	b, _ := json.Marshal(event)
	return domain.AuditEvent{EventID: "evt_" + strings.ReplaceAll(uuid.NewString(), "-", ""), OccurredAt: now, ActorType: actor, EventType: eventType, AggregateType: "issuer_key", AggregateID: id, RequestID: requestID, Event: b}
}

func mustDecode(encoded string) []byte {
	decoded, _ := base64.RawURLEncoding.DecodeString(encoded)
	return decoded
}
