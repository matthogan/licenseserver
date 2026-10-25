package rootkey

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/signing"
)

type Service struct {
	repo    domain.Repository
	signers *signing.Manager
	now     func() time.Time
}

func New(repo domain.Repository, signers *signing.Manager) *Service {
	return &Service{repo: repo, signers: signers, now: func() time.Time { return time.Now().UTC() }}
}

// Initialize registers the configured offline public root on a new database
// and validates every persisted transition as a signature chain from it.
func (s *Service) Initialize(ctx context.Context, configured ed25519.PublicKey) error {
	if len(configured) != ed25519.PublicKeySize {
		return errors.New("configured root public key is invalid")
	}
	now := s.now()
	root := makeRoot(configured, domain.RootStatusActive, "configuration bootstrap", "", now, nil)
	audit := newAudit("root_key.bootstrapped", root.RootKeyID, "system", "", map[string]any{"root_key_id": root.RootKeyID, "fingerprint": root.Fingerprint, "source": "configuration"}, now)
	if err := s.repo.EnsureRootKey(ctx, root, audit); err != nil {
		return err
	}
	if err := s.validateChain(ctx, configured); err != nil {
		return err
	}
	if s.signers != nil {
		s.signers.SetCertificateAuthorityCheck(func(checkCtx context.Context, certificate string, at time.Time) error {
			return VerifyIssuanceCertificate(checkCtx, s.repo, certificate, at)
		})
	}
	return nil
}

func (s *Service) Activate(ctx context.Context, artifact, actor, requestID string) (domain.RootTransition, error) {
	artifact = strings.TrimSpace(artifact)
	roots, err := s.repo.ListRootKeys(ctx)
	if err != nil {
		return domain.RootTransition{}, err
	}
	if len(roots) >= 8 {
		return domain.RootTransition{}, fmt.Errorf("%w: root keyring is at its eight-root safety limit", domain.ErrInvalid)
	}
	active, err := s.repo.GetActiveRootKey(ctx)
	if err != nil {
		return domain.RootTransition{}, err
	}
	now := s.now()
	payload, err := licencefmt.VerifyRootTransition(ed25519.PublicKey(active.PublicKey), artifact, now)
	if err != nil {
		return domain.RootTransition{}, err
	}
	if payload.OldRootKeyID != active.RootKeyID {
		return domain.RootTransition{}, fmt.Errorf("%w: transition does not continue the active root", domain.ErrConflict)
	}
	newPublic, _ := base64.RawURLEncoding.DecodeString(payload.NewRootPublicKey)
	start := payload.NotBefore
	next := makeRoot(ed25519.PublicKey(newPublic), domain.RootStatusOverlap, "transition overlap", payload.TransitionID, now, &start)
	transition := domain.RootTransition{TransitionID: payload.TransitionID, OldRootKeyID: payload.OldRootKeyID, NewRootKeyID: payload.NewRootKeyID, Artifact: artifact, CreatedAt: payload.CreatedAt, NotBefore: payload.NotBefore, OverlapUntil: payload.OverlapUntil, ExpiresAt: payload.ExpiresAt, Status: domain.RootTransitionStatusActive, ActivatedAt: now}
	audits := []domain.AuditEvent{
		newAudit("root_key.registered", next.RootKeyID, actor, requestID, map[string]any{"root_key_id": next.RootKeyID, "fingerprint": next.Fingerprint, "source_transition_id": transition.TransitionID}, now),
		newAudit("root_transition.activated", transition.TransitionID, actor, requestID, map[string]any{"transition_id": transition.TransitionID, "old_root_key_id": transition.OldRootKeyID, "new_root_key_id": transition.NewRootKeyID, "not_before": transition.NotBefore, "overlap_until": transition.OverlapUntil, "expires_at": transition.ExpiresAt, "reason": payload.Reason}, now),
	}
	if err = s.repo.ActivateRootTransition(ctx, transition, next, audits); err != nil {
		return domain.RootTransition{}, err
	}
	return s.repo.GetRootTransition(ctx, transition.TransitionID)
}

func (s *Service) Retire(ctx context.Context, id, reason string, compromiseOld bool, actor, requestID string) (domain.RootTransition, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 512 {
		return domain.RootTransition{}, fmt.Errorf("%w: reason is required", domain.ErrInvalid)
	}
	transition, err := s.repo.GetRootTransition(ctx, id)
	if err != nil {
		return transition, err
	}
	now := s.now()
	if !compromiseOld && now.Before(transition.OverlapUntil) {
		return transition, fmt.Errorf("%w: overlap continues until %s", domain.ErrInvalid, transition.OverlapUntil.Format(time.RFC3339))
	}
	oldRoot, err := s.repo.GetRootKey(ctx, transition.OldRootKeyID)
	if err != nil {
		return transition, err
	}
	newRoot, err := s.repo.GetRootKey(ctx, transition.NewRootKeyID)
	if err != nil {
		return transition, err
	}
	audits := []domain.AuditEvent{
		newAudit(rootStatusEvent(oldRoot.RootKeyID, compromiseOld), oldRoot.RootKeyID, actor, requestID, map[string]any{"root_key_id": oldRoot.RootKeyID, "reason": reason, "transition_id": id}, now),
		newAudit("root_key.activated", newRoot.RootKeyID, actor, requestID, map[string]any{"root_key_id": newRoot.RootKeyID, "transition_id": id}, now),
		newAudit("root_transition.retired", id, actor, requestID, map[string]any{"transition_id": id, "reason": reason, "compromised_old": compromiseOld}, now),
	}
	persist := func(current signing.Signer) error {
		if current != nil && !compromiseOld && !certificateAuthorizedByRoot(newRoot.PublicKey, current.Certificate(), &transition.NotBefore, nil) {
			return fmt.Errorf("%w: active issuer must be certified by the new root before routine retirement", domain.ErrInvalid)
		}
		return s.repo.RetireRootTransition(ctx, id, compromiseOld, reason, now, audits)
	}
	update := func(current signing.Signer) signing.Signer {
		if compromiseOld && current != nil && certificateSignedBy(oldRoot.PublicKey, current.Certificate()) {
			return nil
		}
		return current
	}
	if s.signers != nil {
		err = s.signers.Mutate(persist, update)
	} else {
		err = persist(nil)
	}
	if err != nil {
		return transition, err
	}
	return s.repo.GetRootTransition(ctx, id)
}

func (s *Service) Rollback(ctx context.Context, id, reason string, compromiseNew bool, actor, requestID string) (domain.RootTransition, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 512 {
		return domain.RootTransition{}, fmt.Errorf("%w: reason is required", domain.ErrInvalid)
	}
	transition, err := s.repo.GetRootTransition(ctx, id)
	if err != nil {
		return transition, err
	}
	now := s.now()
	if !now.Before(transition.OverlapUntil) {
		return transition, fmt.Errorf("%w: rollback is only permitted during overlap", domain.ErrInvalid)
	}
	oldRoot, err := s.repo.GetRootKey(ctx, transition.OldRootKeyID)
	if err != nil {
		return transition, err
	}
	newRoot, err := s.repo.GetRootKey(ctx, transition.NewRootKeyID)
	if err != nil {
		return transition, err
	}
	audits := []domain.AuditEvent{
		newAudit("root_key.activated", oldRoot.RootKeyID, actor, requestID, map[string]any{"root_key_id": oldRoot.RootKeyID, "transition_id": id, "reason": "rollback"}, now),
		newAudit(rootStatusEvent(newRoot.RootKeyID, compromiseNew), newRoot.RootKeyID, actor, requestID, map[string]any{"root_key_id": newRoot.RootKeyID, "transition_id": id, "reason": reason}, now),
		newAudit("root_transition.rolled_back", id, actor, requestID, map[string]any{"transition_id": id, "reason": reason, "compromised_new": compromiseNew}, now),
	}
	persist := func(current signing.Signer) error {
		if current != nil && !compromiseNew && !certificateAuthorizedByRoot(oldRoot.PublicKey, current.Certificate(), nil, &transition.OverlapUntil) {
			return fmt.Errorf("%w: activate an old-root issuer before routine rollback", domain.ErrInvalid)
		}
		return s.repo.RollbackRootTransition(ctx, id, compromiseNew, reason, now, audits)
	}
	update := func(current signing.Signer) signing.Signer {
		if compromiseNew && current != nil && certificateSignedBy(newRoot.PublicKey, current.Certificate()) {
			return nil
		}
		return current
	}
	if s.signers != nil {
		err = s.signers.Mutate(persist, update)
	} else {
		err = persist(nil)
	}
	if err != nil {
		return transition, err
	}
	return s.repo.GetRootTransition(ctx, id)
}

func (s *Service) Keyring(ctx context.Context) (licencefmt.TrustedKeyring, error) {
	roots, err := s.repo.ListRootKeys(ctx)
	if err != nil {
		return licencefmt.TrustedKeyring{}, err
	}
	return KeyringFromRoots(roots), nil
}

func (s *Service) Healthy(ctx context.Context, now time.Time) error {
	if _, err := s.repo.GetActiveRootKey(ctx); err != nil {
		return fmt.Errorf("active root metadata: %w", err)
	}
	transitions, err := s.repo.ListRootTransitions(ctx)
	if err != nil {
		return err
	}
	for _, transition := range transitions {
		if transition.Status == domain.RootTransitionStatusActive && !now.Before(transition.OverlapUntil) {
			return fmt.Errorf("root transition %s passed overlap deadline and must be retired or handled as an incident", transition.TransitionID)
		}
	}
	return nil
}

func (s *Service) ListRoots(ctx context.Context) ([]domain.RootKey, error) {
	return s.repo.ListRootKeys(ctx)
}

func (s *Service) ListTransitions(ctx context.Context) ([]domain.RootTransition, error) {
	return s.repo.ListRootTransitions(ctx)
}

func (s *Service) GetTransition(ctx context.Context, id string) (domain.RootTransition, error) {
	return s.repo.GetRootTransition(ctx, id)
}

func KeyringFromRoots(roots []domain.RootKey) licencefmt.TrustedKeyring {
	keyring := licencefmt.TrustedKeyring{SchemaVersion: 1}
	for _, root := range roots {
		keyring.Roots = append(keyring.Roots, licencefmt.TrustedRoot{KeyID: root.RootKeyID, Algorithm: root.Algorithm, PublicKey: base64.RawURLEncoding.EncodeToString(root.PublicKey), Status: root.Status, AcceptCertificatesNotBefore: root.AcceptCertificatesNotBefore, AcceptCertificatesBefore: root.AcceptCertificatesBefore})
	}
	return keyring
}

// VerifyIssuanceCertificate applies stricter live-signing policy than client
// historical verification: legacy roots may verify old licences but may not
// authorize the online signer, and the old root stops authorizing issuance at
// the exact overlap deadline even if the administrative retirement is late.
func VerifyIssuanceCertificate(ctx context.Context, repo domain.Repository, certificate string, now time.Time) error {
	roots, err := repo.ListRootKeys(ctx)
	if err != nil {
		return err
	}
	_, trusted, err := licencefmt.VerifyIssuerCertificateKeyring(KeyringFromRoots(roots), certificate)
	if err != nil {
		return err
	}
	if trusted.Status != domain.RootStatusActive && trusted.Status != domain.RootStatusOverlap {
		return fmt.Errorf("root %s is not authorized for online issuance", trusted.KeyID)
	}
	transitions, err := repo.ListRootTransitions(ctx)
	if err != nil {
		return err
	}
	for _, transition := range transitions {
		if transition.Status == domain.RootTransitionStatusActive && transition.OldRootKeyID == trusted.KeyID && !now.Before(transition.OverlapUntil) {
			return fmt.Errorf("old root %s passed its issuance cutover", trusted.KeyID)
		}
	}
	return nil
}

func (s *Service) validateChain(ctx context.Context, configured ed25519.PublicKey) error {
	roots, err := s.repo.ListRootKeys(ctx)
	if err != nil {
		return err
	}
	transitions, err := s.repo.ListRootTransitions(ctx)
	if err != nil {
		return err
	}
	rootByID := make(map[string]domain.RootKey, len(roots))
	for _, root := range roots {
		if root.RootKeyID != licencefmt.RootKeyID(ed25519.PublicKey(root.PublicKey)) || root.Algorithm != "Ed25519" {
			return fmt.Errorf("persisted root %s has invalid identity metadata", root.RootKeyID)
		}
		rootByID[root.RootKeyID] = root
	}
	reachable := map[string]bool{licencefmt.RootKeyID(configured): true}
	remaining := append([]domain.RootTransition(nil), transitions...)
	for len(remaining) > 0 {
		progress := false
		next := remaining[:0]
		for _, transition := range remaining {
			anchorID := transition.OldRootKeyID
			if !reachable[anchorID] {
				anchorID = transition.NewRootKeyID
			}
			if !reachable[anchorID] {
				next = append(next, transition)
				continue
			}
			oldRoot, oldOK := rootByID[transition.OldRootKeyID]
			newRoot, newOK := rootByID[transition.NewRootKeyID]
			if !oldOK || !newOK {
				return fmt.Errorf("transition %s references missing root metadata", transition.TransitionID)
			}
			anchor := rootByID[anchorID]
			payload, verifyErr := licencefmt.VerifyRootTransitionFromAnchor(ed25519.PublicKey(anchor.PublicKey), transition.Artifact)
			metadataMatches := payload.TransitionID == transition.TransitionID &&
				payload.OldRootKeyID == oldRoot.RootKeyID && payload.OldRootPublicKey == base64.RawURLEncoding.EncodeToString(oldRoot.PublicKey) &&
				payload.NewRootKeyID == newRoot.RootKeyID && payload.NewRootPublicKey == base64.RawURLEncoding.EncodeToString(newRoot.PublicKey) &&
				payload.CreatedAt.Equal(transition.CreatedAt) && payload.NotBefore.Equal(transition.NotBefore) &&
				payload.OverlapUntil.Equal(transition.OverlapUntil) && payload.ExpiresAt.Equal(transition.ExpiresAt)
			if verifyErr != nil || !metadataMatches {
				if verifyErr != nil {
					return fmt.Errorf("verify persisted transition %s: %w", transition.TransitionID, verifyErr)
				}
				return fmt.Errorf("persisted transition %s metadata does not match its signed payload", transition.TransitionID)
			}
			reachable[oldRoot.RootKeyID] = true
			reachable[newRoot.RootKeyID] = true
			progress = true
		}
		if !progress {
			return errors.New("persisted root keyring is not connected to configured trust anchor")
		}
		remaining = next
	}
	for id := range rootByID {
		if !reachable[id] {
			return fmt.Errorf("persisted root %s is not connected to configured trust anchor", id)
		}
	}
	return nil
}

func makeRoot(publicKey ed25519.PublicKey, status, reason, transitionID string, now time.Time, acceptNotBefore *time.Time) domain.RootKey {
	id := licencefmt.RootKeyID(publicKey)
	fingerprint := strings.ToUpper(strings.TrimPrefix(id, "sha256:"))
	var activatedAt *time.Time
	if status == domain.RootStatusActive {
		activatedAt = &now
	}
	return domain.RootKey{RootKeyID: id, Algorithm: "Ed25519", PublicKey: append([]byte(nil), publicKey...), Fingerprint: fingerprint, Status: status, AcceptCertificatesNotBefore: acceptNotBefore, SourceTransitionID: transitionID, RegisteredAt: now, ActivatedAt: activatedAt, StateReason: reason}
}

func certificateSignedBy(root []byte, certificate string) bool {
	_, err := licencefmt.VerifyIssuerCertificate(ed25519.PublicKey(root), certificate)
	return err == nil
}

func certificateAuthorizedByRoot(root []byte, certificate string, notBefore, before *time.Time) bool {
	payload, err := licencefmt.VerifyIssuerCertificate(ed25519.PublicKey(root), certificate)
	if err != nil {
		return false
	}
	if notBefore != nil && payload.AuthorityNotBefore.Before(*notBefore) {
		return false
	}
	return before == nil || payload.AuthorityNotBefore.Before(*before)
}

func rootStatusEvent(_ string, compromised bool) string {
	if compromised {
		return "root_key.compromised"
	}
	return "root_key.retired"
}

func newAudit(eventType, id, actor, requestID string, event any, now time.Time) domain.AuditEvent {
	actorType := "administrator"
	if actor == "" {
		actor = "local-admin"
	} else if actor == "system" {
		actorType = "system"
		actor = ""
	}
	b, _ := json.Marshal(event)
	return domain.AuditEvent{EventID: "evt_" + strings.ReplaceAll(uuid.NewString(), "-", ""), OccurredAt: now, ActorType: actorType, ActorRef: actor, EventType: eventType, AggregateType: aggregateType(eventType), AggregateID: id, RequestID: requestID, Event: b}
}

func aggregateType(eventType string) string {
	if strings.HasPrefix(eventType, "root_transition.") {
		return "root_transition"
	}
	return "root_key"
}

// PublicFingerprint renders the full SHA-256 fingerprint for ceremonies.
func PublicFingerprint(publicKey ed25519.PublicKey) string {
	id := licencefmt.RootKeyID(publicKey)
	decoded, _ := hex.DecodeString(strings.TrimPrefix(id, "sha256:"))
	return strings.ToUpper(hex.EncodeToString(decoded))
}
