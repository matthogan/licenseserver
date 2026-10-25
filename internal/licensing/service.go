package licensing

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/matthogan/licenceserver/internal/domain"
	"github.com/matthogan/licenceserver/internal/failurepoint"
	"github.com/matthogan/licenceserver/internal/licencefmt"
	"github.com/matthogan/licenceserver/internal/retention"
	"github.com/matthogan/licenceserver/internal/signing"
)

type Service struct {
	repo             domain.Repository
	archive          domain.ArchiveStore
	signer           *signing.Manager
	trialPepper      []byte
	defaultTrial     time.Duration
	strictArchive    bool
	activationPepper []byte
	now              func() time.Time
}

type IssueLicenceRequest struct {
	ProductID        string            `json:"product_id"`
	LicenceType      string            `json:"licence_type"`
	CustomerRef      string            `json:"customer_ref,omitempty"`
	PurchaseRef      string            `json:"purchase_ref,omitempty"`
	NotBefore        *time.Time        `json:"not_before,omitempty"`
	ExpiresAt        *time.Time        `json:"expires_at,omitempty"`
	MaxMajorVersion  *int              `json:"max_major_version,omitempty"`
	MaintenanceUntil *time.Time        `json:"maintenance_until,omitempty"`
	SeatModel        string            `json:"seat_model,omitempty"`
	SeatCount        int               `json:"seat_count,omitempty"`
	Entitlements     []string          `json:"entitlements,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}
type IssueTrialRequest struct {
	ProductID string `json:"product_id"`
	InstallID string `json:"install_id"`
}
type IssuedLicence struct {
	LicenceID       string          `json:"licence_id"`
	LicenceArtifact json.RawMessage `json:"licence_artifact"`
	ExpiresAt       *time.Time      `json:"expires_at"`
	Existing        bool            `json:"existing,omitempty"`
	ActivationID    string          `json:"activation_id,omitempty"`
}

type CreatedActivationCode struct {
	Code           string                `json:"code"`
	ActivationCode domain.ActivationCode `json:"activation_code"`
}

type RedeemActivationRequest struct {
	Code           string            `json:"code"`
	InstallationID string            `json:"installation_id"`
	IdempotencyKey string            `json:"-"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func New(repo domain.Repository, archive domain.ArchiveStore, signer *signing.Manager, trialPepper, activationPepper []byte, defaultTrial time.Duration, strict bool) *Service {
	return &Service{repo: repo, archive: archive, signer: signer, trialPepper: trialPepper, activationPepper: activationPepper, defaultTrial: defaultTrial, strictArchive: strict, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) CreateProduct(ctx context.Context, p domain.Product, actor, requestID string) error {
	p.ProductID = strings.TrimSpace(p.ProductID)
	p.DisplayName = strings.TrimSpace(p.DisplayName)
	if p.ProductID == "" || p.DisplayName == "" || strings.ContainsAny(p.ProductID, " \t\r\n") {
		return domain.ErrInvalid
	}
	if p.DefaultTrialSeconds <= 0 {
		p.DefaultTrialSeconds = int64(s.defaultTrial / time.Second)
	}
	p.CreatedAt = s.now()
	audit := newAudit("product.created", "product", p.ProductID, actor, requestID, map[string]any{"product_id": p.ProductID, "active": p.Active, "result": "success"}, p.CreatedAt)
	return s.repo.CreateProduct(ctx, p, audit)
}
func (s *Service) UpdateProduct(ctx context.Context, id string, update domain.ProductUpdate, actor, requestID string) (domain.Product, error) {
	id = strings.TrimSpace(id)
	if id == "" || (update.DisplayName == nil && update.DefaultTrialSeconds == nil && update.Active == nil) {
		return domain.Product{}, domain.ErrInvalid
	}
	if update.DisplayName != nil {
		name := strings.TrimSpace(*update.DisplayName)
		if name == "" {
			return domain.Product{}, domain.ErrInvalid
		}
		update.DisplayName = &name
	}
	if update.DefaultTrialSeconds != nil && *update.DefaultTrialSeconds <= 0 {
		return domain.Product{}, domain.ErrInvalid
	}
	now := s.now()
	audit := newAudit("product.updated", "product", id, actor, requestID, map[string]any{"product_id": id, "changes": update, "result": "success"}, now)
	return s.repo.UpdateProduct(ctx, id, update, audit)
}
func (s *Service) ListProducts(ctx context.Context) ([]domain.Product, error) {
	return s.repo.ListProducts(ctx)
}
func (s *Service) GetProduct(ctx context.Context, id string) (domain.Product, error) {
	return s.repo.GetProduct(ctx, id)
}
func (s *Service) GetTrial(ctx context.Context, id string) (domain.TrialRecord, domain.LicenceRecord, error) {
	return s.repo.GetTrial(ctx, id)
}
func (s *Service) GetLicence(ctx context.Context, id string) (domain.LicenceRecord, error) {
	return s.repo.GetLicence(ctx, id)
}
func (s *Service) ListLicences(ctx context.Context, product string, limit int) ([]domain.LicenceRecord, error) {
	return s.repo.ListLicences(ctx, product, limit)
}

func (s *Service) IssueLicence(ctx context.Context, req IssueLicenceRequest, actor, requestID string) (IssuedLicence, error) {
	var out IssuedLicence
	if err := validateIssue(req); err != nil {
		return out, err
	}
	slices.Sort(req.Entitlements)
	req.Entitlements = slices.Compact(req.Entitlements)
	p, err := s.repo.GetProduct(ctx, req.ProductID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return out, domain.ErrUnknownProduct
		}
		return out, err
	}
	if !p.Active {
		return out, domain.ErrInvalid
	}
	fingerprint, _ := json.Marshal(req)
	if req.PurchaseRef != "" {
		existing, findErr := s.repo.FindLicenceByPurchaseRef(ctx, req.ProductID, req.PurchaseRef)
		if findErr == nil {
			if !jsonEqual(existing.Metadata, fingerprint) {
				return out, domain.ErrConflict
			}
			if err = s.ensureArchived(ctx, existing); err != nil {
				return out, err
			}
			return issued(existing, true), nil
		}
		if !errors.Is(findErr, domain.ErrNotFound) {
			return out, findErr
		}
	}
	now := s.now()
	notBefore := now
	if req.NotBefore != nil {
		notBefore = req.NotBefore.UTC()
	}
	id := newID("lic")
	entitlements := append([]string(nil), req.Entitlements...)
	payload := domain.LicencePayload{SchemaVersion: 1, LicenceID: id, ProductID: req.ProductID, LicenceType: req.LicenceType, SubjectRef: req.CustomerRef, IssuedAt: now, NotBefore: notBefore, ExpiresAt: req.ExpiresAt, MaxMajorVersion: req.MaxMajorVersion, MaintenanceUntil: req.MaintenanceUntil, SeatModel: req.SeatModel, SeatCount: req.SeatCount, Entitlements: entitlements, Metadata: req.Metadata}
	signed, err := s.signer.Sign(ctx, payload, now)
	if err != nil {
		return out, err
	}
	artifact, err := licencefmt.MarshalArtifact(signed.Envelope, signed.Certificate)
	if err != nil {
		return out, err
	}
	hash := sha256.Sum256(signed.PayloadBytes)
	rec := domain.LicenceRecord{LicenceID: id, ProductID: req.ProductID, LicenceType: req.LicenceType, CustomerRef: req.CustomerRef, PurchaseRef: req.PurchaseRef, IssuerKeyID: signed.IssuerKeyID, IssuedAt: now, NotBefore: notBefore, ExpiresAt: req.ExpiresAt, Status: "active", PayloadHash: hash[:], SignedArtifact: artifact, Metadata: fingerprint, CreatedAt: now}
	archiveEvent := makeArchiveEvent(rec, newID("evt"))
	archiveJSON, _ := json.Marshal(archiveEvent)
	outbox := domain.OutboxEvent{EventID: archiveEvent.EventID, EventType: archiveEvent.EventType, Event: archiveJSON, CreatedAt: now}
	audit := newAudit("licence.issued", "licence", id, actor, requestID, req, now)
	if err = failurepoint.Check(ctx, failurepoint.BeforeDBTransaction); err != nil {
		return out, err
	}
	if err = s.repo.CreateLicence(ctx, rec, nil, audit, &outbox); err != nil {
		if errors.Is(err, domain.ErrConflict) && req.PurchaseRef != "" {
			existing, e := s.repo.FindLicenceByPurchaseRef(ctx, req.ProductID, req.PurchaseRef)
			if e == nil && jsonEqual(existing.Metadata, fingerprint) {
				return issued(existing, true), s.ensureArchived(ctx, existing)
			}
		}
		return out, err
	}
	if err = failurepoint.Check(ctx, failurepoint.AfterDBCommit); err != nil {
		return out, err
	}
	if s.strictArchive {
		if err = s.deliver(ctx, outbox); err != nil {
			return out, fmt.Errorf("%w: %v", domain.ErrArchive, err)
		}
	}
	return issued(rec, false), nil
}

func (s *Service) ReissueLicence(ctx context.Context, id, reason, actor, requestID string) (IssuedLicence, error) {
	var out IssuedLicence
	reason = strings.TrimSpace(reason)
	if strings.TrimSpace(id) == "" || reason == "" || len(reason) > 256 {
		return out, domain.ErrInvalid
	}
	original, err := s.repo.GetLicence(ctx, id)
	if err != nil {
		return out, err
	}
	payloadBytes, err := licencefmt.PayloadBytes(original.SignedArtifact)
	if err != nil {
		return out, err
	}
	var payload domain.LicencePayload
	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		return out, err
	}
	now := s.now()
	replacementID := newID("lic")
	payload.LicenceID = replacementID
	payload.IssuedAt = now
	if payload.NotBefore.Before(now) {
		payload.NotBefore = now
	}
	signed, err := s.signer.Sign(ctx, payload, now)
	if err != nil {
		return out, err
	}
	artifact, err := licencefmt.MarshalArtifact(signed.Envelope, signed.Certificate)
	if err != nil {
		return out, err
	}
	hash := sha256.Sum256(signed.PayloadBytes)
	replacementPurchaseRef := ""
	if original.PurchaseRef != "" {
		replacementPurchaseRef = original.PurchaseRef + "#reissue:" + replacementID
	}
	rec := domain.LicenceRecord{LicenceID: replacementID, ProductID: original.ProductID, LicenceType: original.LicenceType, CustomerRef: original.CustomerRef, PurchaseRef: replacementPurchaseRef, IssuerKeyID: signed.IssuerKeyID, IssuedAt: now, NotBefore: payload.NotBefore, ExpiresAt: payload.ExpiresAt, Status: "active", PayloadHash: hash[:], SignedArtifact: artifact, Metadata: original.Metadata, CreatedAt: now}
	archiveEvent := makeArchiveEvent(rec, newID("evt"))
	archiveJSON, _ := json.Marshal(archiveEvent)
	outbox := domain.OutboxEvent{EventID: archiveEvent.EventID, EventType: archiveEvent.EventType, Event: archiveJSON, CreatedAt: now}
	audit := newAudit("licence.reissued", "licence", replacementID, actor, requestID, map[string]any{"source_licence_id": original.LicenceID, "new_licence_id": replacementID, "reason": reason, "result": "success"}, now)
	if err = s.repo.CreateLicence(ctx, rec, nil, audit, &outbox); err != nil {
		return out, err
	}
	if s.strictArchive {
		if err = s.deliver(ctx, outbox); err != nil {
			return out, fmt.Errorf("%w: %v", domain.ErrArchive, err)
		}
	}
	return issued(rec, false), nil
}

func (s *Service) LicenceStatus(ctx context.Context, req domain.LicenceStatusRequest, requestID string) (domain.SignedLicenceStatus, error) {
	req.LicenceID = strings.TrimSpace(req.LicenceID)
	req.ProductID = strings.TrimSpace(req.ProductID)
	req.Nonce = strings.TrimSpace(req.Nonce)
	if req.LicenceID == "" || req.ProductID == "" || len(req.Nonce) < 16 || len(req.Nonce) > 128 {
		return domain.SignedLicenceStatus{}, domain.ErrInvalid
	}
	rec, err := s.repo.GetLicence(ctx, req.LicenceID)
	if err != nil {
		return domain.SignedLicenceStatus{}, err
	}
	if rec.ProductID != req.ProductID {
		return domain.SignedLicenceStatus{}, domain.ErrNotFound
	}
	now := s.now()
	status := rec.Status
	if status != "active" && status != "revoked" {
		status = "unknown"
	}
	if status == "active" && now.Before(rec.NotBefore) {
		status = "not_yet_valid"
	}
	if status == "active" && rec.ExpiresAt != nil && !now.Before(*rec.ExpiresAt) {
		status = "expired"
	}
	payload := domain.LicenceStatusPayload{SchemaVersion: 1, LicenceID: rec.LicenceID, ProductID: rec.ProductID, Status: status, CheckedAt: now, ValidUntil: now.Add(5 * time.Minute), Nonce: req.Nonce}
	statement, err := s.signer.SignStatus(ctx, payload, now)
	if err != nil {
		return domain.SignedLicenceStatus{}, err
	}
	if err = s.repo.AppendAudit(ctx, newAudit("licence.status_checked", "licence", rec.LicenceID, "public", requestID, map[string]any{"status": status, "result": "success"}, now)); err != nil {
		return domain.SignedLicenceStatus{}, err
	}
	return statement, nil
}

func (s *Service) IssueTrial(ctx context.Context, req IssueTrialRequest, requestID string) (IssuedLicence, error) {
	var out IssuedLicence
	if req.ProductID == "" || len(req.InstallID) < 16 || len(req.InstallID) > 512 {
		return out, domain.ErrInvalid
	}
	p, err := s.repo.GetProduct(ctx, req.ProductID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return out, domain.ErrUnknownProduct
		}
		return out, err
	}
	if !p.Active {
		return out, domain.ErrTrialUnavailable
	}
	if len(s.trialPepper) < 16 {
		return out, errors.New("trial pepper must contain at least 16 bytes")
	}
	h := hmac.New(sha256.New, s.trialPepper)
	h.Write([]byte(req.ProductID))
	h.Write([]byte{0})
	h.Write([]byte(req.InstallID))
	subject := h.Sum(nil)
	if _, l, e := s.repo.FindTrial(ctx, req.ProductID, subject); e == nil {
		if l.ExpiresAt != nil && !s.now().Before(*l.ExpiresAt) {
			return out, domain.ErrTrialExpired
		}
		return issued(l, true), nil
	} else if !errors.Is(e, domain.ErrNotFound) {
		return out, e
	}
	now := s.now()
	duration := time.Duration(p.DefaultTrialSeconds) * time.Second
	if duration <= 0 {
		duration = s.defaultTrial
	}
	expiry := now.Add(duration)
	id := newID("trl")
	payload := domain.LicencePayload{SchemaVersion: 1, LicenceID: id, ProductID: req.ProductID, LicenceType: "trial", SubjectRef: "trial_" + hex.EncodeToString(subject[:8]), IssuedAt: now, NotBefore: now, ExpiresAt: &expiry, Entitlements: []string{"*"}}
	signed, err := s.signer.Sign(ctx, payload, now)
	if err != nil {
		return out, err
	}
	artifact, _ := licencefmt.MarshalArtifact(signed.Envelope, signed.Certificate)
	sum := sha256.Sum256(signed.PayloadBytes)
	rec := domain.LicenceRecord{LicenceID: id, ProductID: req.ProductID, LicenceType: "trial", IssuerKeyID: signed.IssuerKeyID, IssuedAt: now, NotBefore: now, ExpiresAt: &expiry, Status: "active", PayloadHash: sum[:], SignedArtifact: artifact, CreatedAt: now}
	trial := domain.TrialRecord{TrialID: newID("trlrec"), ProductID: req.ProductID, SubjectHash: subject, LicenceID: id, StartedAt: now, ExpiresAt: expiry, CreatedAt: now}
	audit := newAudit("trial.issued", "licence", id, "public", requestID, map[string]string{"product_id": req.ProductID}, now)
	if err = s.repo.CreateLicence(ctx, rec, &trial, audit, nil); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			_, l, e := s.repo.FindTrial(ctx, req.ProductID, subject)
			if e == nil {
				return issued(l, true), nil
			}
		}
		return out, err
	}
	return issued(rec, false), nil
}

func (s *Service) Revoke(ctx context.Context, id, reason, text, actor, requestID string) error {
	if id == "" || reason == "" {
		return domain.ErrInvalid
	}
	now := s.now()
	rev := domain.Revocation{RevocationID: newID("rev"), LicenceID: id, ReasonCode: reason, ReasonText: text, RevokedAt: now}
	archiveEvent := domain.ArchiveEvent{SchemaVersion: 1, EventID: newID("evt"), EventType: "licence.revoked", OccurredAt: now, LicenceID: id, Revocation: &rev}
	archiveJSON, _ := json.Marshal(archiveEvent)
	outbox := domain.OutboxEvent{EventID: archiveEvent.EventID, EventType: archiveEvent.EventType, Event: archiveJSON, CreatedAt: now}
	if err := s.repo.RevokeLicence(ctx, rev, newAudit("licence.revoked", "licence", id, actor, requestID, rev, now), &outbox); err != nil {
		return err
	}
	if s.strictArchive {
		if err := s.deliver(ctx, outbox); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrArchive, err)
		}
	}
	return nil
}

func (s *Service) CreateActivationCode(ctx context.Context, licenceID string, maxUses int, expires *time.Time, actor, requestID string) (CreatedActivationCode, error) {
	var out CreatedActivationCode
	if maxUses <= 0 || maxUses > 10000 {
		return out, domain.ErrInvalid
	}
	if len(s.activationPepper) < 32 {
		return out, errors.New("activation pepper must contain at least 32 bytes")
	}
	licence, err := s.repo.GetLicence(ctx, licenceID)
	if err != nil {
		return out, err
	}
	if licence.Status != "active" || (expires != nil && !s.now().Before(*expires)) {
		if licence.Status != "active" {
			return out, domain.ErrLicenceRevoked
		}
		return out, domain.ErrActivationExpired
	}
	code, err := newActivationCode()
	if err != nil {
		return out, err
	}
	now := s.now()
	a := domain.ActivationCode{ActivationCodeID: newID("acode"), CodeHash: activationCodeHMAC(s.activationPepper, code), HashVersion: "hmac-sha256-v1", LicenceID: licenceID, MaxUses: maxUses, ExpiresAt: expires, CreatedAt: now}
	err = s.repo.CreateActivationCode(ctx, a, newAudit("activation_code.created", "activation_code", a.ActivationCodeID, actor, requestID, map[string]any{"activation_code_id": a.ActivationCodeID, "licence_id": licenceID, "max_uses": maxUses, "expires_at": expires}, now))
	if err != nil {
		return out, err
	}
	return CreatedActivationCode{Code: code, ActivationCode: a}, nil
}
func (s *Service) RedeemActivationCode(ctx context.Context, req RedeemActivationRequest, requestID string) (IssuedLicence, error) {
	var out IssuedLicence
	if len(s.activationPepper) < 32 {
		return out, errors.New("activation pepper must contain at least 32 bytes")
	}
	if !validOpaqueRef(req.InstallationID, 16, 512) || !validOpaqueRef(req.IdempotencyKey, 16, 128) || validateActivationMetadata(req.Metadata) != nil {
		return out, domain.ErrInvalid
	}
	hashes := activationCodeHashes(s.activationPepper, req.Code)
	if len(hashes) == 0 {
		return out, domain.ErrActivationInvalid
	}
	now := s.now()
	metadata, _ := json.Marshal(req.Metadata)
	if len(req.Metadata) == 0 {
		metadata = nil
	}
	record := domain.ActivationRecord{ActivationID: newID("act"), InstanceRefHash: activationReferenceHMAC(s.activationPepper, "instance", req.InstallationID), RequestRefHash: activationReferenceHMAC(s.activationPepper, "request", req.IdempotencyKey), ActivatedAt: now, LastRetrievedAt: now, Metadata: metadata}
	redeemedAudit := newAudit("activation.redeemed", "activation", record.ActivationID, "public", requestID, map[string]any{"activation_id": record.ActivationID, "result": "created"}, now)
	retriedAudit := newAudit("activation.retried", "activation", "", "public", requestID, map[string]string{"result": "idempotent_retry"}, now)
	l, activation, existing, err := s.repo.RedeemActivationCode(ctx, hashes, record, now, redeemedAudit, retriedAudit)
	if err != nil {
		return out, err
	}
	out = issued(l, existing)
	out.ActivationID = activation.ActivationID
	return out, nil
}

func (s *Service) ListActivationCodes(ctx context.Context, licenceID string, limit int) ([]domain.ActivationCode, error) {
	return s.repo.ListActivationCodes(ctx, licenceID, limit)
}
func (s *Service) GetActivationCode(ctx context.Context, id string) (domain.ActivationCode, error) {
	return s.repo.GetActivationCode(ctx, id)
}
func (s *Service) RevokeActivationCode(ctx context.Context, id, reason, actor, requestID string) error {
	if id == "" || strings.TrimSpace(reason) == "" {
		return domain.ErrInvalid
	}
	now := s.now()
	return s.repo.RevokeActivationCode(ctx, id, reason, now, newAudit("activation_code.revoked", "activation_code", id, actor, requestID, map[string]string{"activation_code_id": id, "reason": reason}, now))
}
func (s *Service) ListActivations(ctx context.Context, licenceID, codeID string, limit int) ([]domain.ActivationRecord, error) {
	records, err := s.repo.ListActivations(ctx, licenceID, codeID, limit)
	for i := range records {
		records[i] = decorateActivation(records[i])
	}
	return records, err
}
func (s *Service) GetActivation(ctx context.Context, id string) (domain.ActivationRecord, error) {
	record, err := s.repo.GetActivation(ctx, id)
	return decorateActivation(record), err
}
func (s *Service) RevokeActivation(ctx context.Context, id, reason, actor, requestID string) error {
	if id == "" || strings.TrimSpace(reason) == "" {
		return domain.ErrInvalid
	}
	now := s.now()
	return s.repo.RevokeActivation(ctx, id, reason, now, newAudit("activation.revoked", "activation", id, actor, requestID, map[string]string{"activation_id": id, "reason": reason}, now))
}

func (s *Service) ReconcileArchive(ctx context.Context) (int, error) {
	pending, err := s.repo.PendingOutbox(ctx, 500)
	if err != nil {
		return 0, err
	}
	done := 0
	for _, e := range pending {
		if err = s.deliver(ctx, e); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

func (s *Service) ReconcileArchiveDeep(ctx context.Context, repair bool, actor, requestID string) (domain.ArchiveReconciliationReport, error) {
	var report domain.ArchiveReconciliationReport
	if repair {
		if err := s.repo.VerifyAudit(ctx); err != nil {
			return report, fmt.Errorf("refusing archive repair with invalid audit chain: %w", err)
		}
	}
	licences, err := s.repo.ListPaidLicences(ctx)
	if err != nil {
		return report, err
	}
	events, err := s.archive.ListEvents(ctx)
	if err != nil {
		return report, err
	}
	revocations, err := s.repo.ListRevocations(ctx)
	if err != nil {
		return report, err
	}
	dbLicences := make(map[string]domain.LicenceRecord, len(licences))
	for _, licence := range licences {
		dbLicences[licence.LicenceID] = licence
	}
	archiveLicences := map[string]domain.ArchiveEvent{}
	archiveRevocations := map[string]domain.Revocation{}
	archiveIssuedEvents := 0
	suppressed := map[string]struct{}{}
	for _, event := range events {
		if event.EventType == "data.suppressed" && event.Suppression != nil && event.Suppression.SubjectType == "licence" {
			suppressed[event.Suppression.SubjectDigest] = struct{}{}
		}
	}
	for _, event := range events {
		if event.EventType == "data.suppressed" {
			continue
		}
		if _, deleted := suppressed[retention.Digest("licence", event.LicenceID)]; deleted {
			continue
		}
		switch event.EventType {
		case "licence.issued":
			archiveIssuedEvents++
			archiveLicences[event.LicenceID] = event
		case "licence.revoked":
			if event.Revocation != nil {
				archiveRevocations[event.LicenceID] = *event.Revocation
			}
		}
	}
	report.DatabasePaidLicences = len(dbLicences)
	report.ArchiveIssuedEvents = archiveIssuedEvents
	for id, licence := range dbLicences {
		databaseHashValid := validStoredLicenceHash(licence)
		if !databaseHashValid {
			report.HashMismatches = append(report.HashMismatches, id)
		}
		event, exists := archiveLicences[id]
		if !exists {
			report.MissingFromArchive = append(report.MissingFromArchive, id)
			if repair && databaseHashValid {
				queued, queueErr := s.queueIssuedRepair(ctx, licence, actor, requestID)
				if queueErr != nil {
					return report, queueErr
				}
				if queued {
					report.QueuedRepairs++
				}
			}
			continue
		}
		if !strings.EqualFold(event.PayloadHash, hex.EncodeToString(licence.PayloadHash)) {
			report.HashMismatches = append(report.HashMismatches, id)
		}
	}
	for id := range archiveLicences {
		if _, exists := dbLicences[id]; !exists {
			report.MissingFromDatabase = append(report.MissingFromDatabase, id)
		}
	}
	dbRevocations := make(map[string]domain.Revocation, len(revocations))
	for _, revocation := range revocations {
		dbRevocations[revocation.LicenceID] = revocation
		archived, exists := archiveRevocations[revocation.LicenceID]
		if !exists || archived.RevocationID != revocation.RevocationID || archived.ReasonCode != revocation.ReasonCode || !archived.RevokedAt.Equal(revocation.RevokedAt) {
			report.RevocationMismatches = append(report.RevocationMismatches, revocation.LicenceID)
			if repair && !exists {
				queued, queueErr := s.queueRevocationRepair(ctx, revocation, actor, requestID)
				if queueErr != nil {
					return report, queueErr
				}
				if queued {
					report.QueuedRepairs++
				}
			}
		}
	}
	for id := range archiveRevocations {
		if _, exists := dbRevocations[id]; !exists {
			report.RevocationMismatches = append(report.RevocationMismatches, id)
		}
	}
	slices.Sort(report.MissingFromArchive)
	slices.Sort(report.MissingFromDatabase)
	slices.Sort(report.HashMismatches)
	slices.Sort(report.RevocationMismatches)
	report.RevocationMismatches = slices.Compact(report.RevocationMismatches)
	report.HashMismatches = slices.Compact(report.HashMismatches)
	if report.QueuedRepairs > 0 {
		if _, err = s.ReconcileArchive(ctx); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (s *Service) queueIssuedRepair(ctx context.Context, licence domain.LicenceRecord, actor, requestID string) (bool, error) {
	if !validStoredLicenceHash(licence) {
		return false, errors.New("refusing to archive a licence whose stored artifact and payload hash do not match")
	}
	event := makeArchiveEvent(licence, deterministicRepairID("issued", licence.LicenceID, hex.EncodeToString(licence.PayloadHash)))
	return s.queueRepair(ctx, event, actor, requestID)
}

func (s *Service) queueRevocationRepair(ctx context.Context, revocation domain.Revocation, actor, requestID string) (bool, error) {
	event := domain.ArchiveEvent{SchemaVersion: 1, EventID: deterministicRepairID("revoked", revocation.LicenceID, revocation.RevocationID), EventType: "licence.revoked", OccurredAt: revocation.RevokedAt, LicenceID: revocation.LicenceID, Revocation: &revocation}
	return s.queueRepair(ctx, event, actor, requestID)
}

func (s *Service) queueRepair(ctx context.Context, event domain.ArchiveEvent, actor, requestID string) (bool, error) {
	payload, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	outbox := domain.OutboxEvent{EventID: event.EventID, EventType: event.EventType, Event: payload, CreatedAt: event.OccurredAt}
	audit := newAudit("archive.repair_queued", "licence", event.LicenceID, actor, requestID, map[string]any{"archive_event_id": event.EventID, "event_type": event.EventType, "result": "success"}, s.now())
	return s.repo.QueueArchiveEvent(ctx, outbox, audit)
}

func deterministicRepairID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "repair_" + hex.EncodeToString(sum[:16])
}

func validStoredLicenceHash(licence domain.LicenceRecord) bool {
	payload, err := licencefmt.PayloadBytes(licence.SignedArtifact)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(payload)
	return hmac.Equal(sum[:], licence.PayloadHash)
}
func (s *Service) ArchiveStatus(ctx context.Context) (int, *time.Time, error) {
	return s.repo.ArchiveStatus(ctx)
}
func (s *Service) VerifyArchive(ctx context.Context) error { return s.archive.Verify(ctx) }
func (s *Service) SignerHealth(now time.Time) error        { return s.signer.Healthy(now) }

func (s *Service) ensureArchived(ctx context.Context, l domain.LicenceRecord) error {
	pending, err := s.repo.PendingOutbox(ctx, 500)
	if err != nil {
		return err
	}
	for _, e := range pending {
		var a domain.ArchiveEvent
		if json.Unmarshal(e.Event, &a) == nil && a.LicenceID == l.LicenceID {
			return s.deliver(ctx, e)
		}
	}
	return nil
}
func (s *Service) deliver(ctx context.Context, e domain.OutboxEvent) error {
	var event domain.ArchiveEvent
	if err := json.Unmarshal(e.Event, &event); err != nil {
		return err
	}
	if err := s.archive.PutEvent(ctx, event); err != nil {
		return err
	}
	if err := failurepoint.Check(ctx, failurepoint.AfterArchiveUpload); err != nil {
		return err
	}
	return s.repo.MarkArchived(ctx, e.EventID, s.now())
}

func validateIssue(r IssueLicenceRequest) error {
	if r.ProductID == "" || r.LicenceType == "" {
		return domain.ErrInvalid
	}
	switch r.LicenceType {
	case "perpetual":
		if r.PurchaseRef == "" {
			return fmt.Errorf("%w: purchase_ref is required", domain.ErrInvalid)
		}
	case "subscription", "evaluation":
		if r.ExpiresAt == nil {
			return fmt.Errorf("%w: expires_at is required", domain.ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported licence_type", domain.ErrInvalid)
	}
	if r.SeatCount < 0 || r.SeatCount > 100000 {
		return domain.ErrInvalid
	}
	if r.MaxMajorVersion != nil && *r.MaxMajorVersion < 0 {
		return domain.ErrInvalid
	}
	return nil
}
func issued(l domain.LicenceRecord, existing bool) IssuedLicence {
	return IssuedLicence{LicenceID: l.LicenceID, LicenceArtifact: append(json.RawMessage(nil), l.SignedArtifact...), ExpiresAt: l.ExpiresAt, Existing: existing}
}
func makeArchiveEvent(l domain.LicenceRecord, eventID string) domain.ArchiveEvent {
	return domain.ArchiveEvent{SchemaVersion: 1, EventID: eventID, EventType: "licence.issued", OccurredAt: l.CreatedAt, LicenceID: l.LicenceID, ProductID: l.ProductID, CustomerRef: l.CustomerRef, PurchaseRef: l.PurchaseRef, PayloadHash: hex.EncodeToString(l.PayloadHash), SignedLicenceArtifact: base64.RawURLEncoding.EncodeToString(l.SignedArtifact), IssuerKeyID: l.IssuerKeyID}
}
func newAudit(eventType, aggregateType, aggregateID, actor, requestID string, event any, now time.Time) domain.AuditEvent {
	if actor == "" {
		actor = "local-admin"
	}
	b, _ := json.Marshal(event)
	return domain.AuditEvent{EventID: newID("evt"), OccurredAt: now, ActorType: actor, EventType: eventType, AggregateType: aggregateType, AggregateID: aggregateID, RequestID: requestID, Event: b}
}
func newID(prefix string) string {
	id, err := uuid.NewV7()
	if err != nil {
		id = uuid.New()
	}
	return prefix + "_" + strings.ReplaceAll(id.String(), "-", "")
}
func jsonEqual(a, b []byte) bool {
	var av, bv any
	if json.Unmarshal(a, &av) != nil || json.Unmarshal(b, &bv) != nil {
		return false
	}
	return fmt.Sprint(av) == fmt.Sprint(bv)
}
func newActivationCode() (string, error) {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	parts := make([]string, 0, 4)
	for len(raw) > 0 {
		n := 6
		if len(raw) < n {
			n = len(raw)
		}
		parts = append(parts, raw[:n])
		raw = raw[n:]
	}
	code := strings.Join(parts, "-")
	return code, nil
}
func normalizeActivationCode(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	if len(normalized) < 20 || len(normalized) > 64 {
		return ""
	}
	return normalized
}
func activationCodeHMAC(pepper []byte, code string) []byte {
	normalized := normalizeActivationCode(code)
	if normalized == "" {
		return nil
	}
	h := hmac.New(sha256.New, pepper)
	h.Write([]byte("licd:activation-code:v1\x00"))
	h.Write([]byte(normalized))
	return h.Sum(nil)
}
func activationCodeHashes(pepper []byte, code string) []domain.ActivationCodeHash {
	normalized := normalizeActivationCode(code)
	if normalized == "" {
		return nil
	}
	legacy := sha256.Sum256([]byte(normalized))
	return []domain.ActivationCodeHash{{Version: "hmac-sha256-v1", Hash: activationCodeHMAC(pepper, normalized)}, {Version: "sha256-v1", Hash: legacy[:]}}
}
func activationReferenceHMAC(pepper []byte, purpose, value string) []byte {
	h := hmac.New(sha256.New, pepper)
	h.Write([]byte("licd:activation-" + purpose + ":v1\x00"))
	h.Write([]byte(value))
	return h.Sum(nil)
}
func validOpaqueRef(value string, min, max int) bool {
	if value != strings.TrimSpace(value) || len(value) < min || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func validateActivationMetadata(metadata map[string]string) error {
	if len(metadata) > 16 {
		return domain.ErrInvalid
	}
	for key, value := range metadata {
		if !validOpaqueRef(key, 1, 64) || len(value) > 256 {
			return domain.ErrInvalid
		}
	}
	return nil
}
func decorateActivation(record domain.ActivationRecord) domain.ActivationRecord {
	if len(record.InstanceRefHash) >= 8 {
		record.InstanceRef = hex.EncodeToString(record.InstanceRefHash[:8])
	}
	if len(record.RequestRefHash) >= 8 {
		record.RequestRef = hex.EncodeToString(record.RequestRefHash[:8])
	}
	return record
}
