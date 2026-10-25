package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound            = errors.New("not found")
	ErrConflict            = errors.New("conflict")
	ErrInvalid             = errors.New("invalid request")
	ErrArchive             = errors.New("archive unavailable")
	ErrTrialUnavailable    = errors.New("trial not available")
	ErrTrialExpired        = errors.New("trial already expired")
	ErrActivationInvalid   = errors.New("activation invalid")
	ErrActivationExhausted = fmt.Errorf("%w: exhausted", ErrActivationInvalid)
	ErrActivationExpired   = fmt.Errorf("%w: expired", ErrActivationInvalid)
	ErrActivationRevoked   = fmt.Errorf("%w: revoked", ErrActivationInvalid)
	ErrUnknownProduct      = errors.New("unknown product")
	ErrLicenceRevoked      = errors.New("licence revoked")
	ErrPayloadTooLarge     = errors.New("licence payload too large")
	ErrIdempotencyConflict = errors.New("idempotency conflict")
	ErrRetentionBlocked    = fmt.Errorf("%w: retention operation blocked", ErrConflict)
)

type Product struct {
	ProductID           string    `json:"product_id"`
	DisplayName         string    `json:"display_name"`
	DefaultTrialSeconds int64     `json:"default_trial_seconds"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"created_at"`
}

// ProductUpdate is a partial administrative update. Pointer fields preserve
// the distinction between an omitted value and an explicit false/zero value.
type ProductUpdate struct {
	DisplayName         *string `json:"display_name,omitempty"`
	DefaultTrialSeconds *int64  `json:"default_trial_seconds,omitempty"`
	Active              *bool   `json:"active,omitempty"`
}

type LicencePayload struct {
	SchemaVersion    int               `json:"schema_version"`
	LicenceID        string            `json:"licence_id"`
	ProductID        string            `json:"product_id"`
	LicenceType      string            `json:"licence_type"`
	SubjectRef       string            `json:"subject_ref,omitempty"`
	IssuedAt         time.Time         `json:"issued_at"`
	NotBefore        time.Time         `json:"not_before"`
	ExpiresAt        *time.Time        `json:"expires_at"`
	MaxMajorVersion  *int              `json:"max_major_version,omitempty"`
	MaintenanceUntil *time.Time        `json:"maintenance_until,omitempty"`
	SeatModel        string            `json:"seat_model,omitempty"`
	SeatCount        int               `json:"seat_count,omitempty"`
	Entitlements     []string          `json:"entitlements,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type LicenceRecord struct {
	LicenceID      string          `json:"licence_id"`
	ProductID      string          `json:"product_id"`
	LicenceType    string          `json:"licence_type"`
	CustomerRef    string          `json:"customer_ref,omitempty"`
	PurchaseRef    string          `json:"purchase_ref,omitempty"`
	IssuerKeyID    string          `json:"issuer_key_id"`
	IssuedAt       time.Time       `json:"issued_at"`
	NotBefore      time.Time       `json:"not_before"`
	ExpiresAt      *time.Time      `json:"expires_at"`
	Status         string          `json:"status"`
	PayloadHash    []byte          `json:"payload_hash"`
	SignedArtifact []byte          `json:"signed_artifact"`
	Metadata       json.RawMessage `json:"metadata,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type TrialRecord struct {
	TrialID     string    `json:"trial_id"`
	ProductID   string    `json:"product_id"`
	SubjectHash []byte    `json:"-"`
	LicenceID   string    `json:"licence_id"`
	StartedAt   time.Time `json:"started_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type LicenceStatusRequest struct {
	LicenceID string `json:"licence_id"`
	ProductID string `json:"product_id"`
	Nonce     string `json:"nonce"`
}

type LicenceStatusPayload struct {
	SchemaVersion int       `json:"schema_version"`
	LicenceID     string    `json:"licence_id"`
	ProductID     string    `json:"product_id"`
	Status        string    `json:"status"`
	CheckedAt     time.Time `json:"checked_at"`
	ValidUntil    time.Time `json:"valid_until"`
	Nonce         string    `json:"nonce"`
}

type SignedLicenceStatus struct {
	SchemaVersion     int                  `json:"schema_version"`
	Payload           LicenceStatusPayload `json:"payload"`
	IssuerKeyID       string               `json:"issuer_key_id"`
	Signature         string               `json:"signature"`
	IssuerCertificate string               `json:"issuer_certificate"`
}

type SchemaStatus struct {
	Current    int  `json:"current"`
	Supported  int  `json:"supported"`
	Compatible bool `json:"compatible"`
}

type DatabaseStats struct {
	OpenConnections  int           `json:"open_connections"`
	InUseConnections int           `json:"in_use_connections"`
	IdleConnections  int           `json:"idle_connections"`
	WaitCount        int64         `json:"wait_count"`
	WaitDuration     time.Duration `json:"wait_duration"`
}

type BackupVerification struct {
	VerificationID string    `json:"verification_id"`
	Location       string    `json:"location"`
	SHA256         string    `json:"sha256"`
	SizeBytes      int64     `json:"size_bytes"`
	VerifiedAt     time.Time `json:"verified_at"`
}

type MaintenanceState struct {
	Enabled   bool      `json:"enabled"`
	Reason    string    `json:"reason,omitempty"`
	ChangedAt time.Time `json:"changed_at"`
	ChangedBy string    `json:"changed_by,omitempty"`
}

type Revocation struct {
	RevocationID string    `json:"revocation_id"`
	LicenceID    string    `json:"licence_id"`
	ReasonCode   string    `json:"reason_code"`
	ReasonText   string    `json:"reason_text,omitempty"`
	RevokedAt    time.Time `json:"revoked_at"`
}

type AuditEvent struct {
	EventID       string          `json:"event_id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	ActorType     string          `json:"actor_type"`
	ActorRef      string          `json:"actor_ref,omitempty"`
	EventType     string          `json:"event_type"`
	AggregateType string          `json:"aggregate_type,omitempty"`
	AggregateID   string          `json:"aggregate_id,omitempty"`
	RequestID     string          `json:"request_id,omitempty"`
	Event         json.RawMessage `json:"event"`
	PreviousHash  []byte          `json:"previous_event_hash,omitempty"`
	Hash          []byte          `json:"event_hash"`
}

// DataExportFilter and DataExportSnapshot are repository-bound source data.
// Stable external records live in the dependency-free exportdata package.
type DataExportFilter struct {
	ProductID   string
	LicenceID   string
	CustomerRef string
	Status      string
	From        *time.Time
	To          *time.Time
}

type DataExportSnapshot struct {
	Licences    []LicenceRecord
	Activations []ActivationRecord
	Revocations []Revocation
	AuditEvents []AuditEvent
}

const RetentionPolicySchemaVersion = 1

const (
	RetentionExpiredTrials      = "expired_trials"
	RetentionRevokedActivations = "revoked_activations"
	RetentionRevokedLicences    = "revoked_licences"
)

type DataScope struct {
	ProductID   string `json:"product_id,omitempty"`
	LicenceID   string `json:"licence_id,omitempty"`
	CustomerRef string `json:"customer_ref,omitempty"`
}

type RetentionPolicy struct {
	SchemaVersion    int       `json:"schema_version"`
	Category         string    `json:"category"`
	Version          int       `json:"version"`
	RetainForSeconds int64     `json:"retain_for_seconds"`
	RequireExport    bool      `json:"require_export"`
	Active           bool      `json:"active"`
	CreatedAt        time.Time `json:"created_at"`
	CreatedBy        string    `json:"created_by"`
}

type LegalHold struct {
	HoldID     string     `json:"hold_id"`
	Scope      DataScope  `json:"scope"`
	Reason     string     `json:"reason"`
	CreatedAt  time.Time  `json:"created_at"`
	CreatedBy  string     `json:"created_by"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
	ReleasedBy string     `json:"released_by,omitempty"`
}

type DataExportProof struct {
	SHA256       string          `json:"sha256"`
	CreatedAt    time.Time       `json:"created_at"`
	FilterJSON   json.RawMessage `json:"filters"`
	RecordCounts json.RawMessage `json:"record_counts"`
}

type SuppressionTombstone struct {
	SchemaVersion int       `json:"schema_version"`
	SubjectType   string    `json:"subject_type"`
	SubjectDigest string    `json:"subject_digest"`
	DeletedAt     time.Time `json:"deleted_at"`
	ReasonCode    string    `json:"reason_code"`
	PolicyVersion int       `json:"policy_version,omitempty"`
}

type DeletionCounts struct {
	Licences        int `json:"licences"`
	Trials          int `json:"trials"`
	ActivationCodes int `json:"activation_codes"`
	Activations     int `json:"activations"`
	Revocations     int `json:"revocations"`
	OutboxEvents    int `json:"outbox_events"`
	Tombstones      int `json:"tombstones"`
}

type DeletionBlocker struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
	HoldID string `json:"hold_id,omitempty"`
}

type DataDeletionRequest struct {
	Scope                DataScope `json:"scope"`
	Reason               string    `json:"reason"`
	ExportSHA256         string    `json:"export_sha256,omitempty"`
	RequireExport        bool      `json:"require_export,omitempty"`
	AcknowledgeImmutable bool      `json:"acknowledge_immutable_residue"`
}

type DataDeletionPlan struct {
	SchemaVersion         int               `json:"schema_version"`
	GeneratedAt           time.Time         `json:"generated_at"`
	Mode                  string            `json:"mode"`
	Scope                 DataScope         `json:"scope,omitempty"`
	Categories            []string          `json:"categories,omitempty"`
	PolicyVersions        map[string]int    `json:"policy_versions,omitempty"`
	Counts                DeletionCounts    `json:"counts"`
	CandidateLicences     []string          `json:"candidate_licence_ids,omitempty"`
	Blockers              []DeletionBlocker `json:"blockers"`
	ImmutableResidue      []string          `json:"immutable_residue"`
	ImmutableAcknowledged bool              `json:"immutable_residue_acknowledged"`
	ExportProofSHA256     string            `json:"export_proof_sha256,omitempty"`
	Executable            bool              `json:"executable"`
}

type RetentionApplyRequest struct {
	Reason               string `json:"reason"`
	ExportSHA256         string `json:"export_sha256,omitempty"`
	AcknowledgeImmutable bool   `json:"acknowledge_immutable_residue"`
}

type ArchiveEvent struct {
	SchemaVersion         int                   `json:"schema_version"`
	EventID               string                `json:"event_id"`
	EventType             string                `json:"event_type"`
	OccurredAt            time.Time             `json:"occurred_at"`
	LicenceID             string                `json:"licence_id,omitempty"`
	ProductID             string                `json:"product_id"`
	CustomerRef           string                `json:"customer_ref,omitempty"`
	PurchaseRef           string                `json:"purchase_ref,omitempty"`
	PayloadHash           string                `json:"payload_hash"`
	SignedLicenceArtifact string                `json:"signed_licence_artifact"`
	IssuerKeyID           string                `json:"issuer_key_id"`
	Revocation            *Revocation           `json:"revocation,omitempty"`
	Suppression           *SuppressionTombstone `json:"suppression,omitempty"`
}

type ArchiveReconciliationReport struct {
	DatabasePaidLicences int      `json:"database_paid_licences"`
	ArchiveIssuedEvents  int      `json:"archive_issued_events"`
	MissingFromArchive   []string `json:"missing_from_archive"`
	MissingFromDatabase  []string `json:"missing_from_database"`
	HashMismatches       []string `json:"hash_mismatches"`
	RevocationMismatches []string `json:"revocation_mismatches"`
	QueuedRepairs        int      `json:"queued_repairs"`
}

type OutboxEvent struct {
	EventID    string          `json:"event_id"`
	EventType  string          `json:"event_type"`
	Event      json.RawMessage `json:"event"`
	CreatedAt  time.Time       `json:"created_at"`
	ArchivedAt *time.Time      `json:"archived_at,omitempty"`
}

type ActivationCode struct {
	ActivationCodeID string     `json:"activation_code_id"`
	CodeHash         []byte     `json:"-"`
	HashVersion      string     `json:"-"`
	LicenceID        string     `json:"licence_id"`
	MaxUses          int        `json:"max_uses"`
	UseCount         int        `json:"use_count"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason string     `json:"revocation_reason,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
}

type ActivationCodeHash struct {
	Version string
	Hash    []byte
}

type ActivationRecord struct {
	ActivationID     string          `json:"activation_id"`
	ActivationCodeID string          `json:"activation_code_id"`
	LicenceID        string          `json:"licence_id"`
	InstanceRefHash  []byte          `json:"-"`
	InstanceRef      string          `json:"instance_ref"`
	RequestRefHash   []byte          `json:"-"`
	RequestRef       string          `json:"request_ref"`
	ActivatedAt      time.Time       `json:"activated_at"`
	LastRetrievedAt  time.Time       `json:"last_retrieved_at"`
	RevokedAt        *time.Time      `json:"revoked_at,omitempty"`
	RevocationReason string          `json:"revocation_reason,omitempty"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
}

const (
	IssuerStatusStaged      = "staged"
	IssuerStatusActive      = "active"
	IssuerStatusRetired     = "retired"
	IssuerStatusLost        = "lost"
	IssuerStatusCompromised = "compromised"
)

// IssuerKey contains public lifecycle metadata. PrivateKeyRef is an opaque,
// server-local file reference and is deliberately never serialized by an API.
// The private key itself is never stored in the database.
type IssuerKey struct {
	IssuerKeyID        string     `json:"issuer_key_id"`
	Algorithm          string     `json:"algorithm"`
	PublicKey          []byte     `json:"public_key"`
	Fingerprint        string     `json:"fingerprint"`
	IssuerCertificate  string     `json:"issuer_certificate"`
	AuthorityNotBefore time.Time  `json:"authority_not_before"`
	AuthorityNotAfter  time.Time  `json:"authority_not_after"`
	Products           []string   `json:"products"`
	Status             string     `json:"status"`
	PrivateKeyRef      string     `json:"-"`
	RegisteredAt       time.Time  `json:"registered_at"`
	ActivatedAt        *time.Time `json:"activated_at,omitempty"`
	RetiredAt          *time.Time `json:"retired_at,omitempty"`
	StateReason        string     `json:"state_reason,omitempty"`
}

const (
	RootStatusActive      = "active"
	RootStatusOverlap     = "overlap"
	RootStatusLegacy      = "legacy"
	RootStatusRetired     = "retired"
	RootStatusCompromised = "compromised"

	RootTransitionStatusActive     = "active"
	RootTransitionStatusRetired    = "retired"
	RootTransitionStatusRolledBack = "rolled_back"
)

// RootKey is public trust metadata. Root private keys remain offline and are
// never accepted by the repository or administrative API.
type RootKey struct {
	RootKeyID                   string     `json:"root_key_id"`
	Algorithm                   string     `json:"algorithm"`
	PublicKey                   []byte     `json:"public_key"`
	Fingerprint                 string     `json:"fingerprint"`
	Status                      string     `json:"status"`
	AcceptCertificatesNotBefore *time.Time `json:"accept_certificates_not_before,omitempty"`
	AcceptCertificatesBefore    *time.Time `json:"accept_certificates_before,omitempty"`
	SourceTransitionID          string     `json:"source_transition_id,omitempty"`
	RegisteredAt                time.Time  `json:"registered_at"`
	ActivatedAt                 *time.Time `json:"activated_at,omitempty"`
	RetiredAt                   *time.Time `json:"retired_at,omitempty"`
	StateReason                 string     `json:"state_reason,omitempty"`
}

type RootTransition struct {
	TransitionID string     `json:"transition_id"`
	OldRootKeyID string     `json:"old_root_key_id"`
	NewRootKeyID string     `json:"new_root_key_id"`
	Artifact     string     `json:"artifact"`
	CreatedAt    time.Time  `json:"created_at"`
	NotBefore    time.Time  `json:"not_before"`
	OverlapUntil time.Time  `json:"overlap_until"`
	ExpiresAt    time.Time  `json:"expires_at"`
	Status       string     `json:"status"`
	ActivatedAt  time.Time  `json:"activated_at"`
	RetiredAt    *time.Time `json:"retired_at,omitempty"`
	StateReason  string     `json:"state_reason,omitempty"`
}

type Repository interface {
	Close() error
	Ping(context.Context) error
	SchemaStatus(context.Context) (SchemaStatus, error)
	DatabaseStats() DatabaseStats
	Migrate(context.Context) error
	Verify(context.Context, bool) error
	CreateProduct(context.Context, Product, AuditEvent) error
	UpdateProduct(context.Context, string, ProductUpdate, AuditEvent) (Product, error)
	ListProducts(context.Context) ([]Product, error)
	GetProduct(context.Context, string) (Product, error)
	CreateLicence(context.Context, LicenceRecord, *TrialRecord, AuditEvent, *OutboxEvent) error
	GetLicence(context.Context, string) (LicenceRecord, error)
	FindLicenceByPurchaseRef(context.Context, string, string) (LicenceRecord, error)
	FindTrial(context.Context, string, []byte) (TrialRecord, LicenceRecord, error)
	GetTrial(context.Context, string) (TrialRecord, LicenceRecord, error)
	ListLicences(context.Context, string, int) ([]LicenceRecord, error)
	ListPaidLicences(context.Context) ([]LicenceRecord, error)
	RevokeLicence(context.Context, Revocation, AuditEvent, *OutboxEvent) error
	ListRevocations(context.Context) ([]Revocation, error)
	CreateActivationCode(context.Context, ActivationCode, AuditEvent) error
	RedeemActivationCode(context.Context, []ActivationCodeHash, ActivationRecord, time.Time, AuditEvent, AuditEvent) (LicenceRecord, ActivationRecord, bool, error)
	ListActivationCodes(context.Context, string, int) ([]ActivationCode, error)
	GetActivationCode(context.Context, string) (ActivationCode, error)
	RevokeActivationCode(context.Context, string, string, time.Time, AuditEvent) error
	ListActivations(context.Context, string, string, int) ([]ActivationRecord, error)
	GetActivation(context.Context, string) (ActivationRecord, error)
	RevokeActivation(context.Context, string, string, time.Time, AuditEvent) error
	PendingOutbox(context.Context, int) ([]OutboxEvent, error)
	MarkArchived(context.Context, string, time.Time) error
	ArchiveStatus(context.Context) (pending int, oldest *time.Time, err error)
	VerifyAudit(context.Context) error
	AppendAudit(context.Context, AuditEvent) error
	ConsumeRateLimit(context.Context, string, time.Time, time.Time, int) (int, error)
	RegisterIssuer(context.Context, IssuerKey, AuditEvent) error
	RotateIssuer(context.Context, IssuerKey, string, []AuditEvent) error
	ActivateIssuer(context.Context, string, []AuditEvent) error
	SetIssuerStatus(context.Context, string, string, string, bool, AuditEvent) error
	ListIssuers(context.Context) ([]IssuerKey, error)
	GetIssuer(context.Context, string) (IssuerKey, error)
	GetActiveIssuer(context.Context) (IssuerKey, error)
	EnsureRootKey(context.Context, RootKey, AuditEvent) error
	ActivateRootTransition(context.Context, RootTransition, RootKey, []AuditEvent) error
	RetireRootTransition(context.Context, string, bool, string, time.Time, []AuditEvent) error
	RollbackRootTransition(context.Context, string, bool, string, time.Time, []AuditEvent) error
	ListRootKeys(context.Context) ([]RootKey, error)
	GetRootKey(context.Context, string) (RootKey, error)
	GetActiveRootKey(context.Context) (RootKey, error)
	ListRootTransitions(context.Context) ([]RootTransition, error)
	GetRootTransition(context.Context, string) (RootTransition, error)
	RecordBackupVerification(context.Context, BackupVerification, AuditEvent) error
	LatestBackupVerification(context.Context) (BackupVerification, error)
	GetMaintenance(context.Context) (MaintenanceState, error)
	SetMaintenance(context.Context, MaintenanceState, AuditEvent) error
	QueueArchiveEvent(context.Context, OutboxEvent, AuditEvent) (bool, error)
	QueryDataExport(context.Context, DataExportFilter) (DataExportSnapshot, error)
	RecordDataExportProof(context.Context, DataExportProof, AuditEvent) error
	SetRetentionPolicy(context.Context, RetentionPolicy, AuditEvent) (RetentionPolicy, error)
	ListRetentionPolicies(context.Context) ([]RetentionPolicy, error)
	CreateLegalHold(context.Context, LegalHold, AuditEvent) error
	ReleaseLegalHold(context.Context, string, string, time.Time, AuditEvent) (LegalHold, error)
	ListLegalHolds(context.Context, bool) ([]LegalHold, error)
	PlanDataDeletion(context.Context, DataDeletionRequest, time.Time) (DataDeletionPlan, error)
	DeleteData(context.Context, DataDeletionRequest, time.Time, AuditEvent) (DataDeletionPlan, error)
	PlanRetention(context.Context, RetentionApplyRequest, time.Time) (DataDeletionPlan, error)
	ApplyRetention(context.Context, RetentionApplyRequest, time.Time, AuditEvent) (DataDeletionPlan, error)
	ListSuppressionTombstones(context.Context) ([]SuppressionTombstone, error)
	ApplySuppressionTombstones(context.Context, []SuppressionTombstone, time.Time, AuditEvent) (DeletionCounts, error)
}

type ArchiveStore interface {
	PutEvent(context.Context, ArchiveEvent) error
	ListEvents(context.Context) ([]ArchiveEvent, error)
	Verify(context.Context) error
}
