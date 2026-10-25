package exportdata

import (
	"encoding/json"
	"time"
)

const (
	SchemaVersion = 1
	FormatVersion = "1.0.0"
	FormatName    = "licd-public-data-export"
)

// Filter selects a licence scope. From and To are applied independently to
// each exported record's primary occurrence time; the range is [from, to).
type Filter struct {
	ProductID   string     `json:"product_id,omitempty"`
	LicenceID   string     `json:"licence_id,omitempty"`
	CustomerRef string     `json:"customer_ref,omitempty"`
	Status      string     `json:"status,omitempty"`
	From        *time.Time `json:"from,omitempty"`
	To          *time.Time `json:"to,omitempty"`
}

type RecordCounts struct {
	Licences    int `json:"licences"`
	Activations int `json:"activations"`
	Revocations int `json:"revocations"`
	AuditEvents int `json:"audit_events"`
}

type File struct {
	Name        string `json:"name"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	RecordCount int    `json:"record_count"`
}

type Manifest struct {
	SchemaVersion  int          `json:"schema_version"`
	Format         string       `json:"format"`
	FormatVersion  string       `json:"format_version"`
	CreatedAt      time.Time    `json:"created_at"`
	Filters        Filter       `json:"filters"`
	RecordCounts   RecordCounts `json:"record_counts"`
	Files          []File       `json:"files"`
	TimeSemantics  string       `json:"time_semantics"`
	PrivacyProfile string       `json:"privacy_profile"`
}

type Licence struct {
	SchemaVersion         int             `json:"schema_version"`
	LicenceID             string          `json:"licence_id"`
	ProductID             string          `json:"product_id"`
	LicenceType           string          `json:"licence_type"`
	CustomerRef           string          `json:"customer_ref,omitempty"`
	PurchaseRef           string          `json:"purchase_ref,omitempty"`
	IssuerKeyID           string          `json:"issuer_key_id"`
	IssuedAt              time.Time       `json:"issued_at"`
	NotBefore             time.Time       `json:"not_before"`
	ExpiresAt             *time.Time      `json:"expires_at,omitempty"`
	Status                string          `json:"status"`
	PayloadSHA256         string          `json:"payload_sha256"`
	SignedLicenceArtifact json.RawMessage `json:"signed_licence_artifact"`
	Metadata              json.RawMessage `json:"metadata,omitempty"`
	CreatedAt             time.Time       `json:"created_at"`
}

type Activation struct {
	SchemaVersion    int             `json:"schema_version"`
	ActivationID     string          `json:"activation_id"`
	ActivationCodeID string          `json:"activation_code_id"`
	LicenceID        string          `json:"licence_id"`
	ActivatedAt      time.Time       `json:"activated_at"`
	LastRetrievedAt  time.Time       `json:"last_retrieved_at"`
	RevokedAt        *time.Time      `json:"revoked_at,omitempty"`
	RevocationReason string          `json:"revocation_reason,omitempty"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
}

type Revocation struct {
	SchemaVersion int       `json:"schema_version"`
	RevocationID  string    `json:"revocation_id"`
	LicenceID     string    `json:"licence_id"`
	ReasonCode    string    `json:"reason_code"`
	ReasonText    string    `json:"reason_text,omitempty"`
	RevokedAt     time.Time `json:"revoked_at"`
}

// AuditEvent is a filtered public projection, not a raw audit-table row. It
// intentionally omits chain hashes and details classified as secrets/HMACs.
type AuditEvent struct {
	SchemaVersion int            `json:"schema_version"`
	EventID       string         `json:"event_id"`
	OccurredAt    time.Time      `json:"occurred_at"`
	ActorType     string         `json:"actor_type"`
	ActorRef      string         `json:"actor_ref,omitempty"`
	EventType     string         `json:"event_type"`
	AggregateType string         `json:"aggregate_type,omitempty"`
	AggregateID   string         `json:"aggregate_id,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
}

// Bundle is the decoded form returned by validation tooling. On disk, each
// record collection is a separate deterministic NDJSON file.
type Bundle struct {
	Manifest    Manifest
	Licences    []Licence
	Activations []Activation
	Revocations []Revocation
	AuditEvents []AuditEvent
}
