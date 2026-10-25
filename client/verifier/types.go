package verifier

import "time"

const (
	MaxArtifactBytes   = 64 * 1024
	MaxStatusBytes     = 64 * 1024
	MaxTransitionBytes = 64 * 1024
	MaxKeyringBytes    = 256 * 1024
	MaxRoots           = 8
	MaxProducts        = 256
	MaxEntitlements    = 256
	MaxMetadataEntries = 128
)

type Licence struct {
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

// Can reports whether the signed licence grants an entitlement. A literal
// "*" grants every entitlement.
func (l Licence) Can(capability string) bool {
	for _, entitlement := range l.Entitlements {
		if entitlement == "*" || entitlement == capability {
			return true
		}
	}
	return false
}

type IssuerCertificate struct {
	SchemaVersion      int       `json:"schema_version"`
	IssuerKeyID        string    `json:"issuer_key_id"`
	Algorithm          string    `json:"algorithm"`
	PublicKey          string    `json:"public_key"`
	AuthorityNotBefore time.Time `json:"authority_not_before"`
	AuthorityNotAfter  time.Time `json:"authority_not_after"`
	Products           []string  `json:"products"`
}

type LicenceArtifact struct {
	SchemaVersion     int    `json:"schema_version"`
	Envelope          string `json:"envelope"`
	IssuerCertificate string `json:"issuer_certificate"`
}

type StatusRequest struct {
	LicenceID string `json:"licence_id"`
	ProductID string `json:"product_id"`
	Nonce     string `json:"nonce"`
}

type Status struct {
	SchemaVersion int       `json:"schema_version"`
	LicenceID     string    `json:"licence_id"`
	ProductID     string    `json:"product_id"`
	Status        string    `json:"status"`
	CheckedAt     time.Time `json:"checked_at"`
	ValidUntil    time.Time `json:"valid_until"`
	Nonce         string    `json:"nonce"`
}

type SignedStatus struct {
	SchemaVersion     int    `json:"schema_version"`
	Payload           Status `json:"payload"`
	IssuerKeyID       string `json:"issuer_key_id"`
	Signature         string `json:"signature"`
	IssuerCertificate string `json:"issuer_certificate"`
}

type RootTransition struct {
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

type RootStatus string

const (
	RootActive      RootStatus = "active"
	RootLegacy      RootStatus = "legacy"
	RootRetired     RootStatus = "retired"
	RootCompromised RootStatus = "compromised"
)

type TrustedRoot struct {
	KeyID                       string     `json:"key_id"`
	Algorithm                   string     `json:"algorithm"`
	PublicKey                   string     `json:"public_key"`
	Status                      RootStatus `json:"status"`
	AcceptCertificatesNotBefore *time.Time `json:"accept_certificates_not_before,omitempty"`
	AcceptCertificatesBefore    *time.Time `json:"accept_certificates_before,omitempty"`
	StateReason                 string     `json:"state_reason,omitempty"`
	StateChangedAt              *time.Time `json:"state_changed_at,omitempty"`
}

type TransitionState string

const (
	TransitionApplied    TransitionState = "applied"
	TransitionRolledBack TransitionState = "rolled_back"
)

type TransitionRecord struct {
	TransitionID string          `json:"transition_id"`
	OldRootKeyID string          `json:"old_root_key_id"`
	NewRootKeyID string          `json:"new_root_key_id"`
	Artifact     string          `json:"artifact"`
	State        TransitionState `json:"state"`
	AppliedAt    time.Time       `json:"applied_at"`
	ChangedAt    *time.Time      `json:"changed_at,omitempty"`
	StateReason  string          `json:"state_reason,omitempty"`
}

// Keyring is public-only trust metadata. It never contains a private key.
type Keyring struct {
	SchemaVersion int                `json:"schema_version"`
	Revision      uint64             `json:"revision"`
	Roots         []TrustedRoot      `json:"roots"`
	Transitions   []TransitionRecord `json:"transitions,omitempty"`
}

// Clock makes all time-sensitive decisions deterministic in tests.
type Clock interface{ Now() time.Time }

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }
