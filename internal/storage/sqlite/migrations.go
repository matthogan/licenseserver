package sqlite

type MigrationClass string

const (
	MigrationAdditive    MigrationClass = "additive"
	MigrationDestructive MigrationClass = "destructive"
)

type migration struct {
	Name  string
	Class MigrationClass
	SQL   string
}

var migrations = []migration{{Name: "initial-schema", Class: MigrationAdditive, SQL: `
CREATE TABLE products (product_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, default_trial_seconds INTEGER NOT NULL, active INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE licences (licence_id TEXT PRIMARY KEY, product_id TEXT NOT NULL, licence_type TEXT NOT NULL, customer_ref TEXT, purchase_ref TEXT, issuer_key_id TEXT NOT NULL, issued_at TEXT NOT NULL, not_before TEXT NOT NULL, expires_at TEXT, status TEXT NOT NULL, payload_hash BLOB NOT NULL, signed_artifact BLOB NOT NULL, metadata_json TEXT, created_at TEXT NOT NULL, FOREIGN KEY(product_id) REFERENCES products(product_id));
CREATE UNIQUE INDEX licences_purchase_ref_uq ON licences(product_id,purchase_ref) WHERE purchase_ref IS NOT NULL;
CREATE TABLE trials (trial_id TEXT PRIMARY KEY, product_id TEXT NOT NULL, subject_hash BLOB NOT NULL, licence_id TEXT NOT NULL, started_at TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(product_id) REFERENCES products(product_id), FOREIGN KEY(licence_id) REFERENCES licences(licence_id));
CREATE UNIQUE INDEX trials_subject_uq ON trials(product_id,subject_hash);
CREATE TABLE revocations (revocation_id TEXT PRIMARY KEY, licence_id TEXT NOT NULL, reason_code TEXT NOT NULL, reason_text TEXT, revoked_at TEXT NOT NULL, FOREIGN KEY(licence_id) REFERENCES licences(licence_id));
CREATE UNIQUE INDEX revocations_licence_uq ON revocations(licence_id);
CREATE TABLE activation_codes (activation_id TEXT PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE, licence_id TEXT NOT NULL, max_uses INTEGER NOT NULL, use_count INTEGER NOT NULL, expires_at TEXT, revoked_at TEXT, created_at TEXT NOT NULL, FOREIGN KEY(licence_id) REFERENCES licences(licence_id));
CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, actor_type TEXT NOT NULL, actor_ref TEXT, event_type TEXT NOT NULL, aggregate_type TEXT, aggregate_id TEXT, request_id TEXT, event_json TEXT NOT NULL, previous_event_hash BLOB, event_hash BLOB NOT NULL);
CREATE TABLE archive_outbox (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, event_json TEXT NOT NULL, created_at TEXT NOT NULL, archived_at TEXT);
CREATE INDEX archive_outbox_pending_idx ON archive_outbox(archived_at,created_at);
`}, {Name: "issuer-lifecycle", Class: MigrationAdditive, SQL: `
CREATE TABLE signing_keys (
    issuer_key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key BLOB NOT NULL,
    issuer_certificate TEXT NOT NULL,
    authority_not_before TEXT NOT NULL,
    authority_not_after TEXT NOT NULL,
    products_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('staged','active','retired','lost','compromised')),
    private_key_ref TEXT NOT NULL,
    registered_at TEXT NOT NULL,
    activated_at TEXT,
    retired_at TEXT,
    state_reason TEXT
);
CREATE UNIQUE INDEX signing_keys_one_active_uq ON signing_keys(status) WHERE status='active';
`}, {Name: "activation-records", Class: MigrationAdditive, SQL: `
ALTER TABLE activation_codes ADD COLUMN hash_version TEXT NOT NULL DEFAULT 'sha256-v1';
ALTER TABLE activation_codes ADD COLUMN revocation_reason TEXT;
CREATE TABLE activation_records (
    activation_id TEXT PRIMARY KEY,
    activation_code_id TEXT NOT NULL,
    licence_id TEXT NOT NULL,
    instance_ref_hash BLOB NOT NULL,
    request_ref_hash BLOB NOT NULL,
    activated_at TEXT NOT NULL,
    last_retrieved_at TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT,
    metadata_json TEXT,
    FOREIGN KEY(activation_code_id) REFERENCES activation_codes(activation_id),
    FOREIGN KEY(licence_id) REFERENCES licences(licence_id)
);
CREATE UNIQUE INDEX activation_records_instance_uq ON activation_records(activation_code_id,instance_ref_hash);
CREATE UNIQUE INDEX activation_records_request_uq ON activation_records(request_ref_hash);
CREATE INDEX activation_records_licence_idx ON activation_records(licence_id,activated_at);
`}, {Name: "persistent-rate-limits", Class: MigrationAdditive, SQL: `
CREATE TABLE rate_limit_counters (
    scope_key TEXT NOT NULL,
    window_start TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    request_count INTEGER NOT NULL CHECK(request_count > 0),
    PRIMARY KEY(scope_key,window_start)
);
CREATE INDEX rate_limit_counters_expiry_idx ON rate_limit_counters(expires_at);
CREATE TABLE audit_write_lock (lock_id INTEGER PRIMARY KEY CHECK(lock_id=1), token INTEGER NOT NULL);
INSERT INTO audit_write_lock(lock_id,token) VALUES(1,0);
`}, {Name: "operational-safety-state", Class: MigrationAdditive, SQL: `
CREATE TABLE backup_verifications (
    verification_id TEXT PRIMARY KEY,
    location TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    verified_at TEXT NOT NULL
);
CREATE INDEX backup_verifications_verified_at_idx ON backup_verifications(verified_at);
CREATE TABLE maintenance_state (
    state_id INTEGER PRIMARY KEY CHECK(state_id=1),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    reason TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    changed_by TEXT NOT NULL
);
INSERT INTO maintenance_state(state_id,enabled,reason,changed_at,changed_by) VALUES(1,0,'','1970-01-01T00:00:00Z','system');
`}, {Name: "root-key-lifecycle", Class: MigrationAdditive, SQL: `
CREATE TABLE root_keys (
    root_key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_key BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','overlap','legacy','retired','compromised')),
    accept_certificates_not_before TEXT,
    accept_certificates_before TEXT,
    source_transition_id TEXT,
    registered_at TEXT NOT NULL,
    activated_at TEXT,
    retired_at TEXT,
    state_reason TEXT
);
CREATE UNIQUE INDEX root_keys_one_active_uq ON root_keys(status) WHERE status='active';
CREATE TABLE root_transitions (
    transition_id TEXT PRIMARY KEY,
    old_root_key_id TEXT NOT NULL,
    new_root_key_id TEXT NOT NULL,
    artifact TEXT NOT NULL,
    created_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    overlap_until TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','retired','rolled_back')),
    activated_at TEXT NOT NULL,
    retired_at TEXT,
    state_reason TEXT,
    FOREIGN KEY(old_root_key_id) REFERENCES root_keys(root_key_id),
    FOREIGN KEY(new_root_key_id) REFERENCES root_keys(root_key_id)
);
CREATE UNIQUE INDEX root_transitions_one_active_uq ON root_transitions(status) WHERE status='active';
`}, {Name: "retention-and-deletion", Class: MigrationAdditive, SQL: `
CREATE TABLE retention_policies (
    category TEXT NOT NULL,
    version INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    retain_for_seconds BIGINT NOT NULL CHECK(retain_for_seconds > 0),
    require_export INTEGER NOT NULL CHECK(require_export IN (0,1)),
    is_current INTEGER NOT NULL CHECK(is_current IN (0,1)),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY(category,version)
);
CREATE UNIQUE INDEX retention_policies_one_active_uq ON retention_policies(category) WHERE is_current=1;
CREATE TABLE legal_holds (
    hold_id TEXT PRIMARY KEY,
    product_id TEXT,
    licence_id TEXT,
    customer_ref TEXT,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    released_at TEXT,
    released_by TEXT,
    CHECK(product_id IS NOT NULL OR licence_id IS NOT NULL OR customer_ref IS NOT NULL)
);
CREATE INDEX legal_holds_active_idx ON legal_holds(released_at,created_at);
CREATE TABLE data_export_proofs (
    sha256 TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    filters_json TEXT NOT NULL,
    record_counts_json TEXT NOT NULL
);
CREATE INDEX data_export_proofs_created_idx ON data_export_proofs(created_at);
CREATE TABLE suppression_tombstones (
    subject_type TEXT NOT NULL,
    subject_digest TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    deleted_at TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    PRIMARY KEY(subject_type,subject_digest)
);
CREATE INDEX suppression_tombstones_deleted_idx ON suppression_tombstones(deleted_at);
`}}
