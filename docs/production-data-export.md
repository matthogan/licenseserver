# Production data export

`licctl data export` produces a stable, privacy-scoped archive for customer support, portability, migration, and future retention/deletion workflows. It is distinct from `backup export`: backup exports preserve server recovery state, while production data exports expose only the documented public records below.

## Create an export

The output path must be new. The CLI downloads to a temporary file in the destination directory, validates the archive, synchronizes it, and commits it with create-exclusive semantics. It never overwrites an existing file.

```sh
licctl --config config.yaml data export \
  --product com.example.product \
  --customer-ref cust_123 \
  --status active \
  --from 2026-01-01T00:00:00Z \
  --to 2027-01-01T00:00:00Z \
  --output exports/cust_123-2026.tar.gz \
  --json
```

Available filters are exact `product_id`, `licence_id`, opaque `customer_ref`, and licence `status` (`active` or `revoked`). `from` is inclusive and `to` is exclusive. The time range is applied independently to each type's occurrence time: licence `created_at`, activation `activated_at`, revocation `revoked_at`, and audit `occurred_at`. Licence identity filters establish the selected licence scope first, so related records can be selected even when the licence itself predates the time range.

An unfiltered export is allowed and may be large. Use a protected destination: customer and purchase references are deliberately opaque but remain linkable operational data.

On success, JSON output reports the absolute path, whole-archive SHA-256, byte size, schema/format versions, applied filters, and record counts.

## Archive contract

The gzip-compressed POSIX tar contains only these regular files:

| File | Purpose |
|:---|:---|
| `manifest.json` | Format identity, versions, UTC creation time, filters, time semantics, privacy profile, per-file hashes/sizes/counts, and total counts. |
| `licences.ndjson` | One public licence record per line. |
| `activations.ndjson` | One public activation grant per line. |
| `revocations.ndjson` | One licence revocation per line. |
| `audit-events.ndjson` | Relevant, privacy-filtered operational events. |
| `checksums.sha256` | SHA-256 for the manifest and every NDJSON file, sorted by filename. |

Records and files have stable ordering. JSON uses stable field ordering, UTC timestamps, one record per newline, fixed archive metadata, and deterministic gzip settings. Given the same committed database snapshot, filter, and `created_at`, the archive bytes are identical.

Validate after extraction with a SHA-256 checker, for example:

```sh
tar -xzf export.tar.gz -C export-files
cd export-files
sha256sum --check checksums.sha256
```

The CLI performs stricter validation before exposing the output: file allowlisting, expansion and entry limits, duplicate detection, checksums, manifest descriptors, counts, schema versions, and strict JSON/NDJSON parsing.

## Public schema v1

The source-of-truth Go definitions are in the dependency-free public package `github.com/matthogan/licenceserver/exportdata`. They are projections and must not be inferred from internal SQL tables.

Every NDJSON record contains `schema_version: 1`.

- Licence: `licence_id`, `product_id`, `licence_type`, optional `customer_ref` and `purchase_ref`, `issuer_key_id`, `issued_at`, `not_before`, optional `expires_at`, `status`, `payload_sha256`, `signed_licence_artifact`, optional `metadata`, and `created_at`.
- Activation: `activation_id`, `activation_code_id`, `licence_id`, `activated_at`, `last_retrieved_at`, optional `revoked_at` and `revocation_reason`, and optional `metadata`.
- Revocation: `revocation_id`, `licence_id`, `reason_code`, optional `reason_text`, and `revoked_at`.
- Audit event: `event_id`, `occurred_at`, `actor_type`, optional `actor_ref`, `event_type`, optional `aggregate_type`, `aggregate_id`, and `request_id`, plus sanitized `details`.

The current bundle identity is:

```text
format:         licd-public-data-export
schema_version: 1
format_version: 1.0.0
```

### Compatibility policy

- `schema_version` changes for an incompatible manifest or record contract. Consumers must reject unsupported schema versions.
- `format_version` follows semantic versioning within a schema. A minor release may add optional fields or new event types; consumers must ignore unknown fields. A patch release clarifies behavior or fixes encoding without changing the data model.
- Existing field meaning, type, and requiredness do not change within schema v1.
- Consumers should key records by their public IDs, preserve unknown fields when forwarding data, and treat NDJSON order as deterministic presentation rather than business chronology.
- Import/migration code should validate the archive fully before applying any record. There is intentionally no command that writes an export back into a live production database.

SQLite runs the full deterministic round-trip suite. The same suite runs against PostgreSQL when `LICD_TEST_POSTGRES_DSN` is set:

```sh
set LICD_TEST_POSTGRES_DSN=postgres://licd_test:password@localhost/licd_test?sslmode=require
go test ./internal/storage/postgres -run TestRepositoryContract
```

## Privacy and data classification

The public-v1 projection excludes:

- private/root/issuer keys and credentials;
- activation codes and activation-code HMAC digests;
- installation and idempotency-request HMAC digests;
- trial subject HMACs and trial records;
- raw database audit-chain hashes;
- metadata and audit-detail keys classified as credentials, codes, secrets, passwords, tokens, private/access/API keys, HMACs, digests, or non-payload hashes.

`payload_sha256` remains because it identifies the exported signed licence payload and is not a customer-secret digest. Signed licence artefacts are public verification artefacts, not signing secrets.

The following remain sensitive operational/customer data and require access control, encryption at rest, limited distribution, and an explicit retention decision: customer/purchase references, actor references, licence and activation IDs, timestamps, revocation reasons, metadata, and signed licence artefacts.

Do not put credentials in export filenames, command flags, or repository files. Protect export archives like customer records and remove temporary extracted copies after use.

## Authorization and audit

`POST /admin/v1/data-exports` requires the `admin` role over the existing OS-authenticated local transport or mTLS administrative listener. Viewer, operator, and revoker roles are denied. It remains available in read-only and maintenance modes because it does not mutate licensed business state.

Each accepted request records:

- `data.export_requested`, with safe filters and no raw customer reference;
- `data.exported`, with result, archive SHA-256, size, record counts, and safe filters; or
- `data.export_failed`, with a bounded reason code.

The normal `admin.request` event also records the authenticated request result. Exported relevant audit records are sanitized projections; they are not a replacement for the server's tamper-evident audit chain.

## Foundation for retention and deletion

Schema v1 defines the records and privacy classes used by the implemented §79 workflow. A successful export alone does not authorize deletion; see [Production retention and deletion](production-retention-and-deletion.md) for policies, legal holds, proof matching, referential closure, immutable residues and restore suppression.
