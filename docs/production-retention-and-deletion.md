# Production retention and deletion

Section 79 removes eligible records from the live operational database without pretending that immutable audit, archive, or historical backup copies disappear immediately. Deletion is always a two-part operation:

1. transactionally remove eligible live rows and commit an audited, digest-only suppression tombstone;
2. deliver the suppression event to the independent immutable archive so rebuild and point-in-time recovery cannot silently resurrect the removed rows.

Only the `admin` role may configure policies, manage holds, plan/apply retention, delete data, or inspect tombstones.

## Retention policy schema v1

Policies have `schema_version: 1`, a category, monotonically increasing category-local version, positive `retain_for_seconds`, optional `require_export`, creation time/actor, and active state. Updating a category creates a new immutable version and deactivates the former version.

Supported categories are deliberately conservative:

| Category | Eligible live rows | Occurrence boundary |
|:---|:---|:---|
| `expired_trials` | Expired trial licence and its trial/activation/revocation dependencies. | `expires_at + retain_for <= now` |
| `revoked_activations` | Individually revoked activation records; the activation code and licence remain. | `revoked_at + retain_for <= now` |
| `revoked_licences` | Revoked non-trial licence and all activation, code and revocation dependencies. | `revoked_at + retain_for <= now` |

Active paid licences, unexpired trials, products, issuer/root lifecycle state, tamper-evident audit events, backup-verification evidence, and legal-hold records are never policy-deleted. Audit events are an immutable exception because removing a middle event would break the hash chain.

```sh
licctl --config config.yaml data retention policy set \
  --category expired_trials --retain-for 2160h

licctl --config config.yaml data retention policy set \
  --category revoked_licences --retain-for 8760h --require-export

licctl --config config.yaml data retention policy list --json
```

Always dry-run first:

```sh
licctl --config config.yaml data retention plan --json
```

Application requires an operational reason, exact confirmation, and acknowledgement that immutable residues remain:

```sh
licctl --config config.yaml data retention apply \
  --reason "scheduled annual retention" \
  --acknowledge-immutable-residue \
  --confirm "APPLY RETENTION" \
  --json
```

When an eligible category requires export, pass the SHA-256 reported by a server-verified §80 export created within the previous 24 hours. Time-bounded exports are not accepted as deletion proof because they may omit selected dependencies.

## Exact-scope manual deletion

Manual scope is the intersection of any supplied exact product ID, licence ID, and opaque customer reference. At least one selector and a reason are required. The default command is a dry-run:

```sh
licctl --config config.yaml data delete \
  --customer-ref cust_123 \
  --reason "verified erasure request" \
  --require-export \
  --export-sha256 <SHA256> \
  --acknowledge-immutable-residue \
  --json
```

Apply only after reviewing every count and blocker. `--confirm` must equal the most specific selector: licence, then customer reference, then product.

```sh
licctl --config config.yaml data delete \
  --customer-ref cust_123 \
  --reason "verified erasure request" \
  --require-export \
  --export-sha256 <SHA256> \
  --acknowledge-immutable-residue \
  --apply --confirm cust_123 --json
```

Manual deletion still refuses active paid licences and unexpired trials. Revoke the licence or wait for trial expiry; there is no force flag that can silently invalidate a current licensing obligation.

## Legal holds

A hold may cover an exact product, licence, opaque customer reference, or their intersection. Any matching active hold blocks both policy and manual deletion.

```sh
licctl data hold create --customer-ref cust_123 --reason "case LEGAL-2026-014"
licctl data hold list --json
licctl data hold release hold_... --reason "case closed"
```

Holds intentionally retain their exact scope while active. Restrict access to the admin plane and use case references rather than names or email addresses in reasons.

## Transaction and failure behavior

SQLite and PostgreSQL use the same repository implementation and serializable transaction boundary. The transaction re-evaluates eligibility and holds, inserts suppression tombstones/outbox events, deletes activation records, activation codes, trials and revocations in referential order, deletes selected licences, and appends the chained success audit event before commit.

Injected mid-transaction failures prove that no live row, tombstone, outbox event, or success audit survives rollback. A transport failure after commit is an ambiguous success: inspect `data.deleted`/`data.retention_applied` audit events and `licctl data tombstones list` before retrying. Re-running a plan is safe and reports that no eligible rows remain.

Attempts and outcomes use `data.deletion_requested|deleted|deletion_failed`, `data.retention_requested|retention_applied|retention_failed`, policy and legal-hold lifecycle events, plus the normal `admin.request` audit event. Audit details contain counts, policy versions and immutable-residue acknowledgement. Raw customer-reference filters are not copied into deletion audit metadata.

## Tombstone privacy and restoration

A tombstone contains only:

- schema version;
- subject type (`licence` or `activation`);
- `SHA-256("licd-suppression-tombstone-v1" || NUL || type || NUL || public ID)`;
- deletion time, bounded reason code, and policy version.

It does not retain the licence ID, activation ID, customer/purchase reference, metadata, activation HMACs, or free-form deletion reason. Someone who already knows a high-entropy public ID can reproduce the digest to prove it was suppressed; the ledger cannot recover the ID.

Each tombstone is queued as a `data.suppressed` event in the existing immutable filesystem/S3 archive. The admin request synchronously reconciles the outbox and does not report success until the suppression is durably accepted; a crash after the database commit remains recoverable through the persistent outbox. Production deletion fails closed when the archive provider is disabled. Archive reconciliation understands suppression events and does not report suppressed historical issuances as missing database rows.

Database rebuild collects every suppression before replay and skips matching issuance and revocation events regardless of event order. `licctl restore` reconciles the restored database against archive tombstones before reporting success; if the archive is unavailable, the restored output is removed and the command fails. A normal writable `licd` startup also performs this reconciliation before opening listeners. This protects restores made outside the CLI, provided the configured archive is reachable.

Read-only recovery mode does not mutate a restored database. Before promoting a read-only inspection copy to writable production, run the normal restore workflow or start once with archive access and writes enabled in an isolated environment so suppressions can be applied.

## Immutable archive and backup boundary

Deletion from the live database is not immediate erasure from:

- Object-Locked or otherwise immutable licence archive objects;
- Litestream LTX generations, snapshots, S3 versions, or offline database backups;
- the tamper-evident audit chain;
- operational logs already retained under their independent policy.

Those copies expire only under their documented lifecycle, legal-hold, Object Lock, and backup-retention rules. Do not bypass Object Lock or destructively rewrite the audit chain. The suppression ledger is the control that prevents historical data from becoming live again.

If regulations require physical erasure by a deadline, set compatible archive/backup/log lifecycle periods before collecting data and document the maximum erasure latency. KMS-key destruction affects all objects using that key and is not a per-customer deletion mechanism.

## PostgreSQL contract test

The SQLite suite always exercises planning, holds, export proof, rollback, referential deletion, tombstone privacy and archive rebuild suppression. The shared repository contract runs retention against PostgreSQL when credentials are supplied:

```sh
set LICD_TEST_POSTGRES_DSN=postgres://licd_test:password@localhost/licd_test?sslmode=require
go test ./internal/storage/postgres -run TestRepositoryContract
```

Use an isolated disposable database because the integration test applies migrations and deletes its fixture activation.
