# Continuous backup and point-in-time restore

## Migration safety

Every schema migration is classified as additive or destructive. Additive migrations may run during normal startup. Destructive migrations against an existing database are refused by startup and must be invoked explicitly with `licctl db migrate`.

Before destructive migration, create and deeply verify a physical backup:

```sh
licctl --config /etc/licd/config.yaml backup create --reason pre-migration --output /var/lib/licd/backups/pre-migration.db
licctl --config /etc/licd/config.yaml backup verify /var/lib/licd/backups/pre-migration.db
licctl --config /etc/licd/config.yaml maintenance enable --reason "database migration"
licctl --config /etc/licd/config.yaml db migrate --plan
licctl --config /etc/licd/config.yaml db migrate
licctl --config /etc/licd/config.yaml db verify --deep
licctl --config /etc/licd/config.yaml maintenance disable --reason "migration verified"
```

Verification evidence includes the absolute path, size, SHA-256 and time and is committed with the audit event. At migration time the file is re-read and must be unchanged and no older than `database.migration_backup_max_age`. `--force-without-backup` bypasses this gate only when explicitly supplied and is included in the migration audit event.

`licd` manages Litestream v0.5.12 or newer as a child process and continuously replicates the SQLite database to S3. An enabled backup configuration is rejected unless every upload explicitly requests SSE-KMS or SSE-C encryption and any custom S3 endpoint uses HTTPS.

Litestream v0.5 does not currently support its former `age` client-side encryption. This integration therefore uses S3 server-side encryption and TLS in transit. The generated Litestream file uses mode `0600` on POSIX systems and inherits its protected parent-directory ACL on Windows; AWS credentials and SSE-C keys are never written into it.

## Production prerequisites

1. Install Litestream v0.5.12 or newer on the host and set `backup.continuous.binary` to its absolute path.
2. Create a dedicated, non-public S3 bucket outside the licd host. Enable versioning and a retention/lifecycle policy; consider Object Lock.
3. Grant the service identity only the object-list/read/write/delete permissions Litestream needs for the configured prefix and permission to use the selected KMS key. Prefer an EC2/task/workload role. Otherwise provide standard `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional session-token environment variables through the service secret store.
4. Configure `sse-kms` with a KMS key ID/ARN (recommended) or `sse-c` with a base64-encoded 256-bit key in the named environment variable. The SSE-C key must be backed up separately; losing it makes every replica object unrecoverable.
5. Set `enabled: true`, run `licd config check`, start the service, and wait for `licctl backup status` to report matching `local_txid` and `replica_txid` with status `ok`.

The Linux package reads `/etc/licd/licd.env`. Restrict that file to root/`licd` and mode `0640` or tighter. On Windows, use the machine/service-account environment or an instance role. Do not put S3 credentials in YAML or the replica URL.

## Health and alerting

When `required: true`, readiness remains unavailable until Litestream is running and the highest transaction ID visible in S3 has caught up with local Litestream state. licd periodically performs both checks; an idle but fully replicated database stays healthy. Alert on:

- readiness failure or `backup status` other than `ok`;
- `licd_backup_enabled == 1` and `licd_backup_process_up == 0`;
- `time() - licd_backup_last_success_timestamp_seconds` exceeding `max_backup_age`.

`validation_interval` enables Litestream's background continuity checks. This detects missing, overlapping, or unordered LTX files, but it does not replace restore drills.

The recovery-drill scheduler performs that separate end-to-end verification. Alert on `licd_recovery_drill_overdue`, `licd_recovery_drill_failures_total`, and RPO/RTO objective metrics as described in `recovery-drills.md`.

## Restore safely

List stored LTX boundaries and validate the plan before writing:

```text
licctl --config /etc/licd/config.yaml restore points
licctl --config /etc/licd/config.yaml restore latest --output /var/lib/licd/restores/latest.db --dry-run
licctl --config /etc/licd/config.yaml restore point-in-time 2026-08-15T09:30:00Z --output /var/lib/licd/restores/pitr.db --dry-run
```

Perform the selected restore only while the destination path does not exist:

```text
licctl --config /etc/licd/config.yaml restore latest --output /var/lib/licd/restores/latest.db
licctl --config /etc/licd/config.yaml restore point-in-time 2026-08-15T09:30:00Z --output /var/lib/licd/restores/pitr.db
```

The CLI restores to a unique staging file, asks Litestream for a full integrity check, independently runs SQLite `integrity_check` and `foreign_key_check`, closes the database, and atomically renames it to the requested output. It then reads all digest-only deletion suppressions from the independent immutable archive and transactionally removes any historical rows before reporting success. If archive reconciliation fails, the new output is removed. Existing destinations are never overwritten.

Litestream restores at retained LTX-file boundaries, not at every individual transaction. A requested timestamp can therefore restore to the nearest valid boundary at or before that time. Always inspect `--dry-run`; `restore points` shows stored files but a candidate still requires a complete retained snapshot and unbroken chain.

## Recovery runbook

1. Stop licd and preserve the failed database, WAL, SHM, configuration, and logs.
2. Run a dry-run plan and record the selected recovery point and transaction ID.
3. Restore to a new path and retain the CLI verification result.
4. Run `licctl db verify --deep` against the restored database configuration and `licctl audit verify`.
5. Confirm the restore result reports suppression reconciliation, then compare the restored paid-licence high-water mark with the independent immutable archive; rebuild/reconcile events newer than the database recovery point. Never promote an older database while the suppression archive is unavailable.
6. Verify the issuer certificate and separately protected issuer key.
7. Move the old database aside, place the verified restored database at `database.dsn`, and start licd with `server.read_only: true`.
8. Check readiness, backup status, product/licence reads, and offline licence verification. Then re-enable writes and document the achieved RPO/RTO.

Use the automated subsystem for recurring evidence:

```text
licctl --config /etc/licd/config.yaml recovery-drill run --mode simulation --wait
licctl --config /etc/licd/config.yaml recovery-drill run --mode credentialed --exercise-service-restart --wait
licctl --config /etc/licd/config.yaml recovery-drill status
```

Simulation exercises the verification workflow without cloud credentials but does not validate IAM, KMS or S3. Run a credentialed drill against the real destination before launch, at least quarterly, and after changes to bucket policy, KMS policy, retention, Litestream, SQLite schema or deletion-suppression behavior. See `recovery-drills.md` for the complete procedure and report policy.

Current command/config behavior is based on the official [Litestream configuration](https://litestream.io/reference/config/), [restore](https://litestream.io/reference/restore/), [JSON output](https://litestream.io/reference/json-output/), and [S3](https://litestream.io/guides/s3/) documentation.
