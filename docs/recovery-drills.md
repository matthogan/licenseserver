# Automated recovery drills and measured recovery objectives

This runbook covers the isolated recovery-drill subsystem used to measure the operational database RPO/RTO and to verify that database backup, immutable archive, deletion suppression and application trust state can be recovered together. A drill never replaces `database.dsn`, promotes a restored file, or writes to the immutable archive.

## Modes and evidence boundary

`simulation` creates a consistent SQLite snapshot with `VACUUM INTO` and synthesizes read-only archive events from the current database. It executes the complete verification path without AWS credentials. Use it for CI, configuration rehearsals and frequent low-risk scheduling. It does **not** prove S3 access, KMS authorization, replica completeness, Object Lock configuration or production network reachability.

`credentialed` lists the configured Litestream restore points, restores the latest database from the configured encrypted S3 replica, and reads the configured filesystem or S3 immutable archive through the service's normal AWS credential chain. This is the production acceptance mode. No credential, session token, SSE-C key or secret value is written to a report, configuration file, command line, or repository.

Both modes use a unique temporary directory beneath `recovery_drill.report_directory`. The directory is deleted after the report is durably written. Neither mode overwrites an existing file.

## Configuration

```yaml
recovery_drill:
  enabled: true
  required: false
  mode: simulation
  schedule_interval: 168h
  max_report_age: 192h
  timeout: 2h
  rpo_objective: 5m
  rto_objective: 1h
  report_directory: "/var/lib/licd/recovery-drills"
  report_retention: 4320h
  reverse_proxy_url: "https://licensing.example.com"
  require_reverse_proxy: true
  max_memory_bytes: 536870912
  max_goroutines: 1000
  max_temporary_storage_bytes: 21474836480
```

`enabled` controls the scheduler. An administrator may still start a manual drill when scheduling is disabled, provided the service identity can create the report directory. `required` makes an overdue, failed, or objective-missing latest report block readiness; otherwise readiness remains available with a `warning` and metrics expose the condition.

The current automated physical-restore implementation is for the recommended SQLite/Litestream profile. PostgreSQL deployments must use their managed/native restore facility and a separate acceptance procedure.

Set `mode: credentialed` only after continuous backup and an immutable archive are configured. Keep `required: false` until the first successful drill is recorded, then enable the readiness gate if that matches the deployment's availability policy.

## Commands

Start a credential-free drill and wait for its persisted report:

```text
licctl --config /etc/licd/config.yaml recovery-drill run --mode simulation --wait
```

Start the credentialed production drill:

```text
licctl --config /etc/licd/config.yaml recovery-drill run --mode credentialed --wait
```

Exercise the installed Windows Service or Linux service before starting the drill:

```text
licctl --config /etc/licd/config.yaml recovery-drill run \
  --mode credentialed \
  --exercise-service-restart \
  --licd-binary /usr/bin/licd \
  --wait
```

The restart option is intentionally explicit because it causes a real service interruption and requires the operating-system privileges needed by `licd service restart`. The CLI reads the old boot ID, performs the native service restart, waits for a different boot ID and full readiness, and includes the measured restart time in the recovery report. A restored database is also closed and reopened during every drill, independently testing process-restart persistence.

Inspect scheduler state and immutable reports:

```text
licctl --config /etc/licd/config.yaml recovery-drill status
licctl --config /etc/licd/config.yaml recovery-drill list --limit 20
licctl --config /etc/licd/config.yaml recovery-drill show DRILL_ID
```

All recovery-drill endpoints require the `admin` role. Starting a drill is asynchronous, so the server's ordinary HTTP write timeout does not terminate a long restore. Only one drill can run at a time.

## Verification sequence

Every successful report proves:

1. A database was created in a unique isolated path from either a local snapshot or the configured S3 replica.
2. Every immutable `data.suppressed` tombstone was collected and transactionally reapplied before restored data was inspected.
3. SQLite full integrity and foreign-key checks passed.
4. The complete tamper-evident audit chain passed.
5. The restored schema exactly matched the running binary.
6. Every restored licence artefact verified against the persisted multi-root keyring and matched its database identity and product.
7. The restored database closed and reopened successfully.
8. The immutable archive independently rebuilt a new database, including revocations and suppressions.
9. Restored and archive-rebuilt paid licences matched by ID, product, issuer, opaque references, status, payload hash, exact artefact digest and revocation content/time.
10. SHA-256 and byte-size evidence was recorded for both isolated database files.
11. The configured HTTPS reverse-proxy origin returned service-info with HSTS, when configured.
12. process memory, goroutine count and temporary storage remained within configured budgets.
13. Measured RPO and RTO were compared with policy.

The report contains counts for products, licences, paid licences, activations, revocations, relevant audit records, issuer/root metadata, transitions, tombstones and archive events. It never contains licence artefacts, customer references, activation secrets, HMAC digests, private keys or AWS credentials.

## RPO and RTO policy

For a credentialed drill, the recovery point is the newest timestamp returned by the remote Litestream LTX inventory immediately before restore. RPO is `drill_completed_at - recovery_point_at`. For simulation, the recovery point is the local snapshot time, so its RPO only measures the rehearsal path and is not production evidence.

RTO is `drill_completed_at - drill_started_at`. It includes restore/snapshot creation, suppression replay, integrity and audit verification, licence verification, archive reconstruction, reconciliation, checksums, proxy probing and resource checks. It does not include incident detection, clean-host provisioning, DNS changes or human approval. Account for those separately when defining an organizational SLA.

The initial policy defaults are:

| Objective | Target | Automated evidence |
|---|---:|---|
| Acknowledged paid licence loss in strict archive mode | 0 | Exact restored/archive paid-record reconciliation |
| Operational database RPO | 5 minutes | Credentialed remote recovery-point timestamp |
| Operational database RTO | 60 minutes | End-to-end drill duration |
| Normal installed-service restart | 1 minute | Optional boot-ID/readiness evidence |
| Recovery drill frequency | Weekly configured default; no older than 8 days | Persistent report scheduler/readiness state |

A technically successful restore that exceeds either objective has status `objectives_missed`, remains useful evidence, and raises `rpo_objective_missed` or `rto_objective_missed`.

Offline-root authority recovery is deliberately not automated by the online service because the root private key must never be present there. Perform and time the custody/recovery ceremony at least annually using `root-key-rotation-and-recovery.md`; retain its external evidence alongside, but not inside, the database drill report.

## Reports, metrics and alerts

Reports use schema version 1 and are written atomically as `drill_<id>.json` with mode `0640` where supported. They are retained for `report_retention` and are independent of the database under test. Attempt and result events are also appended to the primary audit chain as `recovery_drill.started`, `recovery_drill.completed`, or `recovery_drill.failed`.

Alert on:

- `licd_recovery_drill_overdue == 1`;
- `licd_recovery_drill_failures_total` increasing;
- `licd_recovery_drill_objectives_met == 0` after a completed production drill;
- `time() - licd_recovery_drill_last_success_timestamp_seconds` exceeding policy;
- readiness `recovery_drill.readiness` becoming `warning` or `blocked`;
- report alerts `rpo_objective_missed`, `rto_objective_missed`, `last_recovery_drill_failed`, or a component-specific failure code.

Other metrics are `licd_recovery_drill_runs_total`, `licd_recovery_drill_running`, `licd_recovery_drill_last_rpo_seconds`, and `licd_recovery_drill_last_rto_seconds`.

## Credentialed drill procedure

1. Confirm Litestream health is `ok` with matching local and replica TXIDs.
2. Confirm the immutable archive uses the intended independent bucket/prefix and KMS key.
3. Supply short-lived credentials through the standard AWS credential chain as described in `secure-s3-drill-access.md`. Do not add them to YAML or shell history.
4. Run `licd config check` under the service identity.
5. Start a credentialed drill with `--wait`. Use `--exercise-service-restart` during a planned window.
6. Verify report mode is `credentialed`, status is `passed`, both objectives are met, archive/database counts agree, and the proxy/resource checks passed or were intentionally skipped.
7. Record the drill ID, change/ticket reference and reviewer outside licd. The report itself remains immutable on the service host until retention removes it.
8. Remove/expire the temporary credentials and verify no credential text entered the repository, report directory or command history.

Run a credentialed drill before launch, at least quarterly, and after changes to IAM, KMS, bucket policy, Object Lock, Litestream, schema migrations, root/key lifecycle, retention/suppression behavior or restore hosts.

## Incident response

For `remote_restore_failed`, `restore_point_unavailable` or authentication errors, preserve the report, stop relying on the affected backup as recovery evidence, check credential expiry, IAM conditions, KMS key policy/grants, bucket region/prefix and Litestream inventory, then rerun without changing the source data.

For `suppression_reconciliation_failed`, do not promote any historical restore. Restore archive read access first; otherwise deleted customer data could be resurrected.

For `audit_chain_failed`, `licence_verification_failed`, `archive_reconstruction_failed` or `database_archive_mismatch`, treat the source as potentially incomplete or tampered with. Preserve both source systems, reports and service logs, enter maintenance/read-only mode, and investigate before repair. Do not overwrite immutable events or silently choose one side.

For RPO/RTO misses, distinguish transfer/reconstruction time from credential, network, capacity and human delays. Adjust infrastructure or the documented objective only after risk-owner approval; do not make the threshold larger merely to turn the alert green.
