# Production acceptance checklist

Complete this checklist for the actual deployment before enabling public issuance. Attach drill IDs and external infrastructure evidence to the deployment/change record; never add credentials to the repository.

## Build and host

- [ ] Release binaries/packages and container images are from a signed tag; checksums, signatures, provenance and SBOMs were verified.
- [ ] `licd config check` and `licd layout check` pass as the service identity.
- [ ] The installed service starts automatically after an actual host reboot.
- [ ] `licctl recovery-drill run --exercise-service-restart --wait` records a changed boot ID and readiness within the one-minute target.
- [ ] Recovery-drill memory, goroutine and temporary-storage budgets pass on the production host size.

## Transport and administration

- [ ] Public traffic is direct TLS 1.3 or passes only through the allowlisted reverse proxy.
- [ ] The configured `recovery_drill.reverse_proxy_url` check passes HTTPS, HSTS and service-info validation.
- [ ] The public proxy cannot reach the admin listener.
- [ ] Unix socket mode/ownership, Windows named-pipe SDDL, or remote mTLS identity-role mappings were verified.
- [ ] Viewer, operator, revoker and admin denial/allow behavior was tested with real deployment identities.

## Keys and licence behavior

- [ ] Offline root private keys are absent from the host and available through the approved custody procedure.
- [ ] Active issuer authority, root keyring and compromise/rotation contacts were verified.
- [ ] The offline-root custody/recovery ceremony was timed against the four-hour target and its external evidence was approved.
- [ ] A production-like licence is issued, delivered, verified offline by a real client, activated/idempotently retried where applicable, revoked and audited.
- [ ] Client applications consume the published licence/status/root-transition vectors and pin an approved verifier version.

## Database, archive and deletion safety

- [ ] SQLite WAL/FULL or PostgreSQL TLS/pool configuration matches the selected deployment profile.
- [ ] Strict paid-licence issuance creates exactly one immutable off-host archive event before acknowledgement.
- [ ] S3 versioning, Object Lock mode/retention, SSE-KMS key and least-privilege bucket/key policies were reviewed.
- [ ] Deep archive reconciliation reports no missing IDs, hash mismatches or revocation mismatches.
- [ ] A deletion drill proves immutable suppression tombstones prevent historical restore/archive replay from resurrecting deleted data.

## Backup and recovery

- [ ] Continuous backup reports matching local and remote TXIDs and a recovery point within the RPO target.
- [ ] A **credentialed** recovery drill against the actual S3/KMS destination has status `passed`; a simulation report is not accepted for this item.
- [ ] The credentialed drill restores the physical database, reapplies suppressions, rebuilds the archive database, verifies audit/licence/checksum evidence and reconciles paid records.
- [ ] Measured operational RPO is at most five minutes and automated end-to-end RTO is at most sixty minutes, or an explicitly approved deployment policy replaces those defaults.
- [ ] Report scheduling, retention, alerts and overdue readiness policy are active and monitored.
- [ ] A separate clean-host/manual recovery exercise accounts for provisioning, secret recovery, DNS/proxy changes and approval time not included in automated RTO.

## Operations and privacy

- [ ] Metrics, structured logs and audit events reach the intended monitoring/retention systems without secrets or customer data leakage.
- [ ] Maintenance and read-only recovery modes were exercised.
- [ ] Retention policies, legal holds, export-before-delete requirements and immutable backup/archive boundaries were approved.
- [ ] Payment webhooks are disabled unless a provider-specific authenticated and replay-protected adapter has been implemented and accepted.
- [ ] Incident owners and escalation paths exist for backup, archive, KMS/root/issuer, audit-integrity and privacy failures.

Acceptance is complete only when every applicable item has recorded evidence. Mark intentionally inapplicable items with the approving risk owner and reason rather than silently omitting them.
