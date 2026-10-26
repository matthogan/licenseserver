# licenceserver

`licd` is a small Go licensing service for issuing Ed25519-signed, offline-verifiable desktop licences. `licctl` is its administrative and recovery CLI. The implementation follows the design in [docs/generic-desktop-licensing-server-technical-spec.md](docs/generic-desktop-licensing-server-technical-spec.md).

## Included

- Root-certified online issuer keys, dual-signed `RKT1` root transitions, trusted client keyrings, and the versioned `LIC1` licence envelope.
- Persisted issuer lifecycle with atomic rotation, protected-path enforcement, emergency compromise shutdown, and lost-key recovery.
- Published deterministic licence, signed-status and root-transition cross-language test vectors in `docs/licence-test-vector-v1.json` and `docs/root-transition-test-vectors-v1.json`, with exact signing inputs and a versioned compatibility policy.
- A standard-library-only public Go client verifier/keyring package with typed UX errors, atomic root lifecycle persistence and Windows/Linux/Raspberry Pi examples. See `client/verifier` and `docs/client-verifier-integration.md`.
- Perpetual, expiring, and privacy-preserving 30-day trial issuance.
- Idempotent paid issuance by `(product_id, purchase_ref)`.
- SQLite WAL or TLS-authenticated PostgreSQL persistence, versioned migrations, integrity checks, and audit hash-chain verification.
- Immutable filesystem or SSE-KMS/Object-Lock S3 archive with a transactional outbox and strict or asynchronous acknowledgement.
- Protected local or AWS KMS Ed25519 issuer signing with the same offline-verifiable licence format.
- Managed Litestream v0.5.12+ continuous S3 replication with mandatory SSE-KMS/SSE-C encryption, freshness health, and safe latest/PITR restore.
- TLS-1.3-only public HTTPS or explicitly trusted reverse-proxy termination.
- Administrative mTLS with certificate-to-role mapping, plus OS-secured Unix-socket and Windows named-pipe transports.
- Catalogued stable API errors, rotating/retained structured logs, limits, timeouts, persistent rate limiting, health checks, and metrics.
- HMAC-protected activation codes with durable per-installation grants, idempotent retry, capacity enforcement, and revocation.
- Stable, privacy-scoped, checksummed production data exports with SQLite/PostgreSQL projections and audited admin-only access.
- Versioned retention, legal holds, transactional deletion and digest-only archive suppressions that prevent restored data from being resurrected.
- Scheduled isolated simulation/credentialed recovery drills with persistent reports, measured RPO/RTO, archive reconstruction, deletion-suppression replay, service-restart/proxy/resource acceptance evidence, metrics and overdue readiness policy.
- Windows Service and Linux systemd/OpenRC service control through `licd service`.
- Managed Linux/Windows filesystem layouts with mode/ACL validation through `licd layout`.
- GoReleaser builds for Windows amd64/arm64 and Linux amd64/Raspberry Pi armv7/arm64, plus deb/rpm/apk packages, signed checksums, SBOMs and provenance attestations.
- A hardened non-root container/Compose deployment with persistent data and file-mounted secrets.

## Quick start

Generate an offline root and an online issuer. Keep `root.key` offline after this step.

```sh
mkdir secrets data
licctl issuer generate-root --private-key secrets/root.key --public-key secrets/root.pub
licctl issuer generate --root-private-key secrets/root.key --key-id issuer-2026-01 --private-key secrets/issuer.key --certificate secrets/issuer.cert
```

Copy `configs/config.example.yaml`, set secure paths and TLS, and set distinct random trial and activation peppers (the activation pepper must contain at least 32 bytes):

```sh
export LICD_TRIAL_PEPPER="replace-with-a-long-random-secret"
export LICD_ACTIVATION_PEPPER="replace-with-a-different-32-byte-random-secret"
export LICD_RATE_LIMIT_PEPPER="replace-with-a-third-distinct-32-byte-random-secret"
licd config check --config config.yaml
licd serve --config config.yaml
```

In another shell:

```sh
licctl --config config.yaml product create com.example.product --display-name "Example Product"
licctl --config config.yaml licence issue --product com.example.product --purchase-ref order_123 --customer-ref cust_123 --max-major-version 1 --entitlement core --output customer.lic
licctl licence inspect customer.lic --root-public-key secrets/root.pub --product com.example.product
```

Trial issuance uses the public endpoint:

```sh
licctl trial issue com.example.product --install-id 550e8400-e29b-41d4-a716-446655440000 --output trial.lic
```

## Service management

Run from an elevated Administrator shell on Windows or as root on Linux. Use an absolute configuration path.

```sh
licd --config /etc/licd/config.yaml service install
licd service start
licd service status
```

The packaged Linux unit runs as the restricted `licd` user, creates `/run/licd/admin.sock` with mode `0660`, and loads secrets such as `LICD_TRIAL_PEPPER` from an optional `/etc/licd/licd.env`. Windows uses `\\.\pipe\licd` with an SDDL that permits only LocalSystem and Built-in Administrators by default. The same executable uses the Windows Service Control Manager on Windows. `stop`, `restart`, and `uninstall` are also supported.

For a manual installation, initialize and verify every configured directory before starting the service:

```sh
licd --config /etc/licd/config.yaml layout init
licd --config /etc/licd/config.yaml layout check
```

## Transport security

The server refuses exposed plaintext configurations. Choose one public transport mode:

- Direct HTTPS: set `tls.enabled: true`; the listener enforces TLS 1.3 and emits HSTS.
- Reverse proxy: set `tls.reverse_proxy.enabled: true` and enumerate `trusted_cidrs`. Only those peers are accepted, `X-Forwarded-Proto` must be exactly `https`, and the closest untrusted `X-Forwarded-For` hop becomes the rate-limit/logging identity.
- Local development: plaintext is accepted only when `server.public_listen` is loopback.

Choose one administrative transport:

- `unix` on Linux, protected by socket ownership and mode.
- `named_pipe` on Windows, protected by its configured SDDL.
- `tcp`, which requires mTLS unless `server.allow_insecure_admin: true` is explicitly set on a loopback listener.

Remote mTLS identities can be mapped by certificate fingerprint, URI SAN, DNS SAN, full subject or common name. Available roles are `viewer`, `operator`, `revoker`, and `admin`. See `docs/transport-security.md` for the security model, `configs/config.mtls.example.yaml` for the server, and `configs/licctl.mtls.example.yaml` for the separate client configuration. Do not store a client administrator key in the server configuration.

## Operations

```sh
licctl --config config.yaml health
licctl --config config.yaml archive status
licctl --config config.yaml archive reconcile
licctl --config config.yaml archive reconcile --deep
licctl --config config.yaml archive reconcile --deep --repair
licctl --config config.yaml db verify --deep
licctl --config config.yaml db migrate --plan
licctl --config config.yaml audit verify
licctl --config config.yaml backup create --output backup.db
licctl --config config.yaml backup verify backup.db
licctl --config config.yaml backup export --destination logical-backup
licctl --config config.yaml backup status
licctl --config config.yaml restore points
licctl --config config.yaml restore latest --output restored.db --dry-run
licctl --config config.yaml recovery-drill run --mode simulation --wait
licctl --config config.yaml recovery-drill status
licctl --config config.yaml data export --product com.example.product --customer-ref cust_123 --output customer-data.tar.gz --json
licctl --config config.yaml data retention plan --json
licctl --config config.yaml data delete --customer-ref cust_123 --reason "verified request" --acknowledge-immutable-residue --json
```

See [docs/production-data-export.md](docs/production-data-export.md) for the public schema/versioning contract, filters, privacy classification, validation, and authorization model.
See [docs/production-retention-and-deletion.md](docs/production-retention-and-deletion.md) before configuring retention or deleting data; immutable archive, audit and historical backup copies have independent expiry boundaries.
See [docs/recovery-drills.md](docs/recovery-drills.md) for simulation versus credentialed evidence, configuration, RPO/RTO definitions, report interpretation and incident response. Use [docs/production-acceptance-checklist.md](docs/production-acceptance-checklist.md) before enabling production issuance.

Destructive migrations never run automatically. Verify a recent unchanged backup, inspect the migration plan, enter maintenance mode, and then migrate:

```sh
licctl --config config.yaml backup create --reason pre-migration --output pre-migration.db
licctl --config config.yaml backup verify pre-migration.db
licctl --config config.yaml maintenance enable --reason "database migration"
licctl --config config.yaml db migrate --plan
licctl --config config.yaml db migrate
licctl --config config.yaml db verify --deep
licctl --config config.yaml maintenance disable --reason "migration verified"
```

`db migrate --force-without-backup` is an audited emergency override. For disaster reconstruction, `db rebuild --from-archive` accepts either a filesystem archive directory or an `s3://bucket/prefix` URL and always writes a new database.

Activation redemption requires a stable installation identifier and client-generated request ID. Reuse both values after a timeout so the retry returns the original grant without consuming capacity:

```sh
licctl activation redeem ABCD7-F9K2M-XP4RT-7QCW8 \
  --public-server https://licensing.example.com \
  --installation-id 0198c7dc-c14b-7678-953a-6683bf3e5b6a \
  --request-id 0198c7dd-9354-7f42-b182-6f95a9ad1f75
```

See [docs/activation-management.md](docs/activation-management.md) for the client contract, administrative commands, revocation semantics, privacy model, and recovery requirements.

Issuer lifecycle operations are restricted to the `admin` role. New key files must first be delivered inside `signer.key_directory`; private key bytes never cross the admin API:

```sh
licctl --config config.yaml issuer list
licctl --config config.yaml issuer rotate --private-key-file issuer-2027-01.key --certificate-file issuer-2027-01.cert
licctl --config config.yaml issuer mark-lost issuer-2027-01 --reason "secret unavailable" --confirm issuer-2027-01
licctl --config config.yaml issuer recover --replaces issuer-2027-01 --private-key-file issuer-2027-02.key --certificate-file issuer-2027-02.cert
```

See [docs/issuer-key-lifecycle-and-recovery.md](docs/issuer-key-lifecycle-and-recovery.md) for the normal rotation, lost-key, compromise, root-custody, and acceptance procedures.

Root replacement is exceptional and uses an offline dual-signature ceremony plus a client overlap rollout. See [docs/root-key-rotation-and-recovery.md](docs/root-key-rotation-and-recovery.md) before using `licctl root transition generate|inspect|verify|activate|retire|rollback`.

Run `licctl <command> --help` for flags. Information-returning commands accept the global `--json` flag.

## Production notes

- Keep trusted-proxy CIDRs narrow and firewall the proxy-to-application listener even though the application also enforces the allowlist.
- Prefer Unix sockets or named pipes for same-host administration. Use mTLS and least-privilege role mappings for remote administration.
- Store issuer keys and distinct trial/activation peppers outside the database with restrictive permissions. Configure the root public key, but never deploy the root private key.
- The filesystem archive is an independent durable copy only when it resides on separately backed-up/off-host storage.
- Continuous backup requires Litestream v0.5.12+ on the host and a separately provisioned S3 bucket/KMS policy. See [docs/backup-and-restore.md](docs/backup-and-restore.md) before enabling it.
- For containers, use the persistent-volume and mounted-secret procedure in [docs/container-deployment.md](docs/container-deployment.md).
- Verify release checksums, Cosign signatures, SBOMs and provenance using [docs/supply-chain-security.md](docs/supply-chain-security.md).
- Local Woodpecker release candidates are built on signed tags and exported for
  interactive Cosign signing; see the same guide for release-image setup and
  trusted volumes. Registry publication remains a separate step.
- PostgreSQL, AWS KMS signing and immutable S3 archive configuration is shown in `configs/config.postgres-kms-s3.example.yaml`; PostgreSQL credentials use `LICD_DATABASE_URL` and AWS credentials use the default credential chain rather than configuration files.
- A perpetual `.lic` file remains independently verifiable; loss of this server does not invalidate it.

## Development

For a ready-made Docker test environment with real PostgreSQL, pinned Litestream,
and race detection, run `./scripts/test-local.ps1` from PowerShell. See
[local testing and Woodpecker](docs/local-ci.md) for setup and pipeline instructions.

```sh
go test -race ./...
go vet ./...
goreleaser check
goreleaser release --snapshot --clean --skip=sign,sbom
```
