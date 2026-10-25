# Container deployment

The supplied image runs `licd` and its health-checking `licctl` as numeric user/group `65532`, drops all capabilities, and expects its root filesystem to be read-only. The only durable writable mount is `/var/lib/licd`; never run with the database in the container layer.

Set each file variable referenced by `compose.yaml` to an absolute host path outside the repository, then start the service:

```text
LICD_ROOT_PUBLIC_KEY_FILE
LICD_ISSUER_PRIVATE_KEY_FILE
LICD_ISSUER_CERTIFICATE_FILE
LICD_PUBLIC_TLS_CERTIFICATE_FILE
LICD_PUBLIC_TLS_PRIVATE_KEY_FILE
LICD_TRIAL_PEPPER_FILE
LICD_ACTIVATION_PEPPER_FILE
LICD_RATE_LIMIT_PEPPER_FILE
```

```bash
docker compose up -d
docker compose ps
```

Pepper bytes are read through the corresponding `NAME_FILE` variables. No secret value or credential is placed in the image, configuration, Compose file, or command line. Keep every source file owner-only readable.

The default filesystem archive shares the persistent volume and is therefore not independent disaster recovery. For production, change `archive.provider` to the immutable S3 adapter and enable the encrypted continuous S3 backup policy, or mount the archive on separately protected storage. Supply AWS access through the workload/instance identity or normal AWS credential chain—never through the image.

The public listener requires TLS 1.3 on port 9443. The admin listener is loopback-only inside the container and is used by the image health check; it is not published.

The stock image supports safe `simulation` recovery drills and stores reports under `/var/lib/licd/recovery-drills`. Credentialed Litestream restore drills require a derived image containing the configured supported Litestream binary, or a bare-host deployment. Never mount a Docker socket to exercise native service restart; use the restored-database reopen check and validate container restart separately through the orchestrator.
