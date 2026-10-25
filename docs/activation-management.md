# Production activation handling

The activation endpoint exchanges a high-entropy, single-display activation code for an existing signed licence. It records a privacy-preserving installation grant and makes network retries idempotent.

## Server secret

Configure a dedicated activation pepper:

```yaml
activation:
  pepper_env: LICD_ACTIVATION_PEPPER
```

Set the environment variable to at least 32 random bytes. It must be different from `LICD_TRIAL_PEPPER` and must be supplied to the service through its secret environment or secret manager. Losing this pepper prevents lookup of activation codes and client references after restore, so back it up separately from SQLite under the same recovery controls as other operational secrets.

New codes are stored as:

```text
HMAC-SHA256(activation pepper, domain || normalized activation code)
```

The plaintext code is returned only by `activation create`. It is never persisted, returned by list/show, or written to logs. Databases upgraded from the previous implementation retain `sha256-v1` lookup compatibility for existing codes; all newly generated codes use `hmac-sha256-v1`.

## Client contract

The client must persist two opaque random values:

- `installation_id`: generated once per installation and reused for that installation;
- `Idempotency-Key`: generated once per logical redemption attempt and reused until a definitive response is received.

Recommended values are UUIDv4/v7 strings. Do not derive either value from a hostname, username, email, disk serial number, MAC address, or other personal/hardware identifier.

Request:

```http
POST /v1/activations HTTP/1.1
Content-Type: application/json
Idempotency-Key: 0198c7dd-9354-7f42-b182-6f95a9ad1f75

{
  "code": "ABCD7-F9K2M-XP4RT-7QCW8",
  "installation_id": "0198c7dc-c14b-7678-953a-6683bf3e5b6a",
  "metadata": {
    "platform": "windows"
  }
}
```

`installation_id` must contain 16–512 bytes and `Idempotency-Key` 16–128 bytes. Metadata is optional and limited to 16 entries, 64-byte keys, and 256-byte values.

The response contains the signed licence and `activation_id`. If the request or installation already succeeded, the server returns the original activation and licence with `existing: true`; it does not consume another use. Reusing an idempotency key with a different code, installation, or metadata returns HTTP 409 `IDEMPOTENCY_CONFLICT`.

The server stores only domain-separated HMAC references for installation and request identifiers. Administrative output exposes a short digest prefix for correlation, never either raw identifier.

## Retry and capacity behavior

Redemption is one SQLite transaction containing:

1. activation-code lookup;
2. existing request/installation detection;
3. code, licence, expiry, revocation, and capacity checks;
4. activation-record insertion;
5. guarded use-count increment;
6. audit-chain append.

The server serializes redemptions within the SQLite process and enforces unique database indexes for request and code/installation identities. Concurrent requests cannot exceed `max_uses`.

An existing successful activation can be retrieved after its code expires, is exhausted, or is administratively revoked. This ensures that a delayed retry is not stranded by a later policy change. It cannot be retrieved after the individual activation or its licence is revoked.

## Administration

Create a code; the plaintext appears once:

```sh
licctl --config config.yaml activation create lic_123 \
  --max-uses 3 \
  --expires-in 168h
```

Redeem with stable client identifiers:

```sh
licctl activation redeem ABCD7-F9K2M-XP4RT-7QCW8 \
  --public-server https://licensing.example.com \
  --installation-id 0198c7dc-c14b-7678-953a-6683bf3e5b6a \
  --request-id 0198c7dd-9354-7f42-b182-6f95a9ad1f75 \
  --metadata platform=windows
```

Inspect installation grants:

```sh
licctl --config config.yaml activation list --licence lic_123
licctl --config config.yaml activation show act_123
```

Revoke one installation and release one unit of code capacity:

```sh
licctl --config config.yaml activation revoke act_123 \
  --reason "device retired"
```

Inspect or revoke the activation code itself:

```sh
licctl --config config.yaml activation code list --licence lic_123
licctl --config config.yaml activation code show acode_123
licctl --config config.yaml activation code revoke acode_123 \
  --reason "order refunded"
```

Code revocation blocks new installations but does not implicitly revoke existing installation grants. Revoke those records or the underlying licence when existing installations must also stop retrieving the licence.

## Audit and monitoring

The audit chain records:

- `activation_code.created`;
- `activation.redeemed`;
- `activation.retried`;
- `activation.revoked`;
- `activation_code.revoked`.

Public activation requests are limited independently by client IP and normalized code digest. `licd_activation_failures_total` counts malformed, rate-limited, invalid, exhausted, and conflicting redemption attempts without using activation or customer identifiers as metric labels.

## Backup and recovery

Physical and logical backups include activation codes and activation records. The logical export uses separate `activation-codes.ndjson` and `activations.ndjson` files. Restore the activation pepper through the service secret channel before accepting redemption traffic; it is intentionally absent from every repository and database backup.
