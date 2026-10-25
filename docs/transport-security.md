# Transport and Administration Security

This document describes the enforced transport modes for `licd`. The server fails closed when an exposed plaintext or unauthenticated administrative listener is configured.

## Public API

### Direct TLS

Set `tls.enabled: true` and provide a server certificate and private key. `licd` fixes the minimum protocol at TLS 1.3; setting another `tls.min_version` is rejected. Successful responses include HSTS and `Referrer-Policy: no-referrer`.

```yaml
server:
  public_listen: ":9443"
tls:
  enabled: true
  min_version: "1.3"
  certificate_file: "/etc/licd/tls/public.crt"
  private_key_file: "/run/secrets/licd_public_tls.key"
  reverse_proxy:
    enabled: false
```

The certificate must contain the public DNS name in its SAN and have the TLS server-authentication extended key usage.

### Trusted reverse proxy

When TLS terminates at a reverse proxy, explicitly enable proxy mode and allow only the proxy's narrow source CIDRs:

```yaml
server:
  public_listen: "10.20.0.10:9443"
tls:
  enabled: false
  min_version: "1.3"
  reverse_proxy:
    enabled: true
    trusted_cidrs: ["10.20.0.5/32"]
```

The application rejects requests outside those CIDRs. The proxy must replace—not append untrusted client values to—`X-Forwarded-Proto` and `X-Forwarded-For`. `X-Forwarded-Proto` must be `https`; the first valid `X-Forwarded-For` address becomes the logging and rate-limit identity.

Firewall the application listener so only the proxy can reach it. Application allowlisting complements the firewall; it does not replace it.

Plain HTTP without one of these modes is accepted only on a loopback listener for local development.

## Local administration

Linux packages use a Unix socket:

```yaml
server:
  admin_transport: unix
  admin_socket: "/run/licd/admin.sock"
  admin_socket_mode: "0660"
admin:
  transport: unix
  socket: "/run/licd/admin.sock"
```

The systemd unit creates `/run/licd` for the `licd` user/group. Add authorized operators to the intended operating-system group; never make the socket world-accessible.

Windows uses a named pipe:

```yaml
server:
  admin_transport: named_pipe
  admin_pipe: '\\.\pipe\licd'
  admin_pipe_sddl: "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
admin:
  transport: named_pipe
  pipe: '\\.\pipe\licd'
```

The default SDDL grants access only to LocalSystem and Built-in Administrators. A deployment may replace it with an SDDL containing a dedicated operator group SID. Any identity allowed through a local socket or pipe is treated as a local administrator, so the OS ACL is the authorization boundary.

## Remote administration with mTLS

Remote TCP administration requires mTLS. Plain TCP is allowed only when both the listener is loopback and `server.allow_insecure_admin: true` is explicitly configured for development.

Server certificates must have server-authentication EKU. Client certificates must have client-authentication EKU and chain to `admin_tls.client_ca_file`. Prefer a dedicated administrative CA rather than the public web PKI or the licensing issuer hierarchy.

Certificate identities can be mapped using:

- `sha256:<lowercase certificate fingerprint>`;
- URI SAN, preferably a controlled SPIFFE-style URI;
- DNS SAN;
- email SAN;
- full X.509 subject;
- common name.

```yaml
server:
  admin_transport: tcp
  admin_listen: "10.10.0.5:9444"
  allow_insecure_admin: false
admin_tls:
  enabled: true
  certificate_file: "/etc/licd/tls/admin.crt"
  private_key_file: "/run/secrets/licd_admin_tls.key"
  client_ca_file: "/etc/licd/tls/admin-client-ca.crt"
admin_authorization:
  identities:
    - match: "spiffe://example.com/licensing/operators"
      roles: [viewer, operator]
    - match: "spiffe://example.com/licensing/revokers"
      roles: [viewer, revoker]
    - match: "licensing-admin"
      roles: [admin]
```

`licctl` uses a separate client configuration so its private key is never placed in the server configuration:

```yaml
admin:
  transport: tcp
  url: "https://licensing-admin.example.com:9444"
  tls:
    certificate_file: "/secure/licctl/operator.crt"
    private_key_file: "/secure/licctl/operator.key"
    server_ca_file: "/secure/licctl/admin-server-ca.crt"
    server_name: "licensing-admin.example.com"
```

### Roles

| Role | Read health, metrics and records | Issue products/licences/codes and reconcile archives | Revoke licences | Change issuer lifecycle |
|:---|:---:|:---:|:---:|:---:|
| `viewer` | Yes | No | No | No |
| `operator` | Yes | Yes | No | No |
| `revoker` | Yes | No | Yes | No |
| `admin` | Yes | Yes | Yes | Yes |

Unmapped certificates receive HTTP 403 after a successful TLS handshake. Missing, untrusted or expired certificates fail the TLS handshake. Authentication and authorization failures are logged without certificate or key material.

Production-data export/deletion/retention, root/issuer lifecycle, maintenance and recovery-drill status/reports/execution are deliberately `admin`-only. Recovery reports can expose infrastructure topology and operational timing even though they omit credentials and customer records.

## Rotation

Use overlapping server certificates so clients always trust the active server chain. Rotate client certificates by adding the new mapped identity, deploying the certificate, verifying access, and then removing the old identity. Removing an identity from configuration and restarting `licd` immediately removes its application authorization even if the certificate itself has not expired.

Protect every private key with OS permissions or a secret manager. Administrative TLS keys, public TLS keys, licence issuer keys and the offline licence root are separate security domains and must never be reused.

Issuer lifecycle changes are deliberately restricted to `admin`, even when an `operator` can issue licences. See [issuer-key-lifecycle-and-recovery.md](issuer-key-lifecycle-and-recovery.md) for protected file staging, rotation, and emergency recovery.
