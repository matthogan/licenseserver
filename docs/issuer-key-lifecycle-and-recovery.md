# Issuer-key lifecycle and recovery

This runbook covers routine online issuer rotation and recovery from a lost or compromised issuer. The root private key remains offline throughout server operation. `licd` stores issuer certificates, public keys, status, audit history, and a local key-file reference in SQLite; it never stores issuer private-key bytes in SQLite or returns the key reference through the API.

## Required layout

Configure the public root key and one protected directory containing server-readable issuer material:

```yaml
signer:
  provider: file
  root_public_key_file: "/etc/licd/root.pub"
  key_directory: "/run/secrets/licd-issuers"
  private_key_file: "/run/secrets/licd-issuers/issuer-2026-01.key"
  issuer_certificate_file: "/run/secrets/licd-issuers/issuer-2026-01.cert"
```

The root public key is not secret. The root private key must never be placed on the server. On Linux, issuer private files must not grant group or other permissions; use mode `0600` and make them readable only by the service identity. On Windows, restrict the directory ACL to the licd service identity, SYSTEM, and the administrators responsible for recovery.

The server resolves symlinks and rejects lifecycle paths outside `signer.key_directory`. Remote administration therefore cannot upload or transmit key bytes: an administrator must first deploy the files through the host's approved secret-delivery mechanism.

## States and guarantees

Issuer state is one of:

- `staged`: authenticated by the configured root and registered, but not used for issuance;
- `active`: the one key permitted to issue new licences;
- `retired`: retained for history and possible intentional rollback, but not used for new issuance;
- `lost`: its private key is unavailable and cannot be used;
- `compromised`: its private key may be controlled by an attacker; this state is terminal.

Activating or rotating a key validates the root signature, key/certificate match, product authority, current authority window, and protected path. The database transition is atomic and is serialized against signing. A failed database transition leaves the prior in-memory signer active. Successful normal rotation retires the previous active issuer before new issuance resumes.

Perpetual licences issued by a retired or lost key remain valid because each licence carries its root-signed issuer certificate. The certificate's authority end limits when the issuer could issue; it does not expire an otherwise perpetual licence.

## Routine rotation

1. On an offline root workstation, create a new issuer and certificate. Use a unique, sortable ID:

   ```sh
   licctl issuer generate \
     --root-private-key /offline/root.key \
     --key-id issuer-2027-01 \
     --private-key ./transfer/issuer-2027-01.key \
     --certificate ./transfer/issuer-2027-01.cert \
     --valid-for 8760h \
     --product '*'
   ```

2. Verify the certificate while still offline:

   ```sh
   licctl issuer verify-cert \
     --root-public-key /offline/root.pub \
     --certificate ./transfer/issuer-2027-01.cert
   ```

3. Transfer both files using the approved encrypted secret-delivery channel. Place them inside the server's `signer.key_directory`, apply the required owner/ACL, and delete any temporary transfer copy.

4. Optionally stage and inspect the new issuer before activation:

   ```sh
   licctl --config /etc/licd/licctl.yaml issuer register \
     --private-key-file issuer-2027-01.key \
     --certificate-file issuer-2027-01.cert

   licctl --config /etc/licd/licctl.yaml issuer show issuer-2027-01
   licctl --config /etc/licd/licctl.yaml issuer activate issuer-2027-01
   ```

   For the normal one-step procedure, atomically register, activate, and retire the old issuer:

   ```sh
   licctl --config /etc/licd/licctl.yaml issuer rotate \
     --private-key-file issuer-2027-01.key \
     --certificate-file issuer-2027-01.cert
   ```

5. Verify `issuer list` reports exactly one active issuer and the former issuer as retired. Readiness must report `signer: ok`.

6. Issue a test licence and verify it with the application trust anchor:

   ```sh
   licctl --config /etc/licd/licctl.yaml licence issue \
     --product com.example.product \
     --purchase-ref rotation-test-2027-01 \
     --output rotation-test.lic

   licctl licence inspect rotation-test.lic \
     --root-public-key root.pub \
     --product com.example.product
   ```

7. Re-verify a licence issued by the retired key. Do not delete old certificates from the database or licence archive. Keep or destroy the retired private key according to the organization's rollback and cryptographic-destruction policy.

## Lost issuer recovery

Marking the active issuer lost immediately removes it from the in-memory signer and makes readiness fail closed while leaving the administrative endpoint available:

```sh
licctl --config /etc/licd/licctl.yaml issuer mark-lost issuer-2027-01 \
  --reason "secret volume was lost during host replacement" \
  --confirm issuer-2027-01
```

Use the offline root workflow to create and deploy a replacement, then run:

```sh
licctl --config /etc/licd/licctl.yaml issuer recover \
  --replaces issuer-2027-01 \
  --private-key-file issuer-2027-02.key \
  --certificate-file issuer-2027-02.cert
```

Confirm readiness, issue and inspect a test licence, verify an older licence, and run `licctl audit verify`.

## Compromised issuer response

1. Stop the key immediately. This action does not wait for a replacement:

   ```sh
   licctl --config /etc/licd/licctl.yaml issuer mark-compromised issuer-2027-01 \
     --reason "private key was exposed in a host snapshot" \
     --confirm issuer-2027-01
   ```

2. Preserve relevant host, access, and audit evidence. Revoke access to the old secret and investigate the issuance window.

3. Create and deploy a replacement using the offline root, then run `issuer recover` exactly as in lost-key recovery.

4. Identify licences attributed to the compromised issuer and decide which require revocation/reissue.

5. Distribute the compromised issuer ID through the application's online revocation channel and include it in future application releases. A fully offline client that has already shipped cannot learn that a formerly authorized issuer was compromised; this is an inherent limit of offline verification, not something server-side rotation can repair.

## Deliberately stopping issuance

Retiring an active issuer without a replacement requires explicit intent:

```sh
licctl --config /etc/licd/licctl.yaml issuer retire issuer-2027-02 \
  --reason "planned signing freeze" \
  --allow-no-active
```

Without `--allow-no-active`, the server refuses the operation. Lost and compromised operations always stop an affected active signer because continuing issuance would be unsafe.

## Root custody

- Maintain at least two encrypted root-private-key backups in geographically separate controlled locations.
- Protect the encryption key or recovery secret separately from the media.
- Require dual control for root use where practical and record every root-signing ceremony.
- Test restoration and certificate generation from each backup at least annually.
- Keep several verified copies of `root.pub`; it is public trust metadata and is required to authenticate replacement issuers.
- Never rotate the embedded root merely as routine hygiene. Root transition requires an application trust-anchor rollout and is outside this issuer-rotation procedure.

## Recovery acceptance record

For every rotation or recovery, record the old/new IDs and fingerprints, timestamps, operator identities, reason/incident reference, certificate authority windows, test licence ID, `audit verify` result, application verification result, and confirmation that temporary key-transfer copies were removed.
