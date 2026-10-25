# Root-key rotation and recovery

This runbook covers the exceptional replacement of the offline Ed25519 root. Routine cryptographic hygiene uses issuer rotation instead. Root private keys remain offline throughout normal server operation and are never sent to `licd`, its database, or its administrative API.

## Trust and artefact model

`RKT1.<payload>.<old-signature>.<new-signature>` is a domain-separated root-transition artefact. Its canonical JSON payload identifies both SHA-256 root key IDs and public keys, the creation and installation window, the end of overlap, and the ceremony reason. The old signature grants continuity from existing trust; the new signature proves possession of the successor private key. A server or client must verify both signatures and must already trust one endpoint. A normal licensing API response cannot add a root.

During overlap, clients accept issuer certificates under either root. The new root may certify issuers whose `authority_not_before` is at or after transition `not_before`. After cutover, the old root remains usable only to verify historical issuer certificates whose authority began before `overlap_until`; this preserves old perpetual licences. It cannot authorize a newly created issuer authority at or after cutover. A root marked compromised is not accepted even for historical verification, so affected licences require reissue or an explicit product-specific exception delivered through a trusted application update.

The transition installation deadline (`expires_at`) prevents a stale transition from being newly applied. It does not remove a transition already persisted by a client. Clients should persist the resulting keyring atomically.

## Preparation

1. Confirm issuer rotation cannot solve the problem. Obtain security/change approval and use two authorized custodians where possible.
2. Verify two independent backups of the old root and record its full `licctl issuer generate-root` fingerprint.
3. Generate the successor with `licctl issuer generate-root` in the offline environment. Store its private key under the same or stronger controls and export only `new-root.pub`.
4. Choose a unique transition ID, an overlap long enough to update the supported client population, and a short installation grace after overlap.
5. Back up and verify the server database. The encrypted physical backup contains public keyring and transition metadata; logical export contains `root-keyring.ndjson` and `root-transitions.ndjson`.

Keep ordered copies of every signed transition beside the recovery documentation. Archive-only reconstruction after rotation supplies them explicitly so licences under every historical root can be authenticated:

```sh
licctl db rebuild --from-archive s3://bucket/licence-events \
  --root-public-key root-2026.pub \
  --root-transition root-2026-to-2031.rkt \
  --output rebuilt.db
```

## Offline ceremony

Create the dual-signed artefact with both offline private keys:

```sh
licctl root transition generate \
  --old-root-private-key /offline/root-2026.key \
  --new-root-private-key /offline/root-2031.key \
  --transition-id root-2026-to-2031 \
  --not-before 2031-01-02T00:00:00Z \
  --overlap 720h \
  --install-grace 168h \
  --reason "approved root custody replacement CHG-1234" \
  --output root-2026-to-2031.rkt
```

Inspecting is deliberately unauthenticated parsing; verification is the trust decision:

```sh
licctl root transition inspect --file root-2026-to-2031.rkt
licctl root transition verify \
  --file root-2026-to-2031.rkt \
  --trusted-old-root /offline/root-2026.pub \
  --at 2031-01-02T00:00:00Z
```

Two custodians should independently compare the old/new IDs, timestamps, reason, and output SHA-256 over a separate channel. Preserve the artefact and ceremony record; erase unencrypted transfer media.

## Client rollout and activation

Before server cutover, publish the artefact through a signed application update or another already authenticated update channel. A keyring-aware verifier starts with the embedded old root, applies `RKT1` only inside its installation window, verifies both signatures, and stores the old/new trust bounds. Validate every client implementation against `docs/root-transition-test-vectors-v1.json`.

At or after `not_before`, activate the transition on the server. The exact full new key ID confirmation prevents selection mistakes:

```sh
licctl --config /etc/licd/licctl.yaml root transition activate \
  --file root-2026-to-2031.rkt \
  --confirm-new-root sha256:<FULL_NEW_ROOT_SHA256>

licctl --config /etc/licd/licctl.yaml root keyring
licctl --config /etc/licd/licctl.yaml root transition show root-2026-to-2031
```

Activation persists both public roots and the signed artefact atomically with `root_key.registered` and `root_transition.activated` audit events. It does not upload either private key.

During overlap:

1. Use the new offline root to certify a new online issuer with `authority_not_before >= transition.not_before`.
2. Deploy that issuer key/certificate and run the normal `licctl issuer rotate` procedure.
3. Issue and independently verify a canary licence using keyring-aware clients.
4. Confirm supported application releases installed the transition. Do not use unauthenticated API telemetry as a trust update.

Live signing under the old root is rejected at the exact overlap deadline even if an operator forgets to finish the lifecycle. Readiness also fails until the overdue transition is resolved.

## Complete cutover

Routine retirement is accepted only at or after `overlap_until`, and only when the active online issuer is certified by the new root (or issuance is already stopped):

```sh
licctl --config /etc/licd/licctl.yaml root transition retire root-2026-to-2031 \
  --reason "supported client rollout and new-root canary verified" \
  --confirm-old-root sha256:<FULL_OLD_ROOT_SHA256>
```

This records the old root as `legacy`, the new root as `active`, and the transition as `retired`, with chained audit events. Historical pre-cutover issuer certificates remain verifiable. The configured `signer.root_public_key_file` may remain the old public anchor or be changed to the new public anchor; startup validates the complete dual-signed chain from either endpoint. Never remove the persisted transition evidence while any historical root metadata is retained.

## Rollback during overlap

Rollback is permitted only before `overlap_until`.

1. Stop new-root issuance. For a routine rollback, activate an old-root-certified issuer first. If the new root may be compromised, use the emergency flag; `licd` disables a currently loaded new-root issuer.
2. Roll back with an exact new-root confirmation:

```sh
licctl --config /etc/licd/licctl.yaml root transition rollback root-2026-to-2031 \
  --reason "successor custody validation failed" \
  --confirm-new-root sha256:<FULL_NEW_ROOT_SHA256> \
  --compromised-new
```

3. Revoke or reissue every licence created by a new-root issuer during overlap. Clients that applied the transition need an authenticated rollback/keyring update; the server database cannot silently change an offline client's trust store.
4. Investigate, generate a different successor when required, and use a new transition ID.

After overlap, do not roll back to a root whose retirement/destruction may already have been communicated. Transition from the active root to a third root or ship an emergency application trust-store update.

## Compromised old root

If an already active transition exists and the new root is known good, perform immediate cutover without waiting for overlap:

```sh
licctl --config /etc/licd/licctl.yaml root transition retire root-2026-to-2031 \
  --reason "confirmed old-root compromise incident IR-204" \
  --confirm-old-root sha256:<FULL_OLD_ROOT_SHA256> \
  --compromised-old
```

The old root becomes `compromised`; an old-root online issuer is removed from memory, new issuance fails closed until a new-root issuer is active, and old-root historical verification is intentionally rejected by exported keyrings.

If no transition was distributed before compromise, a newly created cross-signature from the compromised key is not sufficient evidence. Stop issuance, preserve evidence, ship the replacement root through the signed application/update channel, rotate the issuer, and reissue affected licences. Fully offline old clients cannot learn the compromise; this is an inherent boundary of offline verification.

## Acceptance and audit checks

```sh
licctl --config /etc/licd/licctl.yaml root list
licctl --config /etc/licd/licctl.yaml root transition list
licctl --config /etc/licd/licctl.yaml issuer list
licctl --config /etc/licd/licctl.yaml health
licctl --config /etc/licd/licctl.yaml audit verify
```

Expected lifecycle audit events include `root_key.bootstrapped`, `root_key.registered`, `root_key.activated`, `root_key.retired` or `root_key.compromised`, and `root_transition.activated`, `.retired`, or `.rolled_back`. Audit payloads contain only public IDs, timestamps, reason, actor, and request ID.
