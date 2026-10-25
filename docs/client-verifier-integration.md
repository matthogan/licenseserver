# Client verifier/keyring integration

Status: production client package API v1.0.0  
Package: `github.com/matthogan/licenceserver/client/verifier`

## Trust bootstrap

Embed the production Ed25519 root public key in the signed application binary
or installer. The sample roots are test-only and must never ship in a real
product. Do not obtain the first root from the licensing server at runtime:
that would let a network attacker replace both the root and the licence.

Open one keyring file per OS account or service identity. Private keys and AWS
credentials never belong in this file. The store requires owner-only mode on
Unix, rejects symlinks, limits its file to 256 KiB, validates the complete
signed transition chain back to the embedded root, and replaces state through
a synced same-directory temporary file.

## Platform locations

| Client | Recommended per-user keyring | Notes |
| --- | --- | --- |
| Windows | `%LOCALAPPDATA%\Vendor\Product\licensing\keyring.json` | Install for the same account that runs the app; use installer ACLs for machine-wide state. |
| Linux desktop | `$XDG_CONFIG_HOME/vendor/product/licensing/keyring.json` | `os.UserConfigDir` selects the normal location. |
| Raspberry Pi service | `/var/lib/product/licensing/keyring.json` | Pre-create `/var/lib/product` owned by the unprivileged service account. |

Compilable integrations are in `examples/client/windows`,
`examples/client/linux`, and `examples/client/raspberrypi`.

## Application flow

1. Open the store with the embedded root.
2. Create a verifier bound to the application's exact product ID.
3. Read the licence with a bounded file/API read and call `VerifyLicence`.
4. Convert `ErrorCode` to UI state; log the code, never the licence or subject.
5. Authorize capabilities with `Licence.Can`, not licence-type conditionals.
6. If online status is required, generate a fresh unpredictable nonce, bind it
   in `StatusRequest`, and call `VerifySignedStatus` on the response bytes.
7. Apply authenticated RKT1 updates before `expires_at`, then create a fresh
   verifier snapshot.

The explicit-time functions (`VerifyLicence`, `VerifySignedStatus`, and
`VerifyTransition`) support deterministic policy tests. Runtime code normally
uses a `Verifier` with the system clock. A backward wall-clock jump can make a
licence not-yet-valid; a forward jump can expire it. Applications needing
strong rollback resistance should persist a last-known-good signed status time
or use an OS monotonic/secure-time facility as an additional product policy.

## Root incidents

- New root problem during overlap: call `RollbackTransition`; pass
  `compromiseNew=true` for disclosed or suspect key material.
- Old root disclosure after transition: call `MarkCompromised` for the old
  key; already-authorized new-root licences continue to verify.
- Active/only root disclosure: mark it compromised and fail closed. Recovery
  requires a signed application update that embeds a newly established root;
  an unsigned network response cannot repair a lost trust anchor.
- After any state change, retain the old application logs and keyring copy as
  incident evidence without placing them in source control.

Rollback is rejected at and after `overlap_until`. This avoids locally
re-authorizing an old root after the signed cutover boundary.

## Release contract

The package uses semantic versioning with repository tags. Public exported
identifiers and keyring schema 1 remain compatible throughout v1. Protocol
parsers always fail closed on unknown schema versions. Before a release:

```powershell
go test ./client/verifier ./examples/client/...
$env:CC='C:\bin\mingw64\bin\gcc.exe'
$env:CGO_ENABLED='1'
go test -race ./client/verifier
go test ./...
```

CI additionally builds Windows amd64/arm64 and Linux amd64/arm64/armv7. The
package tests consume both published interoperability files:

- `docs/licence-test-vector-v1.json`
- `docs/root-transition-test-vectors-v1.json`

### Consuming the licence/status vector in another language

Require `schema_version == 1`, then inspect the semantic `vector_version`.
Decode base64url without padding and compare the decoded bytes with each
published compact `*_payload_json` string. Construct the ISC1, LIC1 and status
inputs from their ASCII domain separator, issuer key ID where applicable, one
literal LF byte, and the published payload encoding. Compare the resulting
bytes to `*_signing_input` before verifying the raw Ed25519 signature.

Execute the signed outside-authority licence and every
`signed_status_vectors.cases` entry at its published time and request binding.
Compare `ErrorCode`, never localized error text. The normative byte formulas,
expected outcomes and vector-version compatibility rules are documented in
`docs/licence-test-vector-compatibility.md`.

Tag `v1.0.0` only after those checks pass in the release repository. Future
breaking API or trust-store changes require v2 and a migration guide.
