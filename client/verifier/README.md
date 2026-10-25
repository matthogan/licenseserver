# Go client verifier and keyring

`github.com/matthogan/licenceserver/client/verifier` is the supported Go
client for the LIC1, ISC1, signed-status, and RKT1 formats. Version 1.0.0 uses
only the Go standard library and imports no server or `internal` package.

## Install

Pin a semantic version in the desktop application's module:

```sh
go get github.com/matthogan/licenceserver/client/verifier@v1.0.0
```

Until the repository's first public tag exists, a client may use a pinned
commit during integration. Production builds should use a signed semantic
version tag and record it in their dependency lock/SBOM.

## Bootstrap and verify

Embed the initial public root in the application binary. Do not download the
bootstrap root on first run.

```go
//go:embed root-public-key.txt
var root []byte

store, err := verifier.OpenKeyringStore(keyringPath, root, verifier.StoreOptions{})
if err != nil {
    return err
}
client, err := store.Verifier(verifier.Options{ProductID: "com.example.app"})
if err != nil {
    return err
}
licence, err := client.VerifyLicence(licenceJSON)
if err != nil {
    switch verifier.CodeOf(err) {
    case verifier.CodeExpired:
        // Show renewal/expiry UX.
    case verifier.CodeWrongProduct:
        // Explain that this licence belongs to another product.
    default:
        // Fail closed and offer support/re-entry UX.
    }
}
```

`ParseRootPublicKey` accepts raw Ed25519 bytes, base64url, hexadecimal, or
PKIX public-key PEM. The keyring contains public material only.

## Root lifecycle

Deliver an RKT1 artefact through an authenticated application update or the
server's authenticated status channel, then apply it before its signed
installation deadline:

```go
transition, err := store.ApplyTransition(rkt1)
```

The store verifies continuity from the active embedded-root chain and both
signatures before atomically replacing its file. During an incident:

```go
err = store.RollbackTransition(transition.TransitionID, "new-root incident", true)
err = store.MarkCompromised(rootKeyID, "confirmed key disclosure")
```

Rollback is intentionally limited to the signed overlap period. Compromise
can leave no usable root; that is a secure fail-closed result and requires an
authenticated application update with a new embedded bootstrap root.

Each process gets immutable verifier snapshots. After a keyring change,
construct a new verifier with `store.Verifier`. `Reload` atomically adopts a
file changed by another process after fully validating it. Coordinate writes
so only one process updates the keyring file.

## Deterministic time and errors

Pass `ClockFunc` in `Options` or `StoreOptions` for deterministic tests. The
package never extends licence expiry with clock skew; skew is only available
for the recent-issuance side of signed status statements.

All expected failures are `*verifier.Error`. Use `CodeOf` or `errors.Is` with
the exported sentinels. Error text is diagnostic, not an API contract.

## Compatibility and releases

The public API follows semantic versioning:

- patch: fixes with no intended API or persisted-format incompatibility;
- minor: backward-compatible APIs and protocol support;
- major: incompatible API, trust, or persisted-keyring changes.

The persisted keyring has its own `schema_version`; unsupported schemas fail
closed. The `Version` constant identifies the package API. Every release must
run the two files in `docs/*test-vector*.json`, `go test -race`, and cross-OS
builds before the repository is tagged `vMAJOR.MINOR.PATCH`.

See the compilable examples under `examples/client/` and the operational
guide in `docs/client-verifier-integration.md`. Cross-language implementations
should follow `docs/licence-test-vector-compatibility.md` for exact signing
inputs, expected result codes and vector-version policy.
