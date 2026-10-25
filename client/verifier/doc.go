// Package verifier verifies licences and online status statements issued by
// licenceserver and maintains the public root-key keyring used to establish
// trust.
//
// The package is intended for desktop applications. It has no dependency on
// the server, its database, or its configuration packages. Applications
// normally embed their initial root public key, open a KeyringStore, and make
// a Verifier from the store's current snapshot.
//
// Verification is fail-closed. Parsing limits are fixed, unknown JSON fields
// and duplicate object keys are rejected, Ed25519 signatures are checked
// before signed payloads are used, and expiry uses the exact half-open
// boundary documented by the protocol. A Clock can be injected for tests.
//
// Root transitions use the dual-signed RKT1 format. KeyringStore applies,
// persists, rolls back, and records compromise decisions atomically: the
// in-memory snapshot changes only after the replacement file has been synced
// and renamed successfully.
package verifier
