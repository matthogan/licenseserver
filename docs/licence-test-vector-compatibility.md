# Licence/status test-vector compatibility

Published file: `docs/licence-test-vector-v1.json`  
Schema: `schema_version: 1`  
Content release: `vector_version: 1.1.0`

This file is normative interoperability data for LIC1 licences, ISC1 issuer
certificates and signed online status statements. Every key and signature is
test-only. None is a production trust anchor.

## Version policy

`schema_version` identifies the shape and meaning of the vector container.
Increment it for incompatible structural or semantic changes. Consumers must
fail clearly on an unsupported schema rather than silently reinterpret it.

`vector_version` follows semantic versioning within a schema:

- patch: corrects descriptions or adds equivalent metadata without changing
  an existing case's bytes or expected result;
- minor: adds fields or new cases while retaining every existing case and its
  meaning;
- major: removes/renames cases, changes signed bytes, or changes expected
  outcomes. A major change will normally also introduce a new schema/file.

Once released, signed payload bytes, signing inputs, public keys, signatures
and expected outcomes are immutable. A correction that changes any of them is
published as a new named case/vector version; it does not silently replace the
old interoperability assertion. Test harnesses should require schema 1, accept
compatible 1.x `vector_version` additions, execute every understood case and
report unknown expected-error codes.

The deterministic generator is intentionally checked in:

```sh
go run ./internal/licencefmt/testvectorgen \
  -output docs/licence-test-vector-v1.json
```

It derives Ed25519 keys only from public test labels. Running it twice must
produce byte-identical output.

## Byte construction

All strings are UTF-8. JSON payloads use the exact compact bytes published in
the corresponding `*_payload_json` field. Encode those bytes with RFC 4648
base64url without `=` padding. Do not parse and reformat a payload before
reproducing a published signature.

Line breaks below are one byte `0x0a`. There is no trailing line break.

ISC1 issuer certificate signing input:

```text
UTF8("desktop-issuer:v1\n") || UTF8(payload_base64url)
```

LIC1 licence signing input:

```text
UTF8("desktop-licence:v1\n") || UTF8(issuer_key_id) || 0x0a || UTF8(payload_base64url)
```

Signed-status input:

```text
UTF8("desktop-licence-status:v1\n") || UTF8(issuer_key_id) || 0x0a || UTF8(payload_base64url)
```

Verify each detached signature as raw 64-byte Ed25519 after unpadded
base64url decoding. Envelope dots are separators and are not signed.

## Required outcomes

The top-level LIC1 vector covers valid verification, invalid signature, exact
expiry and wrong product. `outside_authority_case` is cryptographically valid
but has `issued_at` after the issuer certificate's `authority_not_after`; it
must fail as `issuer_unauthorized`, even though its signature is valid.

`signed_status_vectors.cases` contains:

| Case | Expected result |
| --- | --- |
| `valid` | authenticated status `active` |
| `expired` | `expired` at the exact `valid_until` boundary |
| `wrong_nonce` | `malformed` binding failure |
| `wrong_product` | `malformed` binding failure |
| `invalid_signature` | `invalid_signature` |

The public Go client maps these strings to `verifier.ErrorCode`. The internal
server verifier maps them to `ErrIssuerAuthority`, `ErrExpired`,
`ErrMalformed`, and `ErrSignature` respectively. Other languages should expose
equivalent stable result categories even when their human-readable messages
differ.

## Consumer checklist

1. Decode the published root and issuer keys as unpadded base64url.
2. Confirm each decoded Ed25519 public key is exactly 32 bytes.
3. Confirm each signature is exactly 64 bytes.
4. Reconstruct and byte-compare every published signing input.
5. Verify issuer, licence and status signatures independently.
6. Execute each case at its published `at` or `verify_at` instant.
7. Compare stable result codes, not error text.
8. Run the separate RKT1 matrix in
   `docs/root-transition-test-vectors-v1.json` for keyring compatibility.

