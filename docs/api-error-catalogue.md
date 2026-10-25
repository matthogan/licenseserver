# API Error Catalogue

Every public and administrative HTTP failure uses this envelope:

```json
{"error":{"code":"UNKNOWN_PRODUCT","message":"The requested product does not exist.","request_id":"req_..."}}
```

Messages are intentionally generic. Internal SQL, KMS, S3 and filesystem details are logged only on the server. Codes are stable within API version `v1`.

| HTTP | Code | Meaning |
|---:|---|---|
| 400 | `INVALID_REQUEST` | JSON, fields, state transition input or identifiers are invalid. |
| 400 | `INVALID_ROOT_TRANSITION` | The root-transition artefact, signatures, trust anchor or installation window is invalid. |
| 401 | `ADMIN_AUTH_REQUIRED` | No trusted administrative identity was presented. |
| 403 | `ADMIN_FORBIDDEN` | The identity lacks the required administrative role. |
| 403 | `TRIAL_NOT_AVAILABLE` | Trials are disabled for the product. |
| 404 | `ROUTE_NOT_FOUND` | No API route exists at the requested path. |
| 404 | `RESOURCE_NOT_FOUND` | A non-specific requested resource was not found. |
| 404 | `UNKNOWN_PRODUCT` | The requested product does not exist. |
| 404 | `LICENCE_NOT_FOUND` | The requested licence does not exist. |
| 404 | `TRIAL_NOT_FOUND` | The requested trial does not exist. |
| 404 | `ACTIVATION_INVALID` | No activation code matches the supplied secret. |
| 404 | `ACTIVATION_NOT_FOUND` | The administrative activation record does not exist. |
| 404 | `ACTIVATION_CODE_NOT_FOUND` | The administrative activation-code record does not exist. |
| 404 | `ISSUER_NOT_FOUND` | The requested issuer does not exist. |
| 404 | `ROOT_TRANSITION_NOT_FOUND` | The requested persisted root transition does not exist. |
| 404 | `RECOVERY_DRILL_NOT_FOUND` | The requested persisted recovery-drill report does not exist. |
| 405 | `METHOD_NOT_ALLOWED` | The route exists but does not accept that HTTP method. |
| 409 | `PRODUCT_ALREADY_EXISTS` | The product identifier is already registered. |
| 409 | `PURCHASE_REF_CONFLICT` | A purchase reference was reused with different issuance data. |
| 409 | `IDEMPOTENCY_CONFLICT` | An activation idempotency key was reused for a different request. |
| 409 | `ACTIVATION_EXHAUSTED` | A valid activation code has no remaining capacity. |
| 409 | `LICENCE_REVOKED` | An operation requires an active licence. |
| 409 | `ALREADY_REVOKED` | The target has already been revoked. |
| 409 | `ISSUER_STATE_CONFLICT` | The requested issuer transition conflicts with durable lifecycle state. |
| 409 | `ROOT_TRANSITION_STATE_CONFLICT` | The requested root lifecycle operation conflicts with persisted active/retired/rollback state. |
| 409 | `RECOVERY_DRILL_RUNNING` | A single-flight recovery drill is already running. |
| 409 | `DATA_DELETION_BLOCKED` | Retention/deletion has active-record, legal-hold, export-proof, immutable-residue or suppression-archive blockers; inspect the dry-run plan. |
| 410 | `TRIAL_ALREADY_EXPIRED` | The installation's one-time trial has expired. |
| 410 | `ACTIVATION_EXPIRED` | The activation code is past its expiry boundary. |
| 410 | `ACTIVATION_REVOKED` | The activation or activation code was revoked. |
| 413 | `REQUEST_TOO_LARGE` | The body exceeds `http.max_body_bytes`. |
| 422 | `LICENCE_PAYLOAD_TOO_LARGE` | The canonical licence payload exceeds the signing-provider limit. |
| 429 | `RATE_LIMITED` | A configured persistent abuse limit was exceeded. |
| 500 | `INTERNAL_ERROR` | An unexpected internal failure occurred. |
| 503 | `READ_ONLY` | Mutation is disabled by recovery mode. |
| 503 | `MAINTENANCE` | Mutation is temporarily disabled by persistent maintenance mode; retry using the response's `Retry-After` guidance. |
| 503 | `ARCHIVE_UNAVAILABLE` | Strict durable archive acknowledgement is pending. |
| 503 | `SIGNER_UNAVAILABLE` | No usable issuer or signing provider is available. |
| 503 | `RATE_LIMIT_UNAVAILABLE` | Persistent abuse-protection storage is unavailable; the request failed closed. |

Clients must branch on `error.code`, not the human-readable `message`.
