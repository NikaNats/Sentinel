# SDK-less Integration Guide

**Last Updated:** 2026-03-21

This guide shows how to call Sentinel with plain HTTP clients and standard JWT/JOSE tooling.

## Supported Authentication Modes

Sentinel currently supports two request shapes at the API edge:

1. Standard JWT access token plus DPoP proof
2. SD-JWT presentation routed through the composite authentication scheme

## DPoP Basics

For protected endpoints, clients send:

```http
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

The DPoP proof must bind:

- `htm` to the HTTP method
- `htu` to the request URI
- `jti` to a unique proof identifier
- `nonce` to the latest server-issued `DPoP-Nonce`

## First Request And Nonce Challenge

If the client has no usable nonce yet, Sentinel challenges with:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce"
DPoP-Nonce: <server_nonce>
Content-Type: application/problem+json
```

Best practice:

1. Capture the `DPoP-Nonce` header.
2. Mint a fresh proof containing that nonce.
3. Retry the same request once.

## Standard Protected Request

Example:

```http
GET /v1/profile HTTP/1.1
Host: api.sentinel.local
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

## SD-JWT Presentation

When using SD-JWT, the `Authorization` header carries the presentation string. The composite auth scheme routes requests to the SD-JWT handler when the token contains `~` separators.

Example:

```http
Authorization: Bearer <issuer-signed-sd-jwt>~<disclosure>~<kb-jwt>
```

Integration expectations:

- hidden claims must remain undisclosed unless explicitly presented
- invalid disclosures are ignored if their digest is not listed in `_sd`
- stale or tampered key-binding JWTs are rejected

## Finance Transfer With Payload Bounds

`POST /v1/finance/transfer` uses payload-bound authorization checks in addition to baseline authentication.

Send:

```http
POST /v1/finance/transfer HTTP/1.1
Host: api.sentinel.local
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
Idempotency-Key: <uuid>
Content-Type: application/json
```

```json
{
  "transactionId": "txn-1001",
  "amount": 50.00,
  "currency": "GEL",
  "destinationAccount": "acct-42"
}
```

The request succeeds only if the signed authorization details match the request payload bounds.

## SSF Receiver

`POST /v1/ssf/events` is not a public user endpoint. It is intended for a trusted transmitter such as Keycloak.

Protection layers:

- signed SET validation
- issuer validation
- timing-safe auth token comparison when `Ssf:AuthToken` is configured

## Common Error Semantics

| Scenario | Status | Notes |
|---|---:|---|
| Missing or stale DPoP nonce | `401` | `WWW-Authenticate: DPoP error="use_dpop_nonce"` |
| Invalid bearer token | `401` | standard auth failure |
| Insufficient assurance or authorization bounds | `403` | policy or transaction-bound rejection |
| Idempotency conflict | `409` | duplicate in-flight operation |
| Replay cache or other fail-closed dependency outage | `503` | retry after server recovery |

## Client Best Practices

1. Generate a fresh DPoP proof for every request.
2. Cache only the latest nonce, not old proofs.
3. Do not log access tokens, DPoP proofs, SD-JWT disclosures, or SSF shared secrets.
4. Treat `401 use_dpop_nonce` as a recoverable challenge, not a terminal failure.
5. Treat `403` on finance transfer as a bounds or policy failure, not a nonce problem.

## References

- [OPENAPI_3_1.yaml](OPENAPI_3_1.yaml)
- [ARCHITECTURE.md](ARCHITECTURE.md)
