# SDK-less Integration Guide

Last Updated: 2026-03-29
Audience: API consumers integrating with plain HTTP clients

This guide shows how to integrate with Sentinel-protected APIs without a proprietary SDK.

## 1. Integration Model

Sentinel endpoints are mounted by host-defined prefixes. In the reference sample:

- framework endpoints: /api/system/security/*
- business endpoints: /api/v1/documents/* and /api/v1/finance/*

Always verify actual prefix in host routing configuration.

## 2. Authentication Modes

### 2.1 Bearer + DPoP (primary)

Headers for protected routes:

```http
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

DPoP proof binds to:

1. htm (HTTP method)
2. htu (absolute request URL)
3. jti (unique per proof)
4. iat (freshness window)
5. nonce (when challenged)

### 2.2 SD-JWT presentation

Where enabled by host policy, SD-JWT tokens in bearer header are routed to SD-JWT validation paths.

## 3. Nonce Challenge and Retry

If nonce is missing/stale, expect:

```http
401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce"
DPoP-Nonce: <nonce>
```

Client retry algorithm:

1. capture DPoP-Nonce from response
2. mint fresh proof with same request target + new nonce
3. retry once

Do not infinitely loop retries.

## 4. Example Calls (Reference Sample)

### 4.1 Refresh Token

```bash
curl -X POST https://localhost:5001/api/system/security/auth/refresh \
  -H "Authorization: Bearer <token>" \
  -H "DPoP: <proof>" \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token>"}'
```

### 4.2 Create Document (idempotent write)

```bash
curl -X POST https://localhost:5001/api/v1/documents \
  -H "Authorization: Bearer <token>" \
  -H "DPoP: <proof>" \
  -H "Idempotency-Key: 5c970c53-9c7e-40f0-9db0-e1eebd3206a7" \
  -H "Content-Type: application/json" \
  -d '{"title":"Quarterly Report","content":"Sensitive business content"}'
```

### 4.3 Execute Transfer (step-up + RAR-constrained)

```bash
curl -X POST https://localhost:5001/api/v1/finance/transfer \
  -H "Authorization: Bearer <acr3-token>" \
  -H "DPoP: <proof>" \
  -H "Idempotency-Key: c8a7bc3d-9f36-4f3a-934d-ec56fe566807" \
  -H "Content-Type: application/json" \
  -d '{
    "transactionId":"txn-2026-0001",
    "amount":1500.00,
    "currency":"USD",
    "destinationAccount":"acct-99887"
  }'
```

## 5. Error Semantics

| Status | Meaning | Typical Action |
|---|---|---|
| 400 | malformed request / missing required input | fix request payload/headers |
| 401 | auth failure or DPoP nonce challenge | refresh auth context or perform one nonce retry |
| 403 | policy/authorization-bounds failure | do not retry blindly; inspect claims/authorization_details |
| 409 | idempotency conflict / in-flight duplicate | reuse previous operation tracking |
| 503 | fail-closed dependency outage | retry with backoff after service recovery |

## 6. Client Implementation Best Practices

1. Mint a new DPoP proof per request.
2. Keep nonce cache keyed by API audience/route context.
3. Use deterministic UUID idempotency keys for retriable write commands.
4. Never log bearer tokens, DPoP proofs, disclosures, or shared auth tokens.
5. Separate retry logic by status class (401 challenge vs 503 outage vs 403 policy denial).

## 7. Minimal Client Checklist

1. HTTP client with TLS verification enabled.
2. JOSE/JWT support for DPoP proof creation.
3. Clock synchronization (iat drift affects DPoP validity).
4. Header preservation through proxies (DPoP, DPoP-Nonce, WWW-Authenticate).

## 8. References

- OPENAPI_3_1.yaml
- ARCHITECTURE.md
- runbooks/auth-token-issuance.md
