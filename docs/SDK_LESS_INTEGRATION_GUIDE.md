# SDK-less HTTP Integration Guide

> **Document ID**: INT-0001  
> **Last Updated**: 2026-05-30  
> **Audience**: Client developers integrating plain HTTP clients (JS, Mobile, Go, Python, C#)  
> **Target Baseline**: FAPI 2.0 Compliant (PAR + PKCE + DPoP)

This guide provides instructions and raw HTTP wire-format examples to integrate with the Sentinel-protected API gateway without requiring any proprietary SDK.

---

## 1. Integration Model

Sentinel endpoints are mounted dynamically by the hosting application. In the reference sample, the endpoints are mapped under the following prefixes:
- **Security & Identity Endpoints:** `http://localhost:5000/api/system/security/auth/*`
- **Business/Profile Endpoints:** `http://localhost:5000/api/v1/*`

*Always verify the active routing prefix and ports from the host's configuration before starting development.*

---

## 2. Authentication Protocol

### 2.1 Bearer + DPoP (Demonstrating Proof-of-Possession)
To access protected routes, clients must present two headers in their HTTP request:
```http
Authorization: DPoP <access_token>
DPoP: <dpop_proof_jwt>
```

### 2.2 DPoP Proof Structure (RFC 9449)
A DPoP proof is a high-entropy, short-lived JWT signed by the client's private key. The public key **must** be embedded in the JOSE header.

#### 1. Jose Header:
```json
{
  "alg": "ES256",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
    "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE"
  }
}
```

#### 2. JWT Payload:
```json
{
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "htm": "GET",
  "htu": "http://localhost:5000/api/v1/profile",
  "iat": 1774880000,
  "nonce": "server-issued-nonce-value"
}
```
*Note: `htm` (HTTP Method) must be exact uppercase. `htu` (HTTP URI) must be absolute and normalized (no query parameters or fragments).*

### 2.3 SD-JWT Presentation (RFC 9901)
If presenting a Selective Disclosure JWT (SD-JWT), the `Authorization` header must carry the presentation format:
```http
Authorization: Bearer <issuer_jwt>~<disclosure_1>~<disclosure_2>~...~<key_binding_jwt>
```

---

## 3. Nonce Challenge-Response Flow

Sentinel enforces rotating single-use nonces. If the client sends a request without a Nonce, or with a stale Nonce, the server rejects it with a **401 Unauthorized** challenge.

### 1. Server Challenge Response:
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce", algs="PS256 ES256"
DPoP-Nonce: sO7u_STxxEOFgon2yB5QoGcStOmjUyNyvUDocw5BqFs
```

### 2. Client Correction Protocol:
Upon receiving this 401 challenge, the client must:
1.  Extract the `DPoP-Nonce` header value.
2.  Mint a fresh DPoP proof containing this `nonce` value in the payload.
3.  Resend the exact same HTTP request with the new DPoP proof.
4.  Cache this `DPoP-Nonce` locally for subsequent requests. **All successful API responses also return a new `DPoP-Nonce` header — the client must dynamically update its cache with every 2xx response.**

---

## 4. Raw HTTP Wire Examples

### 4.1 Token Refresh (Anonymous Endpoint)
```http
POST /api/system/security/auth/refresh HTTP/1.1
Host: localhost:5000
Content-Type: application/json
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7...

{
  "refreshToken": "opaque-refresh-token-value"
}
```

### 4.2 Create Document (Idempotent Write)
```http
POST /api/v1/documents HTTP/1.1
Host: localhost:5000
Authorization: DPoP eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtp...
DPoP: eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7...
Idempotency-Key: c8a7bc3d-9f36-4f3a-934d-ec56fe566807
Content-Type: application/json

{
  "title": "Quarterly Report",
  "content": "Sensitive financial data..."
}
```

---

## 5. Error Semantics & Defensive Latency

| Status | Meaning | Client Action Required |
|---|---|---|
| **400 Bad Request** | Malformed request or missing header | Correct request schema; do not retry. |
| **401 Unauthorized** | Missing token / invalid signature / Nonce challenge | Perform the Nonce correction protocol or refresh credentials. |
| **403 Forbidden** | Insufficient scope or failed mTLS binding | Do not retry. Contact IAM administrator. |
| **409 Conflict** | Idempotency lock active (request in-progress) | Wait and retry with backoff using the same `Idempotency-Key`. |
| **500 Internal Error** | Internal crash or shielded exception | Treat as an unhandled error; log the `traceId` for SRE triage. |
| **503 Service Unavailable** | Fail-Closed state boundary (e.g., Redis offline) | Implement exponential backoff retry. |

### ⚠️ Integration Best Practice: Client Timeout Configuration
To protect against timing side-channel attacks, Sentinel enforces **Constant-Time Failure Padding with Jitter (0-15ms)** on all failed paths. 
- Because failed requests are artificially delayed up to `100ms+`, client HTTP clients **must not** configure aggressive timeouts.
- **SOTA Recommendation:** Set the client connection and read timeout to **at least 300ms** to prevent false client-side timeouts during timing protection padding.

---

## 6. Minimal Client Checklist

- [ ] Cryptographically secure random number generator active for `jti` and `nonce` creation.
- [ ] Clock synchronized (NTP active — clock drift > 60s rejects DPoP proofs).
- [ ] Base64Url encoder does not append padding characters (`=`).
- [ ] Local cache for the rotating `DPoP-Nonce` updated with **every** successful response.
- [ ] Headers preserved through intermediate proxies (specifically `DPoP`, `DPoP-Nonce`, `WWW-Authenticate`).
