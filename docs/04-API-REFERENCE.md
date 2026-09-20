# 04 — API Reference

> Contract sources: `src/Sentinel.AspNetCore/Endpoints/*` (framework endpoints), `samples/Sentinel.Sample.MinimalApi/Endpoints/*` (reference-host business endpoints), `docs/OPENAPI_3_1.yaml` (machine-readable contract, `info.version: 2026-08-20`), `src/Sentinel.AspNetCore/Errors/ErrorCodes.cs` (RFC 7807 type URIs). The framework is prefix-agnostic: `MapSentinelSecurity(prefix)` mounts all security routes under a host-chosen prefix (default `v1`; the reference host uses `v1`, the published OpenAPI contract documents the deployment prefix `/api/system/security`).

## 1. Conventions

### 1.1 Authentication schemes

| Scheme | Meaning |
|---|---|
| `Authorization: DPoP <access-token>` + `DPoP: <proof-jwt>` | Sender-constrained request. The JwtBearer handler strips the `DPoP ` prefix (`OnMessageReceived`); the DPoP middleware validates the proof and binds `cnf.jkt`. |
| `Authorization: Bearer <access-token>` | Accepted by authentication, but a token whose `cnf` contains `jkt` (DPoP-bound) **without** a validated proof is rejected 401 by `MtlsBindingMiddleware` (`/errors/dpop-binding-required`); a token bound with `x5t#S256` requires the matching client certificate. |

Access tokens must carry: valid issuer/audience/signature (PS256/ES256), unexpired `exp` with **zero clock skew in production**, an `acr` claim (enforced twice — by `AcrValidationMiddleware` for every authenticated request, and by the framework **default authorization policy** `RequireAuthenticatedUser().RequireClaim("acr")` installed by `AddApplicationLayer`), and — when `FeatureFlags:Auth:JtiReplayEnforcement=true` — a single-use `jti`. Framework policy names available to endpoints: `RequireAcr3` (ACR rank ≥ acr3) and `ElevatedAccess` (acr3 **and** `security_clearance` ∈ {`top-secret`, `classified`}).

### 1.2 Standard response headers

| Header | Direction | Behavior |
|---|---|---|
| `DPoP-Nonce` | response | Server-issued nonce (challenge on 401 `use_dpop_nonce`; rotation on 2xx/3xx success). CORS-exposed. |
| `WWW-Authenticate` | response | Challenge grammar per [03 §2.3](./03-SECURITY-AND-CRYPTOGRAPHY.md) (DPoP) and RFC 6750-style `Bearer error="insufficient_user_authentication"` (step-up). CORS-exposed. |
| `X-Correlation-ID` | both | Echoed if supplied, else generated (W3C trace id or GUID `N` format). |
| `Idempotency-Key` | request | Required (UUID) on idempotency-protected operations. CORS-allowed. |
| `SSF-Auth-Token` | request | Optional shared-secret header for SSF webhook when `Ssf:RequireAuthToken=true`. CORS-allowed. |
| Security headers | response | HSTS/CSP/nosniff/DENY/no-referrer/Permissions-Policy/no-store on every response ([02 §3.1](./02-ARCHITECTURE.md)). |

### 1.3 Error model (RFC 7807 `application/problem+json; charset=utf-8`)

Canonical type URIs from `ErrorCodes` plus middleware/filter-emitted types:

| Type URI | Emitted by |
|---|---|
| `/errors/internal-server-error`, `/errors/internal` | `ErrorCodes`; host exception handler (adds `traceId` extension) |
| `/errors/unauthorized` | `ErrorCodes`; JwtBearer `OnChallenge` |
| `/errors/token-theft-detected` | refresh-token reuse detection (`AuthEndpoints.RefreshTokenAsync`) |
| `/errors/missing-dpop-proof`, `/errors/invalid-dpop-proof` | `ErrorCodes`; `DpopValidationMiddleware` (401 body type) |
| `/errors/dpop-binding-required` | `MtlsBindingMiddleware.RejectDpopUnbound` |
| `/errors/mtls-binding-failed` | `MtlsBindingMiddleware.Reject` (403) |
| `/errors/service-unavailable` | DPoP middleware fail-closed 503 |
| `/errors/invalid_token` | `AcrValidationMiddleware` (missing `acr`) |
| `/errors/insufficient-acr`, `/errors/session-too-old` | `AcrStepUpAuthorizationFilter` (extensions `required_acr`, `max_age`) |
| `/errors/missing-idempotency-key`, `/errors/invalid-idempotency-key`, `/errors/idempotency-conflict`, `/errors/idempotency-unavailable` | `IdempotencyFilter` |
| `/errors/rate-limit-exceeded` | host rate-limiter `OnRejected` |
| `/errors/ssf-unauthorized`, `/errors/ssf-processing-failed` | `SsfEndpoints` |
| `/errors/invalid-request` | various handlers (e.g. finance transfer validation) |
| `/errors/authorization-bounds-exceeded`, `/errors/missing-authorization-detail` | RAR enforcement (`ErrorCodes`, `SurgicalAuthorizationFilter` 403) |
| `/errors/invalid-captcha`, `/errors/terms-not-accepted`, `/errors/weak-password`, `/errors/invalid-current-password`, `/errors/mfa-not-configured` | `ErrorCodes` (registration/password flows) |
| `/errors/invalid-or-expired-token`, `/errors/token-already-consumed`, `/errors/verification-token-store-failed` | `ErrorCodes` (email-verification token flows) |

Domain-level error codes (non-HTTP) are centralized in `SecurityErrors` (`src/Sentinel.Security.Abstractions/Results/SecurityErrors.cs`), e.g. `identity.conflict`, `validation.weak_password`, `captcha.invalid`, `token.invalid`, `dpop.proof_invalid`, `dpop.nonce_invalid`, `dpop.signature_invalid`, `session.expired`.

## 2. Framework Security Endpoints (`MapSentinelSecurity`)

Route group: `{prefix}` with tag "Sentinel Security API"; sub-groups `/auth`, `/ssf`. Registered via `SentinelEndpointExtensions.MapSentinelSecurity` → `MapAuthEndpoints`, `MapSsfEndpoints`, `MapTokenExchangeEndpoints`, `MapBackchannelLogoutEndpoints`.

### 2.1 `POST {prefix}/auth/refresh` — `RefreshToken`

- **Auth**: `AllowAnonymous` (the refresh token is the credential); DPoP header forwarded to the refresh service for sender-constrained rotation.
- **Request**: `{ "refreshToken": "…" }` (`RefreshRequest`).
- **Success 200**: `{ "access_token": "…", "refresh_token": "…" }` (`TokenResponseDto`; snake_case via `JsonPropertyName`). The rotated refresh token comes from Keycloak (`KeycloakTokenRefreshService` detects `refresh_token` in the response and reports rotation).
- **400**: blank refresh token ("Refresh token is required.").
- **401 `/errors/token-theft-detected`** (title "Session Terminated"): refresh-token **reuse** detected (`result.IsReuseDetected`) — the Keycloak-side revocation of the whole grant is the expected consequence.
- **401**: "Invalid refresh token".
- Client IP is privacy-hashed (`SecurityContextHasher.HashIp`) before being passed to the service.

### 2.2 `POST {prefix}/auth/change-password` — `ChangePassword`

- **Auth**: required + `.RequireAcrStepUp("acr3", 5 min)` + `.RequireIdempotency()`.
- **Request**: `{ "newPassword": "…" }` (`ChangePasswordRequest`).
- **204** on success; **400** invalid payload; **401** step-up challenge (`/errors/insufficient-acr` or `/errors/session-too-old` + `WWW-Authenticate`); **409** idempotency in-progress; **503** idempotency store unavailable. (`Produces` metadata: 204/400/401/409/503.)

### 2.3 `POST {prefix}/auth/logout` — `Logout`

- **Auth**: required + idempotency.
- Back-channel session deletion: extracts `sid`/`sub` from the token (comment: "Eliminates plaintext Refresh Token transmission over HTTP during logout"); blacklists `sid` with TTL `KeycloakOptions.ResolveSessionBlacklistTtl()` (= `SsoSessionMaxLifespanSeconds`, default 28 800 s / 8 h); calls `IAuthRevocationService.RevokeSessionAsync(sub, sid)`; failed Keycloak revocation increments counter `auth.keycloak.revocation_failures`.
- **400** when `sid`/`sub` missing; **204** on success; **409/503** per idempotency state machine.

### 2.4 `GET {prefix}/auth/sessions` — `GetActiveSessions`

- **Auth**: required. **200** with the subject's active Keycloak sessions (`UserSessionInfo` list from `KeycloakAuthRevocationService.GetActiveSessionsAsync`); **401 `/errors/unauthorized`** without `sub`.

### 2.5 `DELETE {prefix}/auth/sessions/{sessionId}` — `RevokeSession`

- **Auth**: required + idempotency. **204** revoked; **404** unknown session; **400** blank id; **401** missing `sub`.

### 2.6 `POST {prefix}/auth/logout-all` — `GlobalLogout`

- **Auth**: required + idempotency.
- Behavior (verbatim from `AuthEndpoints.GlobalLogoutAsync`): blacklists the current session (`sid`) with `ResolveSessionBlacklistTtl()`, then `IAuthRevocationService.RevokeAllSessionsAsync(sub)` (Keycloak admin `POST users/{sub}/logout`).
- **204** on success; **500 `/errors/internal-server-error`** ("Failed to process global logout.") when the IdP revocation reports failure; **401** without `sub`; **409/503** per idempotency state machine.

### 2.7 `DELETE {prefix}/auth/account` — `DeleteAccount`

- **Auth**: required + idempotency.
- Behavior: blacklists the current `sid`; revokes all sessions (result intentionally discarded); then **soft-deletes** the account via `IAuthRevocationService.DeleteAccountAsync(sub)` (Keycloak adapter issues `DELETE users/{sub}`).
- **204** on success; **500 `/errors/internal-server-error`** ("Failed to delete account.") when the delete reports failure; **401/409/503** as above.

### 2.8 MFA surface (stubs)

`POST {prefix}/auth/mfa/totp/setup`, `POST …/totp/verify`, `DELETE …/totp`, `GET …/recovery-codes`, `POST …/recovery-codes/regenerate` are mapped with `RequireAuthorization()` and return **501 Not Implemented** (`StatusCodes.Status501NotImplemented` declared in `Produces` metadata). Tracked as finding **F-03** in [09 §4](./09-COMPLIANCE-AND-TRACEABILITY.md).

### 2.9 `POST {prefix}/auth/token-exchange` — `ExchangeExternalToken`

- **Auth**: `AllowAnonymous` (the external token is the credential) — but a **`DPoP` proof header is mandatory**: missing proof ⇒ **400** type `/errors/missing-dpop-proof` ("DPoP proof is required."), so exchanged tokens are sender-constrained from birth.
- **Request**: `{ "externalToken": "…", "providerName": "…", "codeVerifier": "…" }` (`TokenExchangeRequest`); any blank field ⇒ **400**.
- **Success 200**: `TokenExchangeResponseDto` — `{ "access_token", "refresh_token", "token_type", "expires_in", "scope" }`; `token_type` defaults to `"DPoP"` when the IdP omits it.
- **401**: exchange produced no access token ("Token exchange failed.").
- Downstream: `KeycloakTokenExchangeService` posts `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with `subject_token_type`/`requested_token_type = urn:ietf:params:oauth:token-type:access_token` (externally-confirmed token exchange pattern); the outbound call is signed with a runtime DPoP proof (`KeycloakDpopProofFactory`).

### 2.10 `POST {prefix}/auth/backchannel-logout` — `BackchannelLogout`

OIDC Back-Channel Logout intake (source comments cite RFC 9413). `.AllowAnonymous()` and `ExcludeFromDescription()` — "Backchannel endpoints are not documented in public API spec"; the caller is not authenticated, the **logout token JWT itself** is the credential (`ILogoutTokenValidator` → `src/Sentinel.Infrastructure/Auth/LogoutTokenValidator.cs`).

- **Request**: `application/x-www-form-urlencoded`, field `logout_token`.
- **400**: missing/blank form field.
- **200**: token validated and `sid` blacklisted with `ResolveSessionBlacklistTtl()`; **also 200 when validation fails** (deliberate: "must not indicate token validation errors per RFC for security") and on unexpected exceptions.
- **503**: `SecurityInfrastructureException` (blacklist store outage — "could not persist revocation state") or cancellation.

### 2.11 `POST {prefix}/ssf/events` — SSF/CAEP intake

Implements Shared Signals Framework event reception (source cites RFC 8936); `.AllowAnonymous()`.

| Step | Behavior | Response |
|---|---|---|
| Feature flag | `Ssf:Enabled=false` | **404** (clients "should assume SSF not supported") |
| Webhook auth | `Ssf:RequireAuthToken=true`: `SSF-Auth-Token` header must match `Ssf:AuthToken` via SHA-256-normalized **constant-time** comparison | **404** on mismatch ("Route obfuscation: obfuscating endpoint existence") |
| Payload | Raw JWT with `Content-Type: application/secevent+jwt`, or JSON `{ "set": "<jwt>" }` | **400** problem "SET token is required…" when absent |
| Processing | `SsfEventProcessor.ProcessAsync` | **202** on success |
| Signature/issuer invalid | `result.IsUnauthorized` | **401** type `/errors/ssf-unauthorized` |
| Event handling failure | fail-closed on any event | **400** type `/errors/ssf-processing-failed` |

`SsfEventProcessor` (`src/Sentinel.SSF/SsfEventProcessor.cs`) enforces temporal bounds (`iat` age ≤ `MaxEventAgeSeconds + AllowedClockSkewSeconds`, and not in the future beyond skew; defaults 300 + 300 s) and handles three IANA/CAEP event-type URIs:

| Event type URI | Action |
|---|---|
| `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | Blacklist `sid` (payload `{sid?, sub?}`) for `SessionRevocationTtlSeconds` (default 28 800 s); subject-level revocation when `sid` omitted |
| `https://schemas.openid.net/secevent/caep/event-type/user-status-changed` | Revoke all sessions for subject (payload `{sub?}`) |
| `https://schemas.openid.net/secevent/caep/event-type/credential-change` | Revoke all sessions for subject (payload `{sub?}`) |

Infrastructure outage propagates (endpoint 5xx) so the upstream IdP retries — "fail-closed revocation guarantee" (any single event failure fails the whole SET).

## 3. Reference-Host Business Endpoints (`samples/Sentinel.Sample.MinimalApi`)

| Route | Auth | Filters | Contract |
|---|---|---|---|
| `GET /` | anonymous | — | `SampleInfoResponse(service, docs, endpoints)` discovery document |
| `GET /healthz` | anonymous | — | `{ "status": "ok", "utc": … }`; also the k8s liveness/readiness target |
| `GET v1/documents` | policy `ScopeDocumentsRead` | — | Paged `DocumentSummaryDto(id, title, encryptedBytes, createdUtc)` |
| `POST v1/documents` | policy `ScopeDocumentsWrite` | — | `CreateDocumentRequest(title, content)`; content stored **envelope-encrypted** (`IEnvelopeEncryptionService`; `DocumentRecord.EncryptedContent`) → `DocumentDetailDto` |
| `GET v1/documents/{id}` / `DELETE v1/documents/{id}` | scope policies | — | 200 / 204; 404 unknown |
| `POST api/v1/finance/transfer` | `RequireAuthorization()` | `RequireAcrStepUp("acr3", 5 min)` + `RequireIdempotency()` + `SurgicalAuthorizationFilter` (RAR) | `TransferRequest(transactionId, amount, currency, destinationAccount)` → `TransferResponse(status, transactionId, message, processedAtUtc)`; 400 validation problems (`/errors/invalid-request`), 403 `/errors/authorization-bounds-exceeded` on RAR violation, 401 step-up, 409/503 idempotency |
| `GET v1/profile`, `GET v1/security-context`, `GET v1/test/protected`, `GET v1/test/step-up` | group default `RequireAuthorization()`; `v1/test/step-up` requires policy `Policies.RequireAcr3` | — | `SecurityContextDto`, `UserProfileDto`, `ProtectedTestResponseDto` |

> **Prefix note**: the *sample* host mounts security routes at `v1` and showcase routes at `v1` (`MapShowcaseEndpoints("v1")`), so live paths are e.g. `/v1/auth/refresh` and `/v1/profile` (this is what `dpop-dance.sh` exercises at `https://sentinel:8080/v1/profile`). The **CI contract host** (`tests/Sentinel.Tests.Load/Program.cs`, the `AdversarialTestHost` used by Gate 4/5 and Schemathesis) maps representative stubs at the canonical deployment prefixes `/api/system/security/*`, `/api/v1/documents`, `/api/v1/finance`, `/api/v1/showcase/*` — these are the paths frozen in `docs/OPENAPI_3_1.yaml` and the v1 baseline. Consumers deploying behind a gateway should mount `MapSentinelSecurity("api/system/security")` (or any prefix) to match the published contract.

**RAR enforcement detail** (`SurgicalAuthorizationFilter`): extracts `authorization_details` from the authenticated principal (`RarExtensions.GetAuthorizationDetails`), serializes the transfer payload, and calls `IRarValidator.ValidateByType(details, "urn:sentinel:finance:transfer", payloadJson)`. `RarValidator` routes to the highest-weight matcher for the type (`FinancialAuthorizationMatcher`); bounds checks use `RarValidationOptions` (`MonetaryPrecisionTolerance = 0.0001m`, `MaxAuthorizationDetailsCount = 100`, case-sensitivity/exact-match switches). Violation ⇒ **403** with warning log `RAR_VALIDATION_FAILED`.

Authorization policies registered by the host: `ScopeProfile` (`scope=profile`), `ScopeDocumentsRead` (`documents:read`), `ScopeDocumentsWrite` (`documents:write`) via `ScopeRequirement`; ACR policies via `AcrRequirement` + rank table.

## 4. Idempotency Contract (Stripe-style semantics)

`IdempotencyFilter` (`src/Sentinel.AspNetCore/Filters/IdempotencyFilter.cs`) + `RedisIdempotencyStore`:

1. `Idempotency-Key` header **required** and must parse as a **GUID** → else 400 (`/errors/missing-idempotency-key` / `/errors/invalid-idempotency-key`).
2. Store key: `idempotency:{sub}:{key}` (`sub` from the authenticated principal, `"anonymous"` fallback).
3. State machine on the shared key:

```text
TryAcquireAsync (SET key "IN_PROGRESS" NX EX 5min)
 ├─ Acquired    → execute endpoint
 │                ├─ 2xx   → MarkCompletedAsync(key, {status, contentType, body}, TTL 24h)
 │                └─ non-2xx / exception → ReleaseAsync(key)   (retryable)
 ├─ InProgress  → 409 /errors/idempotency-conflict ("A request with this Idempotency-Key is currently running.")
 │                (up to 3 acquisition attempts on read races; contention → auth.idempotency.lock_contention_total)
 └─ Completed   → replay cached response bytes verbatim (status + content-type + body);
                  cached-without-body → 204
Store outage    → 503 /errors/idempotency-unavailable (fail-closed; Critical log)
```

Concurrency proof: `tests/Sentinel.Tests.Concurrency/IdempotencyConcurrencyTests.cs` (Coyote systematic scheduling, 1000 iterations in CI).

## 5. Rate-Limit Contract

429 responses (global chained limiter, [02 §5](./02-ARCHITECTURE.md)) carry `Retry-After: 10` and problem type `/errors/rate-limit-exceeded`. Identity partition key derivation: JWT `sub` from `DPoP ` or `Bearer ` scheme when parseable, else remote IP, else `ip:anonymous` — so anonymous floods are isolated per IP while authenticated clients get per-subject quota (20 req/10 s) on top of the per-IP network floor (100 req/10 s).

## 6. Client Integration Walkthrough — the DPoP "dance"

Derived from the repository's own E2E scripts (`dpop-dance.sh`, `dpop-e2e.sh`, `tests/scripts/mint-dpop-pool.mjs`, `tests/scripts/sign-dpop-proof.mjs`) and `docs/SDK_LESS_INTEGRATION_GUIDE.md`.

### 6.1 Proof structure the server accepts

```json
// Header
{ "typ": "dpop+jwt", "alg": "PS256", "jwk": { "kty": "RSA", "n": "…", "e": "AQAB", "alg": "PS256", "use": "sig" } }
// Payload
{ "jti": "<unique>", "htm": "GET", "htu": "https://api.example/v1/profile", "iat": 1789900000, "nonce": "<server nonce, when challenged>" }
```

Constraints enforced server-side: `alg` ∈ configured allow-list; `jwk.alg` (if present) == `alg`; no private members; `htu` without query/fragment; `iat` within `[now−60−skew, now+skew]` (defaults); proof ≤ 8192 chars; `jti` single-use. ML-DSA proofs use `"kty":"ML-DSA"` with raw `x` (1312/1952/2592 bytes for 44/65/87) — see [03 §5](./03-SECURITY-AND-CRYPTOGRAPHY.md).

### 6.2 End-to-end sequence (nonce challenge–response)

```bash
# 0) Acquire a DPoP-bound access token from the authorization server
#    (Keycloak realm 'sentinel': client 'sentinel-api-client' has
#     dpop.bound.access.tokens=true + PKCE S256). The token endpoint call
#     itself needs a DPoP proof (realm fapi2-security-profile).

# 1) First API call WITHOUT nonce — expect 401 + challenge when the server requires one
curl -sk -D - -o /dev/null https://localhost:5260/v1/profile \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $PROOF1"
#   HTTP/1.1 401 Unauthorized
#   WWW-Authenticate: DPoP error="use_dpop_nonce", algs="PS256 ES256 EdDSA ML-DSA-65"
#   DPoP-Nonce: <server-nonce>

# 2) Re-sign the proof including  "nonce": "<server-nonce>"  and retry
curl -sk https://localhost:5260/v1/profile \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $PROOF2_WITH_NONCE"
#   HTTP/1.1 200 OK
#   DPoP-Nonce: <rotated-nonce>   ← persist and use on the NEXT request
```

Client rules (all server-verified): one fresh `jti` per proof; sign `htm`/`htu` per request (no reuse across methods/paths); treat every `DPoP-Nonce` response header as the nonce for the next request; on 401 `use_dpop_nonce` re-sign and retry **once**; on 503 + `Retry-After` back off (infrastructure fail-closed, not a client error).

### 6.3 Node.js minimal signer (mirrors `tests/scripts/sign-dpop-proof.mjs`)

```js
import { webcrypto as crypto } from "node:crypto";

const key = await crypto.subtle.generateKey({ name: "RSASSA-PSS", modulusLength: 2048,
  publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256" }, true, ["sign","verify"]);
const jwk = await crypto.subtle.exportKey("jwk", key);           // {kty:"RSA", n, e, …}
const b64u = (buf) => Buffer.from(buf).toString("base64url");

export async function dpopProof(method, url, nonce) {
  const header = { typ: "dpop+jwt", alg: "PS256",
    jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "PS256", use: "sig" } };
  const payload = { jti: crypto.randomUUID(), htm: method, htu: url,
    iat: Math.floor(Date.now()/1000), ...(nonce ? { nonce } : {}) };
  const si = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PSS", saltLength: 32 },
    key, new TextEncoder().encode(si));
  return `${si}.${b64u(sig)}`;
}
```

### 6.4 Access-token binding requirements

Tokens minted for DPoP clients carry `cnf.jkt = base64url(SHA-256(canonical JWK))` (RFC 7638 thumbprint of the *client's* proof key — computed identically by `DpopThumbprintComputer`). The server rejects any DPoP-scheme request whose proof thumbprint ≠ `cnf.jkt` (`jkt_mismatch`). mTLS-bound (M2M) clients carry `cnf["x5t#S256"]` instead and must present the matching certificate (Keycloak client `sentinel-m2m-worker` has `tls.client.certificate.bound.access.tokens=true`).

## 7. Published OpenAPI Contract

`docs/OPENAPI_3_1.yaml` (title "Sentinel API Contract (Framework + Reference Host)", version `2026-08-20`) documents operationIds: `getServiceInfo`, `getHealth`, `refreshToken`, `changePassword`, `logout`, `getActiveSessions`, `revokeSession`, `globalLogout`, `deleteAccount`, `setupTotp`, `verifyTotp`, `deleteTotp`, `getRecoveryCodes`, `regenerateRecoveryCodes`, `exchangeExternalToken`, `backchannelLogout`, `receiveSsfEvent`, `listDocuments`, `createDocument`, `getDocument`, `deleteDocument`, `executeTransfer`, `getSecurityContext`, `getShowcaseProfile`, `getShowcaseProtected`, `getShowcaseStepUp`.

Contract governance: the document is regenerated in CI from a running host and diffed against `tests/Sentinel.Contracts/OpenApi/Baselines/v1-baseline.json` ("Gate 5 — OpenAPI Schema Drift Audit"); compatibility tests (`RequestSchemaCompatContractTests`, `ResponseSchemaCompatContractTests`, `SecuritySchemeContractTests`, `EndpointAvailabilityContractTests`) fail breaking changes; `scripts/generate_openapi_baseline.py` regenerates baselines. Schemathesis 4.23.0 fuzzes the live contract in the `schemathesis-fuzzing` job (`--checks not_a_server_error`).
