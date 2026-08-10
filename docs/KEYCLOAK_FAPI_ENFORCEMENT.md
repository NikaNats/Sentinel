# Keycloak FAPI 2.0 Enforcement (26.6.4)

> **Document ID**: DOC-0016
> **Last Updated**: 2026-08-10
> **Applies To**: `infra/keycloak/realms/sentinel.json`, `infra/keycloak/realms/sentinel-dast.json`, `src/Sentinel.Keycloak`
> **Status**: Live enforcement verified by `Sentinel.Contracts` Keycloak suite (41/41) and live probes

## Context

The realm files previously declared FAPI client policies under the wrong schema
slot. Keycloak 26.6.4 splits policy and profile representations across TWO
separate top-level realm keys:

| Key | Holds | Example |
|---|---|---|
| `clientPolicies` | `policies` + `globalPolicies` only | rule: which clients / conditions |
| `clientProfiles` | `profiles` + `globalProfiles` only | which executors run |

Any `clientProfiles`/`profiles` nested inside `clientPolicies` is silently
ignored at import (`ClientPoliciesRepresentation` deserializes only
`policies`/`globalPolicies`), which dropped **all** enforcement while the realm
reported healthy. The imported realm authenticated with zero client policies
active.

## 26.6.4 executor IDs (bytecode-verified)

| Intended | 26.6.4 executor ID | Notes |
|---|---|---|
| PKCE | `pkce-enforcer` | requires `auto-configure: "true"` (NPE otherwise) |
| DPoP | `dpop-bind-enforcer` | NOT `dpop-enforcer`; `auto-configure: "true"` required |
| Signature | `secure-signature-algorithm` | NOT `secure-signing-algorithm`; config `default-algorithm` + `algorithm` |
| Session | `secure-session` | – |
| HoK (mTLS) | `holder-of-key-enforcer` | NOT deployed, see Gaps |
| PAR | `secure-par-content` | Deployed in `sentinel-dast` (`sentinel-dast.json:231`); main realm enforces via `require.pushed.authorization.requests: true` on `sentinel-api-client` (`sentinel.json:260`) |
| Implicit | `reject-implicit-grant` | `auto-configure: "true"` required |
| ROPC | `reject-ropc-grant` | `auto-configure: "true"` required |

## Live enforcement (verified)

- **DPoP universal**: every token-endpoint call without an RFC 9449 proof →
  `400 DPoP proof is missing`. Access tokens carry `typ: DPoP`, and
  `token_type: "DPoP"` in token responses.
- **Signing**: default/single algorithm PS256 — no RS256 key is ever generated
  because `components` ships a PS256 primary + RSA-OAEP encryption key provider
  (verified via `/admin/realms/sentinel/keys` and JWKS).
- **PKCE**: S256 auto-configured on all clients.
- **Audiences**: `sentinel-api-client` and `sentinel-m2m-worker` token
  audiences via `oidc-audience-mapper`; correct 26.6.4 config keys are
  `included.custom.audience` + `access.token.claim` (the older
  `includedClientAudience` key is a dead Java-field name).
- **Authz-code flow**: interactive login now sends `client_data` and observes
  the `KC_RESTART` cookie (Keycloak 26 login form behavior).
- **eventsListeners**: `["jboss-logging"]` only — the phantom `event-queue`
  listener emitted `KC-SERVICES0083` errors on every event.

## Runtime DPoP client support

The Sentinel runtime signs every outbound token-endpoint call:

- `KeycloakDpopProofFactory` (`src/Sentinel.Keycloak/Dpop/`): single per-process
  RSA key, PS256 (FAPI baseline) RFC 9449 proofs, unique `jti`/`iat` per call,
  optional `ath` claim for refresh.
- `DpopProofDelegatingHandler`: attached to the `keycloak-admin`,
  `KeycloakUmaPermissionService`, `KeycloakTokenRefreshService`, and
  `KeycloakTokenExchangeService` HTTP clients. Caller-supplied `DPoP` headers
  (e.g. a browser-held key forwarded for refresh) are preserved, never
  overwritten.

Verified live against Keycloak 26.6.4: PS256-proof client_credentials → 200,
`token_type=DPoP`; no-proof → 400.

## Gaps (documented deviations)

1. **Interactive login DPoP**: the browser login flow (authorization code +
   PKCE) cannot yet present DPoP proofs at the token endpoint. The API-side
   implementation (backend-for-frontend) must adopt RFC 9449 proof signing in
   the browser layer before interactive logins can run against this posture.
2. **holder-of-key (mTLS)**: `holder-of-key-enforcer` is intentionally not in
   the profiles — no mTLS ingress is provisioned, and enabling it yields
   `400 Client Certification missing for MTLS HoK Token Binding`. Configured
   mTLS is a prerequisite.
3. **PAR client flow**: pushed authorization requests are *enforced* server-side — `secure-par-content` is deployed in `sentinel-dast` (`sentinel-dast.json:231`) and the main-realm `sentinel-api-client` sets `require.pushed.authorization.requests: true` (`sentinel.json:260`). The Sentinel runtime contains no PAR **client** implementation (the `/protocol/openid-connect/par` POST) — any API-driven browser flow that cannot push needs the PAR client-side work before interactive login is exercised against this posture.
4. **DAST realm**: `sentinel-dast` deliberately omits `reject-ropc-grant` /
   `reject-implicit-grant` — `sentinel-dast-victim` uses ROPC by design for
   gray-box scanning.

## Re-import check

```powershell
# after any realm edit, confirm enforcement actually survived import:
curl.exe -k -s https://<kc>/admin/realms/sentinel -H "Authorization: Bearer $token" |
  ConvertFrom-Json | % { $_.clientPolicies.policies.Count; $_.clientProfiles.profiles.Count }
# expect: 1 and 1 - a 0 proves the wrong-slot mistake returned
```