# Keycloak FAPI 2.0 Enforcement (26.6.4)

> **Document ID**: DOC-0016
> **Last Updated**: 2026-08-15
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

## WebAuthn AAL3 (NIST 800-63B) — realm configuration

Added 2026-08-15, verified against a live Keycloak **26.6.4** container
(`--import-realm`, admin API introspection). Both realm files carry the same
configuration; the DAST realm keeps `rpId localhost` and no client binding.

### WebAuthn policy (realm `attributes`)

| Attribute | Value | Rationale |
|---|---|---|
| `webAuthnPolicyRpEntityName` | `Sentinel Government` / `Sentinel DAST` | RP display name |
| `webAuthnPolicyRpId` | `sentinel.local` / `localhost` | per-realm origin anchor |
| `webAuthnPolicySignatureAlgorithms` | `"ES256,RS256"` | **comma-separated string** — arrays fail import (`Cannot deserialize value of type java.lang.String from Array value`) |
| `webAuthnPolicyAttestationConveyancePreference` | `direct` | MDS3-validatable attestation (FR-10) |
| `webAuthnPolicyAuthenticatorAttachment` | `cross-platform` | AAL3-appropriate |
| `webAuthnPolicyRequireResidentKey` | `required` | valid values are `required/preferred/discouraged` (PLAN-0001's `"Yes"` is invalid) |
| `webAuthnPolicyUserVerificationRequirement` | `required` | FR-09 |
| `webAuthnPolicyCreateTimeout` | `300` | seconds |
| `webAuthnPolicyAvoidSameAuthenticatorRegister` | `false` | |
| `webAuthnPolicyAcceptableAaguids` / `webAuthnPolicyExtraOrigins` | `""` | empty string, not array (same deserialization rule) |
| `acr.loa.map` | `{"government-aal3-browser":"acr3"}` | FR-11: `acr3` after this flow |
| brute force (realm level) | `bruteForceProtected: true`, `failureFactor: 5`, `maxDeltaTimeSeconds: 600` | FR-14 (already present) |

### Flow tree (`government-aal3-browser`)

```
government-aal3-browser
├─ [ALTERNATIVE] Cookie
├─ [ALTERNATIVE] Identity Provider Redirector
└─ [ALTERNATIVE] gov-aal3-forms
   ├─ [REQUIRED] Username Password Form
   ├─ [REQUIRED] WebAuthn Authenticator          (UV=required enforced by policy)
   └─ [CONDITIONAL] gov-aal3-otp-recovery
      ├─ [REQUIRED] Condition - user configured   (config: alias=CONFIGURE_TOTP)
      └─ [REQUIRED] OTP Form
```

- `webauthn-register` required action: enabled, **default action** (priority 10)
  → FR-13 (credential enrollment on first login).
- FR-12 (TOTP *only* as recovery after repeated WebAuthn failure) cannot be
  expressed natively: Keycloak has no "N failures → TOTP" condition. The
  implemented form is `Condition - user configured` + OTP Form — TOTP is
  offered to users who configured it. A failure-count trigger requires a
  custom authenticator SPI (documented limitation, not blocking).

### Client binding — not importable, applied via admin API

Single-file realm import on 26.6.4 fails when a client carries
`authenticationFlowBindingOverrides.browser` referencing a *custom* flow:

```
ERROR: Unable to resolve auth flow binding override for: browser
```

The flow imports fine; only the client→flow binding fails. Apply it after
import with the idempotent helper (same kcadm conventions as the FAPI
provisioner):

```bash
KC_ADMIN_URL=https://keycloak:8443 \
KC_REALM=sentinel \
KC_ADMIN_USER=admin KC_ADMIN_PASSWORD=... \
DOCKER_FALLBACK=true infra/keycloak/scripts/apply-browser-flow-bindings.sh
```

Default binding: `sentinel-api-client` → `government-aal3-browser`
(override via `BINDINGS="clientId=flowAlias ..."`).

### kcadm-in-docker fallback notes (Windows/Git Bash)

Each `kcadm` call is a separate `--rm` container, so the session must survive
across invocations — and the image's `user.home` is the **passwd home of the
uid** (`keycloak` user → `/opt/keycloak`, root → `/root`). The fallback uses
`-u root -v kcadm-credentials:/root/.keycloak` + `--entrypoint
/opt/keycloak/bin/kcadm.sh` (the `kc.sh` entrypoint has no kcadm dispatch).
`MSYS_NO_PATHCONV=1` prevents Git Bash from converting `/opt/...` to a Windows
path, and `python3` is detected with a `python` fallback (Windows Store alias).

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