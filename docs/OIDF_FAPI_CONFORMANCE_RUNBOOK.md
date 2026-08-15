# OIDF FAPI 2.0 Conformance Gate — Runbook

> **Document ID**: DOC-0017
> **Status**: ACTIVE
> **Governs**: `.github/workflows/fapi-conformance-gate.yml`, `infra/dast/scripts/run-fapi-conformance.sh`, `infra/keycloak/scripts/provision-fapi-conformance-clients.sh`, `infra/keycloak/fapi2-conformance-profile.json`
> **Objective**: A verifiable **PASSED** OIDF Conformance result against the FAPI 2.0 Security Profile (DPoP, plain_fapi, private_key_jwt), archived as cryptographically bound release evidence.

This runbook closes the three systemic gaps in the previous conformance setup:

1. **Network topology** — the suite is cloud-hosted and must reach the Authorization Server.
2. **API payload** — the runner now speaks the real suite API (`planName` + `variant` as query parameters, configuration as JSON body, plan id from `id`).
3. **Evidence chain of custody** — the runner downloads the certificate PDF and HTML report export, verifies integrity, and writes a SHA-256 manifest.

---

## 1. Phase 1 — Network Topology (mandatory prerequisite)

The OIDF Conformance Suite initiates outbound HTTP requests to the Authorization Server (Keycloak). A private `keycloak.staging.sentinel.local` address can never be reached by the cloud-hosted suite — any run against it fails with connection errors before a single test executes.

| Requirement | Specification | Verification |
|---|---|---|
| Public URL | `https://keycloak.staging.sentinel.io` (or your domain) | `curl -sI https://<host>/realms/<realm>/.well-known/openid-configuration` → 200 |
| TLS | Public CA (Let's Encrypt / ACM), TLS 1.2 **and** 1.3 | `nuclei -t infra/dast/nuclei/templates/tls-version.yaml` (already gating in DAST) |
| DNS | A/CNAME → staging ingress | `Resolve-DnsName <host>` (PowerShell) |
| Issuer | `https://<host>/realms/<realm>` — must match exactly | Discovery document returns 200 from an external network |
| Proxy headers | Keycloak `proxy-headers` = `xforwarded` so `X-Forwarded-Proto/Host` are honored | DPoP `htu`/`htm` checks pass (see §5 matrix) |
| Resource server | Public Sentinel API base URL for the suite's DPoP resource tests (`RESOURCE_URL`) | `https://api.staging.sentinel.io/` reachable over HTTPS |

> **Deployment note**: TLS 1.3 is already enforced by the DAST gate (`tls-version.yaml`); reuse the same ingress/ingress-nginx TLS configuration for staging Keycloak. Do **not** use the self-signed `infra/certs` bundle — the suite will reject the chain.

## 2. Phase 2 — Keycloak FAPI 2.0 Hardening

### 2.1 Client policy profile

`infra/keycloak/fapi2-conformance-profile.json` is a **Keycloak 26.6.4-verified** client profile. Executor IDs were bytecode-verified against the realm export (`infra/keycloak/realms/sentinel-dast.json`); the IDs in generic third-party guides (`dpop-enforcer`, `par-enforcer`, `secure-signing-algorithm`) do **not** exist in 26.6.4 and are silently ignored on import:

| Intended control | 26.6.4 executor (this profile) | Notes |
|---|---|---|
| PKCE S256 | `pkce-enforcer` | `auto-configure: "true"` required (NPE otherwise) |
| DPoP sender-constraint | `dpop-bind-enforcer` | `auto-configure: "true"` required; **not** `dpop-enforcer` |
| PAR | `secure-par-content` | **not** `par-enforcer` |
| Signing algorithms | `secure-signature-algorithm` | `default-algorithm: PS256`, allow `[PS256, ES256]`; **not** `secure-signing-algorithm` |
| Session | `secure-session` | |
| Request object | *(per-client)* | `request.object.signature.alg=PS256` on the client; no verified policy executor in 26.6.4 |
| mTLS HoK | *(not enforced)* | FAPI 2.0 uses DPoP for sender constraint — `holder-of-key-enforcer` is intentionally omitted (no mTLS ingress; enabling it breaks every token call with `400 Client Certification missing`) |

**Apply** (realm API or admin console → Realm Settings → Client Policies → Create Profile → paste executors; then bind a policy selecting `clientId == sentinel-fapi-conformance*` → profile `fapi2-conformance-profile`). After import, re-verify with the check from `docs/KEYCLOAK_FAPI_ENFORCEMENT.md` (profile count must be > 0 — a `0` proves the wrong-slot mistake returned).

### 2.2 Client registration (automated)

`infra/keycloak/scripts/provision-fapi-conformance-clients.sh` registers **two** confidential clients — the suite tests client-mixup attacks and mandates distinct keys per client:

- `sentinel-fapi-conformance` — primary
- `sentinel-fapi-conformance-mixup` — second client, different key

Both get: `clientAuthenticatorType=client-jwt` (private_key_jwt), `token.endpoint.auth.signing.alg=PS256`, `dpop.bound.access.tokens=true`, `pkce.code.challenge.method=S256`, `require.pushed.authorization.requests=true`, and redirect URIs matching the suite callback:

```
https://www.certification.openid.net/test/a/*/callback
https://www.certification.openid.net/test/a/*/callback?dummy1=lorem&dummy2=ipsum
```

The runner extracts the suite-generated per-plan public JWKS from the plan object and passes it to this hook (`FAPI_PROVISION_HOOK`), which converts the JWK to SPKI PEM and stores it as Keycloak's static `jwt.credential.public.key` client attribute. No keys or secrets are committed; the JWKS lives under `artifacts/fapi/jwks/` (gitignored) per run.

> **Manual fallback** (no admin API access): run `run-fapi-conformance.sh` once without the hook; it archives the suite JWKS to `artifacts/fapi/jwks/`; upload `client-jwks.json` via Keycloak admin console → client → Credentials → *Upload JWKS*; then re-run the runner with `FAPI_PROVISION_HOOK` unset (provisioning skipped, plan continues).

## 3. Phase 3 — Suite API integration (what changed and why)

The previous runner posted the entire payload as the JSON body and read `planId`; the real suite API (verified against `openid/conformance-suite` and the authentik/credo-ts suite clients) is:

| Aspect | Previous (broken) | Correct (now implemented) |
|---|---|---|
| Plan creation | `POST /api/plan` JSON body `{planName, server, client}` | `POST /api/plan?planName=...&variant=<json>` + configuration as JSON body |
| Variant matrix | absent | `{"openid":"openid_connect","client_auth_type":"private_key_jwt","sender_constrain":"dpop","fapi_profile":"plain_fapi"}` |
| Plan id | `.planId` | `.id` (fallback `.planId`) |
| HTML report | *(not downloaded)* | `GET /api/plan/<id>/exporthtml` → zip (unpacked into `report/`) |
| Result JSON | polled without `Accept` | `GET /api/plan/<id>/result` with `Accept: application/json` |
| Certificate | *(not downloaded)* | `GET /api/plan/<id>/certificate` with `Accept: application/pdf` (on PASSED only), verified `%PDF` magic bytes |
| Client keys | omitted | suite-generated per-plan JWKS extracted from the plan and provisioned into Keycloak |

Status values handled: `PASSED`, `FAILED`, `REVIEW`, `ERROR`, `INTERRUPTED`, `COMPLETED` (terminal); `RUNNING`/`CREATED` (continue polling, up to `FAPI_MAX_POLL`).

## 4. Phase 4 — CI/CD evidence archiving

`.github/workflows/fapi-conformance-gate.yml` runs on `release/**` + `main` and on demand, against GitHub environment `staging-fapi`. It uploads `artifacts/fapi/` (report pack, result JSON, certificate, manifest) with 365-day retention and the commit SHA in the artifact name. Configure these secrets:

| Secret | Purpose |
|---|---|
| `FAPI_SUITE_URL` | Suite base URL (hosted or self-hosted) |
| `FAPI_SUITE_TOKEN` | Suite API token (OIDF account required for hosted certification runs) |
| `STAGING_KEYCLOAK_ISSUER` | Public issuer, e.g. `https://keycloak.staging.sentinel.io/realms/sentinel-dast` |
| `STAGING_API_RESOURCE_URL` | Public Sentinel API base URL for DPoP resource tests |
| `STAGING_KEYCLOAK_ADMIN_URL` / `_USER` / `_PASSWORD` | Keycloak admin API for the provisioning hook |
| `STAGING_KEYCLOAK_REALM` | Realm to provision (e.g. `sentinel-dast`) |

## 5. Phase 5 — First-run failure matrix (triage playbook)

The suite will fail on the first run — that is expected and is the point. Triage the failures from `artifacts/fapi/fapi-result.json` (failing modules are printed to CI logs) and `artifacts/fapi/report/`:

| OIDF failure area | Root cause (Keycloak/Sentinel) | Remediation |
|---|---|---|
| `iss` parameter missing in AuthZ response | RFC 9207 issuer parameter disabled | Keycloak Realm Settings → Security Defenses → enable *Authorization Response Issuer Parameter* (realm attribute `authorizationResponseIssuerParameter: true`) |
| DPoP `htu`/`htm` mismatch | Reverse proxy strips/rewrites `X-Forwarded-Proto`/`Host` | Keycloak `proxy-headers: xforwarded`; never terminate TLS on a path that alters `Host` |
| `nonce` not bound to DPoP proof | Nonce rotation rejects suite timing | Keep nonce rotation enabled but verify rotation TTL exceeds the suite's request window (Keycloak default is compatible) |
| PAR `request_uri` replay | `request_uri` accepted more than once | `secure-par-content` active (profile above); PAR URIs are single-use with ≤ 60 s TTL by the executor |
| Algorithm confusion (RS256) | JWKS exposes RS256 alongside PS256 | Realm signing keys must be PS256 primary (as `sentinel-dast.json` ships); do not add RS256 providers |
| Error response format | HTML or non-RFC6749 errors on 400/401 | Sentinel's global exception handler returns RFC 6749/RFC 7807 JSON for OAuth endpoints (already covered by `Sentinel.Contracts`) |
| private_key_jwt rejected | Client JWKS not yet trusted | Provisioning order: plan → extract JWKS → provision hook → start. Rerun with the hook or manual upload (§2.2) |
| Client mixup tests fail | Second client missing or same key | Both `sentinel-fapi-conformance` and `...-mixup` registered with **different** per-plan keys |
| Discovery failure | Issuer URL mismatch | `ISSUER_URL` must equal the exact `issuer` of the realm (no trailing slash) and be publicly resolvable |

## 6. Executive sign-off criteria

Once the workflow reports PASSED and `artifacts/fapi/fapi-certificate.pdf` exists (with `%PDF` magic verified) **and** `fapi-evidence-manifest.txt` contains the SHA-256 of every artifact:

1. Download the artifact pack `fapi2-conformance-evidence-<sha>`; verify the manifest hashes locally (`sha256sum -c`).
2. Commit the certificate to `docs/compliance/fapi2-certificate-<YYYY-MM-DD>.pdf` **plus** the manifest (`fapi-evidence-manifest.txt`) as the attestation of provenance.
3. Link the certificate and manifest from `docs/COMPLIANCE_AUDIT_MATRIX.md` (evidence index) — the OIDF suite plan page `plan-detail.html?plan=<id>` (recorded in the manifest) is the third-party verifiable source.
4. Once OIDF formally lists Sentinel on https://openid.net/developers/certification/ add the conformance badge to the root `README.md`.

> **Certification note**: results from a self-hosted suite instance are for internal evidence only; a formal OIDF certificate requires the hosted suite (certification.openid.net) and the Foundation's certification fee/process. Design the gate to target the hosted URL with the repo-owned token; local instances are for pre-flight.

## 7. Local pre-flight checklist

```bash
# 1. syntax gates
bash -n infra/dast/scripts/run-fapi-conformance.sh
bash -n infra/keycloak/scripts/provision-fapi-conformance-clients.sh
# 2. dry payload check (no network): validate the config builder
jq -n --arg i "https://k.example/realms/sentinel-dast/.well-known/openid-configuration" \
      '{server:{discoveryUrl:$i}, client:{client_id:"sentinel-fapi-conformance"}, client2:{client_id:"sentinel-fapi-conformance-mixup"}}'
# 3. profile import sanity (see docs/KEYCLOAK_FAPI_ENFORCEMENT.md re-import check)
# 4. run against a self-hosted suite first, then flip FAPI_SUITE_URL to the hosted suite
```
