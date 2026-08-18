# OIDF FAPI 2.0 Conformance Gate — Runbook

> **Document ID**: DOC-0017
> **Status**: ACTIVE
> **Governs**: `.github/workflows/fapi-conformance-gate.yml` (remote gate), `security-pipeline.yml` → `fapi-local-preflight` (local pre-flight), `infra/dast/scripts/run-fapi-conformance.sh`, `infra/keycloak/scripts/provision-fapi-conformance-clients.sh`, `infra/keycloak/fapi2-conformance-profile.json`, `infra/fapi-conformance/` (local suite stack), `infra/k8s/staging/` (staging AS manifests), `infra/staging/provision-staging-tls.sh`, `infra/staging/verify-fapi-readiness.sh`
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

### 1.1 Staging manifests (in-repo)

| Artifact | Purpose |
|---|---|
| `infra/k8s/staging/keycloak-staging.yaml` | Namespace + Keycloak deployment (TLS-only, `KC_HTTPS_PROTOCOLS=TLSv1.3`, `KC_PROXY_HEADERS=xforwarded`, DPoP+PAR features, realm import) + Service. Checkov-clean (mirrors the `infra/k8s/keycloak-deployment.yaml` hardening). |
| `infra/k8s/staging/keycloak-staging-ingress.yaml` | ingress-nginx ingress terminating `keycloak.staging.sentinel.io` from the `keycloak-staging-tls` secret; must preserve `Host`/`X-Forwarded-Proto` for DPoP `htu`/`htm` checks. |
| `infra/staging/provision-staging-tls.sh` | Provisions the public-CA certificate into secret `keycloak-staging-tls` — Let's Encrypt via cert-manager (`--issuer cert-manager`, default) or AWS ACM (`--issuer acm`). Idempotent; verifies DNS and certificate validity before exiting 0. Re-run with `STAGING_HOST=api.staging.sentinel.io STAGING_TLS_SECRET=sentinel-api-staging-tls` for the resource server. |
| `infra/k8s/staging/sentinel-api-staging.yaml` | Staging **resource server**: Sentinel API deployment + service (TLS on `:8080` from `sentinel-api-staging-tls`), `redis-staging` revocation store, `init-db` creating `sentinel_dev` on `postgres-staging`, and network policies (ingress-nginx → `:8080`; egress to DNS / postgres / redis / ingress-nginx for the public JWKS). Checkov-clean (mirrors the `infra/k8s/sentinel-api-deployment.yaml` hardening). |
| `infra/k8s/staging/sentinel-api-staging-ingress.yaml` | ingress-nginx ingress terminating `api.staging.sentinel.io` from the `sentinel-api-staging-tls` secret; must preserve `Host`/`X-Forwarded-Proto` for DPoP `htu`/`htm` checks. `RESOURCE_URL=https://api.staging.sentinel.io/` activates the suite's RS tests. |

**Provisioning order** (one-time, runbook phase 1):

```bash
# 1. TLS secret (public CA - REQUIRED; the suite rejects self-signed certs)
bash infra/staging/provision-staging-tls.sh --issuer cert-manager   # or --issuer acm

# 2. Admin credentials secret (values from your secrets vault)
kubectl create secret generic keycloak-staging-admin -n staging \
  --from-literal=KEYCLOAK_ADMIN=<admin> \
  --from-literal=KEYCLOAK_ADMIN_PASSWORD=<password>

# 3. Database credentials secret (username MUST be "keycloak" - the postgres
#    probes hardcode -U keycloak -d keycloak)
kubectl create secret generic keycloak-staging-db -n staging \
  --from-literal=username=keycloak \
  --from-literal=password=<password>

# 4. Realm import config map (ships the FAPI-hardened sentinel-dast realm)
kubectl create configmap sentinel-realm-config -n staging \
  --from-file=infra/keycloak/realms/sentinel-dast.json

# 4b. RS runtime secrets (postgres string must use the keycloak-staging-db
#     credentials with Database=sentinel_dev; keycloak client secret from the
#     sentinel-dast realm's confidential client)
kubectl create secret generic sentinel-api-staging-secrets -n staging \
  --from-literal=postgres-connection-string="Host=postgres-staging;Port=5432;Database=sentinel_dev;Username=keycloak;Password=<password>" \
  --from-literal=keycloak-client-secret=<client-secret>

# 4c. RS TLS secret (public CA for api.staging.sentinel.io)
STAGING_HOST=api.staging.sentinel.io STAGING_TLS_SECRET=sentinel-api-staging-tls \
  bash infra/staging/provision-staging-tls.sh --issuer cert-manager

# 5. Deploy AS + RS + bundled postgres-staging/redis-staging + ingress + network policies
kubectl apply -f infra/k8s/staging/

# 6. DNS: point keycloak.staging.sentinel.io AND api.staging.sentinel.io at the
#    ingress external IP, then re-run provision-staging-tls.sh (steps 4c and
#    the keycloak invocation) to complete the ACME challenges.
```

> **Secret sourcing**: the `kubectl create secret` steps above are the bootstrap
> fallback. Per `docs/KUBERNETES_SECRET_MANAGEMENT_STRATEGY.md`, Sentinel
> clusters must not rely on imperative Secrets — reconcile
> `keycloak-staging-tls`, `keycloak-staging-admin`, and `keycloak-staging-db`
> from a KMS-backed store via External Secrets Operator (Azure Key Vault / AWS
> Secrets Manager + workload identity) before the gate runs. The manifest
> references only secret *names*, so swapping the provisioning mechanism is a
> drop-in change.

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

### 3.1 Pre-flight readiness verification

`infra/staging/verify-fapi-readiness.sh` runs **before** the suite starts (both in the remote gate and manually against staging). It fails fast with triage output instead of burning a certification attempt on a misconfigured AS. Eight checks (plus a ninth, resource-server reachability, when `RESOURCE_URL` is set):

| # | Check | Failure symptom |
|---|---|---|
| 1 | Discovery 200 + `issuer` matches `KEYCLOAK_URL` | Issuer URL mismatch (see §5) |
| 2 | `pushed_authorization_request_endpoint` advertised | PAR feature off — `KC_FEATURES=dpop,par` |
| 3 | Realm keys: PS256 present, RS256 absent | Algorithm confusion (§5) |
| 4 | Client policies bound (count > 0) | Wrong-slot policy import (§2.1) |
| 5 | Client profiles present (count > 0) | Profile never imported |
| 6 | DPoP feature enabled (`/admin/serverinfo`) | Feature flag off |
| 7 | PAR feature enabled (`/admin/serverinfo`) | Feature flag off |
| 8 | TLS 1.3 handshake (`openssl s_client -tls1_3`) | Reverse proxy TLS config |
| 9 | RS reachable over HTTPS (`RESOURCE_URL`) — when set | `api.staging.sentinel.io` DNS/ingress/TLS |

Manual run:

```bash
KEYCLOAK_URL=https://keycloak.staging.sentinel.io/realms/sentinel-dast \
KC_ADMIN_URL=https://keycloak.staging.sentinel.io \
RESOURCE_URL=https://api.staging.sentinel.io/ \
KC_ADMIN_USER=... KC_ADMIN_PASSWORD=... \
bash infra/staging/verify-fapi-readiness.sh
```

The remote gate (`fapi-conformance-gate.yml` → "Verify FAPI Readiness (Pre-flight)") passes the `STAGING_KEYCLOAK_*` secrets; a failing readiness check blocks the run before any suite API call is made.

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

### 4.1 Local self-hosted suite (pre-flight)

The local stack (`infra/fapi-conformance/`) stands up the official OIDF
Conformance Suite (MongoDB + `conformance-server` + nginx proxy) against the
Keycloak + Sentinel API from the root `docker-compose.yml`. **Local results
are for pre-flight/triage only** — a formal OIDF certificate requires the
hosted suite (§6 note).

```bash
# 1. Start the AS stack (Keycloak TLS on :8443, imports sentinel-dast realm)
docker compose up -d keycloak redis

# 2. Stand up the suite (generates certs + creates .env on first run)
make fapi-up
#    → edit infra/fapi-conformance/.env: set FAPI_SUITE_TOKEN, then re-run
make fapi-up

# 3. Run conformance against the local stack
make fapi-conformance-local

# 4. Inspect evidence
open artifacts/fapi/fapi-report.html       # extracted report pack
cat artifacts/fapi/fapi-evidence-manifest.txt

# 5. Tear down
make fapi-down
```

**Topology & TLS trust:** the suite container joins the root stack network
(`sentinel-fapi2-stack_default`, declared `external`), so it reaches the AS
as `https://keycloak:8443` — the dev cert from `infra/certs/generate-certs.sh`
already carries the `keycloak` SAN. The suite's JVM trusts the local CA via
`JAVA_TOOL_OPTIONS` → `certs/truststore.p12` (generated by
`generate-fapi-certs.sh`); no JVM/container modification needed.

**Client provisioning:** `make fapi-conformance-local` passes
`FAPI_PROVISION_HOOK` with `DOCKER_FALLBACK=true` and `KC_TRUSTSTORE_HOST`
(the generated truststore), so kcadm runs with `--network host` and trusts
the local CA. Required env vars for the hook are read from
`infra/fapi-conformance/.env` (`KC_ADMIN_*`, `KEYCLOAK_ISSUER`,
`SENTINEL_API_URL`).

**Known local-mode limitations:**

| Limitation | Impact | Workaround |
|---|---|---|
| Self-signed Keycloak cert | Browser-interactive modules fail TLS in the suite's in-container browser (it does not use the JVM truststore) | Back-channel modules (discovery, PAR, token, DPoP, private_key_jwt) run headless and are unaffected; for full browser-module coverage use a CA-signed staging cert (§1) or the hosted suite |
| Resource-server modules skipped | `RESOURCE_URL` unset → DPoP resource tests omitted | Set `SENTINEL_API_URL` in `.env` once `sentinel-api` runs with a trusted cert |
| First run fails modules | Expected — triage via §5 | Fix Keycloak realm config, re-run (`make fapi-conformance-local`) |

**CI pre-flight job:** `security-pipeline.yml` → `fapi-local-preflight` runs
the same flow on `workflow_dispatch` or PRs labelled `run-fapi` (never on
release branches — the authoritative gate is `fapi-conformance-gate.yml`).
Evidence is uploaded with 365-day retention; the suite + AS stack are torn
down in `always()`.

### 4.2 Remote (authoritative) gate

`.github/workflows/fapi-conformance-gate.yml` runs on `release/**` + on demand against GitHub environment `staging-fapi`. Pipeline:

1. **Verify FAPI Readiness (Pre-flight)** — `infra/staging/verify-fapi-readiness.sh` (§3.1); a failed check fails the run before the suite is invoked.
2. **Run FAPI 2.0 Conformance Suite** — any non-`PASSED` outcome exits non-zero → the workflow (and therefore the `release/**` push) is blocked.
3. **Commit Evidence on PASSED** — archives `fapi2-certificate-<YYYY-MM-DD>.pdf` + `fapi-evidence-manifest.txt` into `docs/compliance/` and pushes to the release branch (skipped if today's certificate is already committed — a repeat run terminates after one extra execution and cannot loop).
4. **FAPI 2.0 Evidence Gate (release proof)** — defense-in-depth: re-checks out the release branch and verifies the certificate + manifest are committed before the run is green.

It uploads `artifacts/fapi/` (report pack, result JSON, certificate, manifest) with 365-day retention and the commit SHA in the artifact name. Configure these secrets:

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

The gate now automates step 2 below (certificate + manifest committed to `docs/compliance/` on PASSED). Remaining manual steps:

1. Download the artifact pack `fapi2-conformance-evidence-<sha>`; verify the manifest hashes locally (`sha256sum -c`).
2. *(automated)* Certificate committed to `docs/compliance/fapi2-certificate-<YYYY-MM-DD>.pdf` plus the manifest (`fapi-evidence-manifest.txt`) as the attestation of provenance — confirm the "Commit Evidence on PASSED" step ran and the "FAPI 2.0 Evidence Gate" job is green.
3. Link the certificate and manifest from `docs/COMPLIANCE_AUDIT_MATRIX.md` (evidence index) — the OIDF suite plan page `plan-detail.html?plan=<id>` (recorded in the manifest) is the third-party verifiable source.
4. Once OIDF formally lists Sentinel on https://openid.net/developers/certification/ add the conformance badge to the root `README.md`.

> **Certification note**: results from a self-hosted suite instance are for internal evidence only; a formal OIDF certificate requires the hosted suite (certification.openid.net) and the Foundation's certification fee/process. Design the gate to target the hosted URL with the repo-owned token; local instances are for pre-flight.

## 7. Local pre-flight checklist

```bash
# 1. syntax gates
bash -n infra/dast/scripts/run-fapi-conformance.sh
bash -n infra/keycloak/scripts/provision-fapi-conformance-clients.sh
bash -n infra/fapi-conformance/certs/generate-fapi-certs.sh
bash -n infra/staging/provision-staging-tls.sh
bash -n infra/staging/verify-fapi-readiness.sh
# 2. compose validation
docker compose -f infra/fapi-conformance/docker-compose.yml --env-file infra/fapi-conformance/.env.example config --quiet
# 3. dry payload check (no network): validate the config builder
jq -n --arg i "https://keycloak:8443/realms/sentinel-dast/.well-known/openid-configuration" \
      '{server:{discoveryUrl:$i}, client:{client_id:"sentinel-fapi-conformance"}, client2:{client_id:"sentinel-fapi-conformance-mixup"}}'
# 4. profile import sanity (see docs/KEYCLOAK_FAPI_ENFORCEMENT.md re-import check)
# 5. staging readiness (against the deployed AS, §3.1)
KEYCLOAK_URL=https://keycloak.staging.sentinel.io/realms/sentinel-dast \
  KC_ADMIN_URL=https://keycloak.staging.sentinel.io \
  KC_ADMIN_USER=... KC_ADMIN_PASSWORD=... \
  bash infra/staging/verify-fapi-readiness.sh
# 6. local pre-flight: make fapi-up && make fapi-conformance-local
# 7. hosted certification run: FAPI_MODE=remote make fapi-conformance
```
