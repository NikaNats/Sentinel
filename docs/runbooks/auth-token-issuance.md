# Auth And Token Issuance Runbook

Last Updated: 2026-03-29
Audience: SRE, SOC, Security Engineering
Scope: Token issuance and token-validation incident response

## 1. Objective

Restore secure token issuance and acceptance for protected Sentinel routes without relaxing security validation policy.

## 2. Trigger Conditions

Use this runbook when one or more conditions are observed:

1. clients cannot obtain access tokens from issuer
2. token-exchange requests begin failing unexpectedly
3. protected endpoint authentication failure rate spikes after deployment or key rotation
4. issuer/signature validation failures increase abnormally

## 3. Failure Taxonomy

Classify quickly before remediation:

1. issuer mismatch: token issuer does not match configured authority
2. audience mismatch: token audience rejected by API policy
3. keyset drift: JWKS unavailable, stale, or missing active key id
4. temporal validity failure: nbf, exp, iat failures due to drift
5. client auth or grant issue: token endpoint rejects client credentials/grant
6. transport dependency issue: discovery/JWKS network path instability

## 4. Initial Triage (First 15 Minutes)

1. determine blast radius by environment, client, route group
2. correlate first-seen failures with release and rotation events
3. collect representative failed requests and trace identifiers
4. verify issuer discovery and JWKS endpoint health from runtime network

## 5. Verification Workflow

### A. Validate Issuer Metadata

1. fetch discovery document for configured authority
2. confirm issuer value matches runtime configuration exactly
3. verify token_endpoint and jwks_uri are reachable and stable

### B. Validate Token Claims

1. inspect failed token claims: iss, aud, exp, nbf, iat, jti
2. confirm accepted audience configuration matches expected clients
3. validate token lifetime policy against current issuer settings

### C. Validate Keys And Signature Path

1. fetch JWKS and confirm active kid is present
2. verify key rotation propagation across runtime instances
3. confirm no stale cache pins old key material

### D. Validate Time Synchronization

1. confirm NTP synchronization for API and issuer hosts
2. verify no sustained drift causing nbf/exp rejects

### E. Validate Client Registration (Upstream)

1. confirm client secret or certificate validity
2. confirm required grant types and scopes remain enabled
3. verify realm or tenant routing alignment

## 6. DPoP Nonce Validation Path

Expected challenge shape for missing or stale nonce:

1. status: 401 Unauthorized
2. header: WWW-Authenticate with error="use_dpop_nonce"
3. header: DPoP-Nonce containing latest nonce

If shape differs, inspect proxy/header mutation and DPoP middleware path immediately.

## 7. Replay Alert Handling

When replay detection spikes:

1. correlate jti, subject, client, and source network
2. verify replay key read/write health in cache backend
3. confirm protected endpoint logic was not executed after replay rejection

## 8. Cache Dependency Failure

Sentinel is fail-closed for replay-sensitive paths.

Expected behavior:

1. protected routes may return 503 or deny access based on path policy
2. replay and blacklist checks must not be bypassed as emergency workaround

Primary response:

1. restore cache availability and latency first
2. validate replay and nonce state operations recover fully

## 9. Remediation Actions

Apply least-risk corrective action matching root cause:

1. issuer or audience mismatch: restore exact config and redeploy
2. JWKS drift: refresh key metadata cache and complete rotation rollout
3. clock skew: re-sync clocks and re-validate acceptance windows
4. client auth failure: rotate or re-provision upstream credentials
5. dependency outage: restore discovery/JWKS network path and trust chain

Security requirement: do not disable signature, issuer, or audience checks.

## 10. Post-Recovery Validation

Run in sequence:

1. acquire fresh token from issuer
2. execute token-exchange flow if enabled
3. call protected endpoint with valid DPoP proof
4. attempt replay and confirm rejection
5. trigger nonce challenge and confirm successful retry with fresh nonce

## 11. SSF Session Revocation Validation

After valid session-revoked event ingestion:

1. confirm session identifier is blacklisted
2. confirm subsequent requests for that session are rejected
3. confirm security event logging captured the action

## 12. Evidence And Escalation

Collect for incident record:

1. timeline from detection to mitigation
2. affected clients, environments, endpoints
3. representative sanitized errors and traces
4. config or key rotation change records
5. final validation results

Escalate immediately if token forgery, trust-chain compromise, or persistent signature anomalies are suspected.
