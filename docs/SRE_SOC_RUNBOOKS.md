# SRE And SOC Runbooks

Last Updated: 2026-03-29
Scope: Sentinel security-path incident response and recovery

## 1. Monitoring Priorities

Track and alert on:

1. replay detections (token/proof)
2. DPoP validation failures
3. nonce challenge rate (use_dpop_nonce)
4. SSF rejection and processing failure rates
5. finance authorization bounds exceeded events
6. cache dependency latency/error budget breach

## 2. Incident Severity Model

| Severity | Criteria |
|---|---|
| Sev-1 | security bypass suspected, widespread auth outage, or confirmed replay abuse campaign |
| Sev-2 | localized security-path degradation with user impact |
| Sev-3 | elevated warnings without confirmed user-impacting failures |

## 3. Runbook: Replay Detection Spike

### Trigger

- sudden increase in replay-related failures/alerts

### Triage

1. determine scope by route, client_id, subject, source network
2. verify whether failures map to a single integration/client rollout
3. check cache state health before concluding active abuse

### Response

1. keep fail-closed behavior enabled
2. notify security engineering if replay pattern is distributed/coordinated
3. collect trace IDs and correlated logs for forensic timeline

### Recovery Verification

1. replay rate returns to baseline
2. no permissive bypass behavior observed

## 4. Runbook: DPoP Nonce Challenge Storm

### Trigger

- increase in 401 responses with use_dpop_nonce

### Common Causes

1. client not persisting latest nonce
2. intermediary stripping DPoP-Nonce or WWW-Authenticate headers
3. nonce store/cache degradation

### Response

1. verify challenge headers are emitted by API
2. inspect edge/proxy header behavior
3. validate cache health and latency
4. work with affected clients on retry logic correctness (single retry with fresh nonce)

## 5. Runbook: SSF Validation Failures

### Trigger

- repeated 401/400 outcomes on SSF event endpoint

### Triage

1. identify failure class: auth token mismatch, signature/issuer, payload timing/shape
2. verify IdP discovery/JWKS reachability
3. check auth token config parity between sender and receiver

### Response

1. rotate/update shared auth token if compromised or mismatched
2. coordinate issuer key-rotation validation path
3. isolate malformed sender batches to avoid event flood masking

## 6. Runbook: Cache Dependency Degradation

### Trigger

- replay/nonce/session checks showing backend unavailability or timeouts

### Expected Behavior

- requests on protected paths may fail closed (503/denials depending path)

### Response

1. restore cache availability first; do not disable replay or blacklist checks
2. verify state writes and reads recover
3. run synthetic auth checks (nonce challenge + valid retry + replay rejection)

## 7. Runbook: Finance Bounds Rejection Spike

### Trigger

- increased authorization-bounds-exceeded warnings and 403 responses on transfer route

### Triage

1. compare expected signed bounds with submitted payload shapes
2. detect client-side currency/amount normalization regressions
3. assess for potential tampering/abuse signals

### Response

1. preserve opaque external 403 response semantics
2. use internal structured logs for detailed delta analysis
3. coordinate fix rollout with affected client teams

## 8. Post-Incident Validation Checklist

After mitigation:

1. protected endpoints succeed for valid DPoP flows
2. replay attempts are rejected
3. nonce challenge volume normalizes
4. SSF valid events are accepted and applied
5. finance transfer policy denials match expected baseline

## 9. Escalation Artifacts

Always collect:

1. incident time window
2. impacted endpoints and prefixes
3. trace IDs and correlation IDs
4. dependency health snapshots
5. mitigation actions and rollback conditions

## 10. Change Control Requirement

Any incident-driven config or policy change in auth/security paths must trigger updates to:

1. LIVING_THREAT_MODEL.md
2. COMPLIANCE_AUDIT_MATRIX.md
3. OPENAPI_3_1.yaml (if contract behavior changed)
