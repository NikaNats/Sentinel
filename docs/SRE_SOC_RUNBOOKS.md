# SRE And SOC Runbooks

**Last Updated:** 2026-03-21

## Key Alerts

Monitor and alert on:

- JWT replay detections
- DPoP validation failures
- repeated `use_dpop_nonce` challenges
- Redis unavailability or high latency
- SSF validation failures
- finance transfer bounds violations

## Replay Detection

### Trigger

- replay metric increases above zero

### Immediate Actions

1. confirm whether the replays are isolated or broad
2. correlate subject, client, IP, and route
3. verify Redis health before assuming malicious reuse

### Expected API Behavior

- replayed requests are rejected
- no protected endpoint handler should execute after replay detection

## DPoP Nonce Challenge Storm

### Trigger

- sudden increase in `401` responses with `error="use_dpop_nonce"`

### Possible Causes

- client is not caching the latest nonce
- proxy strips the `DPoP-Nonce` response header
- Redis nonce state is degraded

### Actions

1. verify `DPoP-Nonce` is present on challenge responses
2. verify Redis connectivity from API pods
3. check whether an upstream proxy strips or rewrites the header

## SSF Validation Failure

### Trigger

- repeated invalid SETs on `/v1/ssf/events`

### Possible Causes

- wrong issuer keys
- stale discovery/JWKS metadata
- malformed or replayed SET payloads
- wrong static auth token at the sender

### Actions

1. inspect validator errors for `jti`, `iat`, `events`, or signature failures
2. verify discovery metadata and JWKS refresh behavior
3. confirm the configured SSF auth token matches the sender configuration

## Redis Outage

### Trigger

- Redis unavailable or latency high enough to break replay and nonce operations

### Expected API Behavior

- Sentinel fails closed
- protected request paths may return `503`

### Actions

1. restore Redis availability
2. do not disable replay protection in production as a quick fix
3. verify recovery by checking replay and nonce flows end-to-end

## Finance Bounds Rejection Spike

### Trigger

- surge in `403` responses on `/v1/finance/transfer`

### Possible Causes

- client payload does not match signed authorization details
- client normalized currency or amount incorrectly
- malicious tampering attempt

### Actions

1. compare request payload fields with signed authorization details
2. confirm client sends the same `transactionId`, `amount`, and `currency`
3. escalate if the spike appears coordinated

## Recovery Checks

After any auth-path incident, verify:

1. nonce challenges return to baseline
2. replay detections return to baseline
3. SSF processing succeeds for valid events
4. finance authorization failures are back to expected levels
5. Redis and Keycloak dependency latency are stable
