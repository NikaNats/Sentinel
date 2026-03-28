# Sentinel Living Threat Model

Last Updated: 2026-03-29
Classification: Internal

## 1. System Context

Sentinel protects API access using DPoP, replay defenses, session revocation controls, SSF event intake, and payload-bound authorization checks for high-risk operations.

Primary modules in scope:

- Sentinel.DPoP
- Sentinel.Session
- Sentinel.SSF
- Sentinel.Rar
- Sentinel.Redis
- Sentinel.AspNetCore
- Sentinel.Infrastructure

## 2. Protected Assets

1. Access and refresh tokens
2. DPoP proof integrity and proof private-key binding semantics
3. Session blacklist and replay-state records
4. SSF event trust decisions
5. Authorization detail constraints for high-risk transfers
6. Security telemetry and incident correlation data

## 3. Trust Boundaries

1. External clients -> API host
2. API host -> cache/state backends
3. API host -> identity provider discovery/JWKS
4. Event sender -> SSF ingress endpoint
5. Internal service boundaries between protocol and adapter modules

## 4. Threat Inventory

| Threat | Impact | Likelihood | Primary Mitigation |
|---|---|---|---|
| Access token replay | High | Medium | JTI replay checks with fail-closed behavior |
| DPoP proof replay | High | Medium | Proof JTI replay state + nonce handling |
| Nonce bypass/reuse | High | Medium | 401 use_dpop_nonce challenge flow |
| Authorization payload tampering | High | Medium | RAR-style transfer bounds filter |
| SSF forgery or stale event replay | High | Medium | Signature/issuer/timing checks + fixed-time auth token compare |
| Composite auth downgrade attempts | Medium | Medium | Auth scheme routing + protocol-specific validation paths |
| Discovery/JWKS dependency amplification | Medium | Medium | Shared metadata manager and cache-aware validation paths |
| Telemetry privacy leakage via naive IP hashing | High | Low | HMAC-based SecurityContextHasher in diagnostics module |
| Cache outage on security-critical checks | High | Medium | Fail-closed semantics for replay/session checks |

## 5. Key Mitigations in Code

### 5.1 DPoP and Replay

- DPoP proof validation in Sentinel.DPoP and ASP.NET middleware integration.
- Nonce challenge semantics with explicit retry path.
- Replay state checks for proof/token identifiers.

### 5.2 Session and Revocation

- Session blacklist checks in request authorization paths.
- Logout and SSF pathways converge on session invalidation.

### 5.3 SSF Integrity

- Event token parsing and validation in Sentinel.SSF + endpoint ingress checks.
- Timing-safe static auth token comparison for shared token mode.

### 5.4 Payload-Bound Authorization

- Finance transfer guard compares request payload to signed authorization details.
- External responses remain opaque; detailed mismatch data is logged internally.

### 5.5 Privacy-Hardened Diagnostics

- Canonical IP context hashing via HMAC in Sentinel.Security.Diagnostics/SecurityContextHasher.cs.
- No plain SHA256(IP) logging in active paths.

## 6. Fail-Closed Expectations

The following are mandatory security behaviors:

1. replay or blacklist state unavailable -> reject request
2. invalid/stale/malformed DPoP proof -> reject request
3. invalid SSF token -> reject event processing
4. missing/invalid required nonce -> challenge, do not bypass

## 7. Detection and Monitoring Priorities

1. Replay detection spikes
2. DPoP failure ratio increase
3. use_dpop_nonce surge patterns
4. SSF rejection trends
5. Finance bounds exceeded events
6. Cache dependency latency/error rates

## 8. Residual Risks

1. Container packaging path is incomplete in repo (see CONTAINER_BUILD_READINESS.md).
2. Identity provider outage can degrade trust-refresh operations.
3. OpenAPI contract is manually maintained and can drift if not release-gated.

## 9. Review Cadence and Triggers

Review this model:

- at each release
- after any authentication pipeline modification
- after introducing/changing endpoint filters
- after cache/state model changes
- after significant incident postmortems

Required synchronized updates:

1. ARCHITECTURE.md
2. COMPLIANCE_AUDIT_MATRIX.md
3. SRE_SOC_RUNBOOKS.md
