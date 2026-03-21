# Sentinel Living Threat Model

**Last Updated:** 2026-03-21
**Classification:** Internal

## System Summary

Sentinel is a Zero Trust API front end for authentication, session control, profile access, documents, finance transfer authorization, and security-event ingestion.

Current security features in code:

- JWT validation
- DPoP sender-constrained access
- Redis-backed replay detection
- session blacklist enforcement
- SD-JWT selective disclosure verification
- SSF/CAE session revocation ingestion
- payload-bound finance authorization
- partial ML-DSA interoperability groundwork

## High-Value Assets

- access tokens
- refresh tokens
- DPoP private keys held by clients
- SD-JWT disclosures containing sensitive claims
- SSF security event tokens
- Redis-backed replay and blacklist state

## Primary Threats

### Token Replay

Threat:
- a captured JWT or DPoP proof is replayed

Controls:
- JWT JTI replay cache
- DPoP proof JTI replay cache
- rotating nonce challenge
- fail-closed behavior on cache dependency failure

### Nonce Bypass

Threat:
- clients reuse stale proofs or skip nonce rotation

Controls:
- `401 Unauthorized`
- `WWW-Authenticate: DPoP error="use_dpop_nonce"`
- `DPoP-Nonce` header issuance

### Composite Auth Downgrade

Threat:
- a client attempts to bypass stronger verification by presenting one token type through another scheme

Controls:
- policy scheme routes SD-JWT presentations by token shape
- security tests cover downgrade and cross-scheme confusion paths

### SD-JWT Over-Disclosure

Threat:
- clients reveal claims that are not required or attempt forged disclosures

Controls:
- disclosure digest must exist in issuer `_sd`
- unsupported `_sd_alg` values are rejected
- key-binding JWT freshness is enforced

### SSF Forgery Or Replay

Threat:
- an attacker sends a fake or stale SET to revoke sessions or poison security state

Controls:
- signed SET validation
- issuer validation
- required `jti`, `iat`, and `events`
- stale/future event rejection
- timing-safe static auth token comparison in the controller path

### Payload Tampering On Sensitive Transactions

Threat:
- a client changes amount, currency, or transaction identifier after authorization

Controls:
- transaction-bound authorization filter on `/v1/finance/transfer`
- ordinal-ignore-case currency comparison
- exact transaction ID and amount checks

### Key Discovery Storms

Threat:
- per-request OIDC discovery/JWKS fetch creates latency and external dependency amplification

Controls:
- singleton `IConfigurationManager<OpenIdConnectConfiguration>` in DI
- shared JWKS/discovery cache for SD-JWT and SSF validators

### Timing Side Channels On Shared Secrets

Threat:
- attacker infers SSF shared-secret bytes through variable-time string comparison

Controls:
- `CryptographicOperations.FixedTimeEquals`

### PQC Transition Risk

Threat:
- algorithm allow-listing and thumbprint handling drift from provider interoperability during ML-DSA rollout

Controls:
- explicit algorithm allow-list
- dedicated thumbprint tests
- treat ML-DSA as controlled rollout, not assumed universal interoperability

## Trust Boundaries

1. Client to API
2. API to Redis
3. API to Keycloak discovery/JWKS
4. Keycloak to SSF receiver

## Fail-Closed Expectations

- replay cache unavailable -> reject request
- invalid or stale SET -> reject event
- invalid DPoP proof -> reject request
- missing nonce -> challenge with `401`, not permissive fallback

## Monitoring Priorities

- JWT replay detections
- DPoP validation failures
- nonce challenge spikes
- SSF validation failures
- finance bounds rejection spikes
- Redis latency and availability

## Current Residual Risks

- container/runtime baseline drift until Docker images are aligned with the application target framework
- upstream Keycloak availability remains critical for discovery and trust refresh
- ML-DSA interoperability remains a rollout concern until end-to-end validation is standardized in production

## Review Trigger

Update this document when:

- auth pipeline ordering changes
- new token types or auth schemes are introduced
- replay/session storage semantics change
- SSF event handling or finance authorization rules change
