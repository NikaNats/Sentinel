# Auth And Token Issuance Runbook

**Last Updated:** 2026-03-21

## Purpose

Operational checks for token issuance, replay protection, and post-issuance enforcement paths.

## DPoP Challenge Flow

Expected behavior for a client without a valid nonce:

- response status: `401 Unauthorized`
- response header: `WWW-Authenticate: DPoP error="use_dpop_nonce"`
- response header: `DPoP-Nonce: <value>`

If that shape changes, investigate proxy/header handling and DPoP middleware behavior immediately.

## Replay Alert Handling

If a token or proof replay alert fires:

1. correlate `jti`, subject, client, and source IP
2. verify Redis replay keys are healthy
3. confirm the request was rejected before endpoint execution

## Redis Dependency Failure

Sentinel is intentionally fail-closed for replay-sensitive flows.

Expected behavior:

- protected paths may return `503`
- operators should restore Redis, not bypass replay checks

## Keycloak Metadata And JWKS

Sentinel uses a shared `ConfigurationManager<OpenIdConnectConfiguration>` for discovery and JWKS caching.

Operational checks:

1. confirm metadata endpoint health
2. confirm JWKS can refresh after key rotation
3. confirm SD-JWT and SSF validators recover without per-request discovery storms

## SSF Session Revocation

After a valid `session-revoked` event:

1. confirm the session is blacklisted
2. confirm subsequent access attempts for that session are rejected
3. confirm the event was logged as a security action
