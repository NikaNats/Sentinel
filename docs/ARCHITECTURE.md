# Sentinel Architecture

**Last Updated:** 2026-03-21

## Overview

Sentinel is a layered API built around Keycloak-issued identity, sender-constrained access, replay resistance, session invalidation, and payload-bound authorization.

Core layers:

- `Sentinel.Domain`
- `Sentinel.Application`
- `Sentinel.Infrastructure`
- `Sentinel.Presentation`

## Request Pipeline

At a high level:

1. authentication routing
2. JWT or SD-JWT validation
3. rate limiting
4. DPoP validation for bearer-token flows
5. authorization policy and endpoint-specific guards

## Authentication Modes

### Standard JWT + DPoP

Used for most protected endpoints.

Expected request shape:

```http
Authorization: Bearer <access_token>
DPoP: <proof_jwt>
```

If the request is missing a usable nonce, Sentinel responds with:

```http
401 Unauthorized
WWW-Authenticate: DPoP error="use_dpop_nonce"
DPoP-Nonce: <nonce>
```

### SD-JWT

The composite authentication scheme routes to the SD-JWT handler when the authorization token has SD-JWT presentation shape.

Security properties:

- disclosure digests must be present in `_sd`
- unsupported disclosure algorithms are rejected
- key-binding JWT validation is required

## Replay And Session Controls

- JWT JTI replay protection
- DPoP proof JTI replay protection
- Redis-backed nonce state
- Redis-backed session blacklist
- logout and SSF event ingestion both feed session invalidation

## SSF / CAE Receiver

`POST /v1/ssf/events` receives security event tokens from a trusted sender.

Validation flow:

1. timing-safe static auth token check if configured
2. signed SET validation
3. issuer and claim validation
4. event processing into session and subject blacklist state

The validator uses a shared singleton `ConfigurationManager<OpenIdConnectConfiguration>` so discovery and JWKS fetching are cached rather than recreated per request.

## Finance Authorization Bounds

`POST /v1/finance/transfer` uses a dedicated authorization filter that checks the request payload against signed authorization details.

Validated fields:

- `transactionId`
- `amount`
- `currency`

## Key Architectural Decisions

### ADR-001

DPoP is the primary sender-constraining mechanism.

### ADR-002

Replay protection uses Redis-backed atomic state.

### ADR-003

Nonce challenge semantics are fail-closed and use `401` with `error="use_dpop_nonce"`.

### ADR-004

Authentication routing supports both standard bearer+DPoP and SD-JWT presentation flows.

### ADR-005

Session blacklist TTL is derived from Keycloak session settings through shared options logic.

### ADR-006

SSF validation and SD-JWT validation share a singleton OIDC discovery/JWKS configuration manager.

### ADR-007

Shared-secret comparisons in security-sensitive controller paths must use constant-time comparison.

### ADR-008

High-risk transaction endpoints can enforce payload-bound authorization rather than scope-only checks.

### ADR-009

Authorization handlers that depend on ASP.NET Core belong in the presentation boundary, while pure requirements and interfaces remain in application/domain-friendly layers.

### ADR-010

Tests are split by intent into unit, integration, and security projects so container-backed suites do not slow down fast feedback loops.

## Operational Notes

- The application code targets `net10.0`.
- The Dockerfile still needs baseline alignment with that runtime target.
- Historical docs in this folder are preserved for audit lineage, but current engineering truth should come from this file, the README, and the OpenAPI contract.
