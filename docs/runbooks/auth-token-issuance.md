# Operational Runbook: Auth & Token Issuance

## 1. Diagnosing a TOKEN_REPLAY Alert (P1 Incident)
If SIEM emits Event ID `1001` (`TOKEN_REPLAY_ALERT`), an identical `jti` was presented more than once inside token validity.

- Action: Correlate `clientId`, `ipHash`, and `correlationId` across API logs, gateway logs, and WAF telemetry.
- Mitigation: Block abusive source patterns at API gateway or WAF layer.
- Expected API behavior: The API remains fail-closed and returns authentication failure for replay attempts.

## 2. Redis Outage and Fail-Closed Behavior
If Redis is unavailable, replay validation cannot be guaranteed.

- Action: Restore Redis availability immediately.
- Expected API behavior: API returns HTTP 503 from replay protection paths.
- Important: Do not bypass replay checks in production to recover traffic.

## 3. Break-Glass DPoP Disable Procedure
Use only for severe production incidents where DPoP validation is confirmed faulty.

1. Update `FeatureFlags:Auth:DpopFlow` in managed configuration to `false`.
2. Roll restart API workloads.
3. Record incident timeline and compensating controls.

Security note: This reduces sender-constrained token assurance and exits strict FAPI 2.0 posture.

## 4. Keycloak Client and Realm Rotation
- Rotate client credentials or signing material via Keycloak admin procedures.
- Verify JWKS propagation and issuer metadata health.
- Confirm API can refresh discovery metadata and accept newly signed tokens.

## 5. Post-Incident Validation Checklist
- Replay alerts return to baseline.
- 401/403/503 rates normalize.
- OpenTelemetry traces include authentication spans end-to-end.
- Prometheus metrics (`auth.dpop.failures`, `auth.jti.replays_total`) are stable.
