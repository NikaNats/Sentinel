# SRE And SOC Runbooks

> **Document ID**: OPS-0001  
> **Last Updated**: 2026-05-30  
> **Scope**: Incident response, continuous monitoring, and emergency recovery for Sentinel core security paths

---

## 1. Monitoring & Alerting Priorities (OpenTelemetry Metrics)

The SOC and SRE teams must track and alert on the following security-critical metrics:

| Metric Name | Type | Alerting Threshold | Severity |
|---|---|---|---|
| `auth.jti.replays_total` | Counter | > 5 replays / 1 minute | **Sev-1** (Possible active attack) |
| `auth.dpop.failures` | Counter | > 50 failures / 5 minutes | **Sev-2** (Client config error / Downgrade attempt) |
| `auth.token.validation.duration` | Histogram | p99 > 50 ms (Normal baseline: <15ms) | **Sev-2** (Redis cache degradation) |
| `security:rate_limit_exceeded` | Event | > 100 events / 1 minute | **Sev-2** (DDoS / Automated scraping) |
| `auth.redis.degraded_mode_activations` | Counter | > 1 activation | **Sev-1** (Loss of Redis cluster quorum) |

---

## 2. Incident Severity Model

| Severity | Criteria | Trigger / Action |
|---|---|---|
| **Sev-1** | Security boundary breach suspected; Widespread authentication outage; Active replay campaign. | Trigger PagerDuty; Assemble Security Incident Response Team (SIRT) immediately. |
| **Sev-2** | Localized degradation; Intermittent cache timeouts; Elevated rate-limiting blocks. | Notify On-Call Engineer; Resolve within 2 hours. |
| **Sev-3** | Informational warnings; Minor clock drift (<5s); Transitive network jitter. | Create JIRA ticket; Review during next business hours. |

---

## 3. Runbook: Replay Detection Spike (JTI Replay Alert)

### Trigger
Alert `auth.jti.replays_total > 5/min` fires.

### Triage & Analysis
1.  **Correlate via Trace ID:** Extract the W3C `traceId` from the log events in your SIEM.
2.  **Identify the Source:** Group the alerts by `sub` (user ID), `clientId`, and `ipHash` (pseudonymized IP).
3.  **Determine the Class:**
    - Single Client, Single IP: Possible client-side retry regression (double-click bug).
    - Multiple Clients, Distributed IPs: Active distributed token replay campaign (stolen tokens).

### Emergency Response
1.  **Keep Fail-Closed Active:** Under no circumstances should the JTI replay cache be bypassed.
2.  **Identify Compromised Subject:** If a specific `sub` is identified, invoke Keycloak Admin API to revoke all active sessions for that subject immediately:
    ```bash
    # Revoke all sessions for compromised user
    dotnet coyote ... # Or invoke Keycloak global logout API
    ```
3.  **Block Attacker IP:** If the attack is centralized, block the offending `ipHash` at the WAF / Ingress Gateway layer.

---

## 4. Runbook: Malformed Token Scans (Exception Shielding Logs)

### Trigger
Surge in `DpopValidationMiddleware` warnings with message: `TryExtractProofThumbprint caught expected parsing exception...`

### Triage & Analysis
This warning indicates that Sentinel's **Exception Shielding** is successfully intercepting malformed, corrupted, or poisoned DPoP headers (preventing process-crashing DoS attacks) and safely returning `401 Unauthorized`.
1.  Verify the HTTP response status code is indeed returning `401` (and NOT `500` - which would indicate a shielding bypass).
2.  Extract the offending payload from the logs (safe as no PII is logged).
3.  If the source IP is sending hundreds of malformed headers per minute, this is an automated fuzzing/vulnerability scan.

### Emergency Response
1.  Configure the rate-limiter to block the offending IP dynamically at the Ingress/WAF layer.
2.  Do not disable the exception shielding; it is protecting the Kestrel process from memory corruption.

---

## 5. Runbook: Cache Dependency Timeout / Outage

### Trigger
Alert `auth.token.validation.duration p99 > 50ms` or Redis connection failures logged.

### Expected Behavior
Sentinel is strictly **fail-closed**. All protected routes will reject requests with `503 Service Unavailable` or `500 Internal Error` (due to missing JTI/Nonce state validation).

### Emergency Response
1.  **Do NOT disable the security pipeline.** Bypassing the middlewares to restore uptime is a critical compliance violation that opens the system to replay attacks.
2.  Check Redis Cluster health. Verify if the cluster lost quorum.
3.  If memory is exhausted, perform a safe Redis memory eviction or restart the degraded nodes.
4.  Once Redis is back online, verify connection restoration logs:
    `Redis connection restored. Endpoint: 127.0.0.1:6379`

---

## 6. Post-Incident Validation Checklist

After any security incident or emergency infrastructure restoration, run the following automated verification suite to mathematically prove system integrity before declaring the incident closed:

- [ ] **Verify Cryptographic Consistency:** Confirm `dotnet test` unit suite passes cleanly.
- [ ] **Verify Timing Side-Channel Resilience:** Run the high-precision Welch's T-Test timing tests to prove no timing oracle exists:
  ```powershell
  dotnet test tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj --filter "FullyQualifiedName~Timing" -c Release
  ```
- [ ] **Verify Concurrency & Lock Safety:** Run the Microsoft Coyote systematic concurrency tests (1000 iterations) to prove there are no race conditions in the restored cluster:
  ```powershell
  dotnet coyote test Sentinel.Tests.Concurrency.dll -m Sentinel.Tests.Concurrency.IdempotencyConcurrencyTests.TestConcurrentIdempotencyAcquisition -i 1000 -ms 200 --portfolio-mode fair
  ```
- [ ] **Verify Network Chaos Resilience:** Run the Toxiproxy chaos tests to ensure the system degrades gracefully under remaining packet loss or latencies:
  ```powershell
  dotnet test tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj --filter "FullyQualifiedName~Chaos" -c Release
  ```

---

## 7. Escalation & SIRT Contact

If token forgery, signing key compromise, or persistent timing side-channel leaks are detected:
1.  Capture the W3C trace history and Base64Url payloads.
2.  Escalate immediately to the **Security Incident Response Team (SIRT)** at: `sirt@sentinel.security`.
