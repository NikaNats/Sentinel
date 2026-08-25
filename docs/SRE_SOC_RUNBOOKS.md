# SRE And SOC Runbooks

> **Document ID**: OPS-0001  
> **Last Updated**: 2026-08-25  
> **Status**: APPROVED (Enterprise Production Baseline)  
> **Scope**: Incident response, continuous monitoring, SRE disaster recovery, and emergency runbooks for Sentinel core security paths

---

## 1. Monitoring & Alerting Priorities (OpenTelemetry Metrics)

The SOC and SRE teams track and alert on the following security-critical metrics emitted via `Sentinel.Security.Diagnostics.AuthTelemetry` (Meter: `Sentinel.Auth.Metrics`):

### Tier-1 Security & Availability Alerts
* `auth.jti.replays_total` (Counter)
  * Alerting Threshold: > 5 replays / 1 minute
  * Severity: **Sev-1** (Active distributed token replay attack)
* `auth.redis.degraded_mode_activations` (Counter)
  * Alerting Threshold: > 0 activations
  * Severity: **Sev-1** (Loss of Redis cluster/sentinel quorum; fail-closed state active)
* `crypto.tls.cert_days_remaining` (Observable Gauge)
  * Alerting Threshold: < 30 days (Warning), < 7 days (Critical)
  * Severity: **Sev-1 / Sev-2** (TLS certificate nearing expiration)
* `crypto.tls.cert_reload_total{success="false"}` (Counter)
  * Alerting Threshold: > 0 failures
  * Severity: **Sev-1** (Kestrel hot-reload failed on new certificate bundle)

### Tier-2 Operational & Protocol Degradation Alerts
* `auth.dpop.failures` (Counter)
  * Alerting Threshold: > 50 failures / 5 minutes
  * Severity: **Sev-2** (Client configuration defect or active downgrade probing)
* `auth.token.validation.duration` (Histogram)
  * Alerting Threshold: p99 > 50 ms (Normal baseline: < 15 ms)
  * Severity: **Sev-2** (Cryptographic engine or Redis state latency degradation)
* `auth.idempotency.lock_contention_total` (Counter)
  * Alerting Threshold: > 100 / minute
  * Severity: **Sev-2** (High lock contention or orphaned IN_PROGRESS state)
* `auth.dpop.nonce_mismatch_total` (Counter)
  * Alerting Threshold: > 50 / minute
  * Severity: **Sev-2** (Client clock skew or aggressive uncoordinated retry loops)
* `crypto.keyring.active_key_mismatch` (Counter)
  * Alerting Threshold: > 0 rate
  * Severity: **Sev-2** (Envelope key ring configuration drift or legacy cipher backlog)

---

## 2. Incident Severity Model

* **Sev-1 (Critical)**:
  * Criteria: Security boundary compromise suspected; active token replay campaign; Redis Sentinel quorum loss; database migration deadlock; TLS expiration in < 7 days.
  * Action: Trigger PagerDuty; page On-Call Lead; assemble Security Incident Response Team (SIRT) within 15 minutes.
* **Sev-2 (Major)**:
  * Criteria: Localized cache latency degradation (p99 > 50ms); elevated rate-limiting rejections (> 100/min); DPoP signature failure surges; lazy re-wrap backlog increase.
  * Action: Page On-Call SRE; resolve within 2 hours.
* **Sev-3 (Minor)**:
  * Criteria: Transitive network latency jitter (< 50ms); single client nonce mismatches; isolated malformed header warnings.
  * Action: Create tracking ticket; review during standard business hours.

---

## 3. Runbook: Replay Detection Spike (JTI Replay Alert)

### Trigger
Alert `auth.jti.replays_total > 5/min` fires or `TOKEN_REPLAY_ALERT` logs appear in Loki/SIEM.

### Triage & Analysis
1. **Trace Correlation**:
   * Search Loki for the structured log: `{service_name="sentinel-api"} |= "TOKEN_REPLAY_ALERT"`.
   * Extract the `CorrelationId`, `jti` hash, and `sub` hash.
2. **Determine Attack Class**:
   * Single `sub` hash, single `ipHash`: Client SDK retry regression (missing idempotency key or double-click bug).
   * Multiple `sub` hashes, distributed `ipHash`: Active credential stuffing or stolen token replay campaign.

### Emergency Response
1. **Maintain Fail-Closed Invariants**: Never bypass or disable the JTI replay cache to restore throughput.
2. **Session Revocation via Keycloak Admin API**:
   * If a compromised subject ID is identified, terminate all sessions immediately:
   ```bash
   curl -k -X POST "https://keycloak:8443/admin/realms/sentinel/users/${USER_ID}/logout" \
     -H "Authorization: Bearer ${ADMIN_TOKEN}"
   ```
3. **WAF IP Mitigation**: If the replay campaign is centralized, block the offending IP address at the Ingress/WAF edge.

---

## 4. Runbook: Malformed Token Scans & DPoP Header Fuzzing

### Trigger
Surge in `DpopValidationMiddleware` warnings (`DpopSignatureError` / `invalid_dpop_proof`) or `auth.dpop.failures > 50/5min`.

### Triage & Analysis
1. Verify that the API is properly returning `HTTP 401 Unauthorized` with ProblemDetails (and **NOT** `500 Internal Server Error`).
2. Verify that Constant-Time Failure Padding (120ms floor + 0–15ms CSPRNG jitter) is active in response logs.
3. If an external IP is generating hundreds of invalid DPoP tokens per minute, an automated vulnerability scanner is probing the endpoint.

### Emergency Response
1. The Kestrel process is protected by **Exception Shielding** and **L1AntiFloodCache** (50,000 entries, 3s TTL).
2. Dynamic Rate Limiting: The IP partition limiter will automatically clamp the source at 100 req/10s (`429 Too Many Requests`).
3. If necessary, drop traffic at the Ingress controller:
   ```bash
   kubectl annotate ingress sentinel-api -n sentinel-prod \
     nginx.ingress.kubernetes.io/denylist-source-range="${ATTACKER_IP}/32" --overwrite
   ```

---

## 5. Runbook: Redis Sentinel HA Failover & Outage Triage

### Trigger
Alert `RedisDegradedModeActivated` fires or `auth.token.validation.duration` p99 breaches 50ms.

### Expected Architecture Behavior
* Sentinel utilizes a **3-Node Redis Sentinel StatefulSet** (`sentinel-redis-ha-0`, `1`, `2`).
* When the Primary node fails, Sentinel nodes elect a new Primary within 2,000ms.
* `StackExchange.Redis` receives the `+switch-master` event and automatically redirects writes without restarting the API gateway.
* If **all** Redis nodes become unreachable, Sentinel strictly **fails closed**, returning `503 Service Unavailable` with `Retry-After: 5`.

### Emergency Response & Diagnostics
1. **Check Sentinel Quorum & Identify Active Master**:
   ```bash
   kubectl exec -it sentinel-redis-ha-0 -c sentinel -n sentinel-prod -- \
     redis-cli -p 26379 sentinel get-master-addr-by-name mymaster
   ```
2. **Check Pod Health in StatefulSet**:
   ```bash
   kubectl get pods -n sentinel-prod -l app.kubernetes.io/name=sentinel-redis-ha
   ```
3. **Trigger Manual Failover (if Primary is unresponsive but not dead)**:
   ```bash
   kubectl exec -it sentinel-redis-ha-0 -c sentinel -n sentinel-prod -- \
     redis-cli -p 26379 sentinel failover mymaster
   ```
4. **Inspect Connection Logs on API Pods**:
   ```bash
   kubectl logs -n sentinel-prod -l app.kubernetes.io/name=sentinel-api --tail=100 | grep -i "Redis connection"
   ```
   *Expected recovery log*: `Redis connection restored. Active Endpoint: ...`

---

## 6. Runbook: PostgreSQL Database Backup, Restore & Point-in-Time Recovery (PITR)

### Scope
Covers the durable anchor database (`sentinel_dev` / `sentinel_prod`) used by `SentinelSecurityDbContext` and `HybridSessionBlacklistCache`.

### 6.1 Automated Backup Verification (Daily Job)
Verify that automated WAL archiving and daily base backups are completing cleanly:
```bash
# Verify latest backup archive
kubectl exec -it deploy/postgres -n sentinel-prod -- \
  sh -c "ls -la /var/lib/postgresql/data/backups/"
```

### 6.2 Manual Logical Backup (Pre-Migration / Maintenance)
Before applying EF Core schema migrations in production, take an immediate snapshot:
```bash
kubectl exec -it deploy/postgres -n sentinel-prod -- \
  pg_dump -U postgres -d sentinel_prod -F c -b -v \
  -f "/tmp/sentinel_prod_pre_migration_$(date +%Y%m%d_%H%M%S).dump"

# Copy dump to secure administrative storage
kubectl cp sentinel-prod/$(kubectl get pod -n sentinel-prod -l app.kubernetes.io/name=postgres -o jsonpath='{.items[0].metadata.name}'):/tmp/sentinel_prod_pre_migration_*.dump ./sentinel_backup.dump
```

### 6.3 Disaster Recovery: Database Restore Procedure
In the event of data corruption or disaster recovery:
1. **Scale Down Application Pods (Prevent State Race)**:
   ```bash
   kubectl scale deployment sentinel-api -n sentinel-prod --replicas=0
   ```
2. **Restore Database from Snapshot**:
   ```bash
   kubectl exec -i deploy/postgres -n sentinel-prod -- \
     pg_restore -U postgres -d sentinel_prod --clean --if-exists /tmp/sentinel_backup.dump
   ```
3. **Execute Migration Catch-Up**:
   ```bash
   dotnet ef database update --project src/Sentinel.EntityFrameworkCore \
     --connection "${PROD_POSTGRES_CONNECTION_STRING}"
   ```
4. **Scale Application Pods Back Up**:
   ```bash
   kubectl scale deployment sentinel-api -n sentinel-prod --replicas=3
   ```

---

## 7. Runbook: Cryptographic Key Ring Drift & TLS Hot-Reload Alert

### 7.1 Alert: `crypto.tls.cert_days_remaining < 30`
* **Action**:
  1. Verify cert-manager ACME challenge status:
     ```bash
     kubectl get certificate -n sentinel-prod
     kubectl describe certificaterequest -n sentinel-prod
     ```
  2. If manually provisioned, generate/renew certificate and update the secret:
     ```bash
     kubectl create secret tls sentinel-api-tls -n sentinel-prod \
       --cert=tls.crt --key=tls.key --dry-run=client -o yaml | kubectl apply -f -
     ```
  3. `KestrelCertificateReloader` will detect file system modification, debounce for 500ms, and swap the active certificate in Kestrel's `ServerCertificateSelector` with zero downtime.

### 7.2 Alert: `crypto.keyring.active_key_mismatch` Surge
* **Meaning**: Records in the database were encrypted with a retired key and are triggering lazy re-wraps (`DecryptEnvelope`).
* **Action**:
  1. Check if an scheduled key retirement window has concluded.
  2. Monitor `crypto.lazy_rewraps_total` counter.
  3. Once lazy re-wraps settle to 0, the retired key can safely be removed from `Cryptography:KeyRing` in configuration.

---

## 8. Post-Incident Automated Validation Checklist

After resolving any infrastructure outage, failover, or security incident, run the following command battery to mathematically prove full-system recovery before declaring the incident resolved:

```powershell
# 1. Full Unit, Protocol & Concurrency Suite (666 tests, 100% green)
dotnet test Sentinel.slnx -c Release

# 2. Native AOT & Trim Safety Verification
./tests/scripts/validate-native-aot.sh linux-x64

# 3. Network Chaos Resilience & Fail-Closed Gate
dotnet test tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj `
  --filter "FullyQualifiedName~Chaos|FullyQualifiedName~Timing" -c Release

# 4. Hybrid Multi-Tier Cache State Verification
dotnet test tests/Sentinel.Tests.Integration/Sentinel.Tests.Integration.csproj `
  --filter "FullyQualifiedName~HybridSession" -c Release

# 5. Reqnroll End-to-End Acceptance Verification (Live Gateway + Docker Stack)
dotnet test tests/Sentinel.Tests.Acceptance/Sentinel.Tests.Acceptance.csproj -c Release
```

---

## 9. Escalation & SIRT Contact

If token forgery, signing key compromise, or persistent cryptographic failure is detected:
1. Capture W3C trace IDs, request headers, and client IP hashes from Loki.
2. Escalate immediately to the **Security Incident Response Team (SIRT)**:
   * **Emergency Escalation Email**: `sirt@sentinel.security`
   * **PagerDuty Escalation Policy**: `Sentinel-Security-Tier0`
   * **24/7 Security Operations Desk**: Internal Bridge channel `#sirt-war-room`
