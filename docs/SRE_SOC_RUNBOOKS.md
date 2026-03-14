# SRE/SOC Runbooks for Sentinel API

Operational procedures for incident response, troubleshooting, monitoring, and maintenance of Sentinel authentication API.

---

## Table of Contents

1. [Monitoring & Alerting](#monitoring--alerting)
2. [Common Alerts & Response](#common-alerts--response)
3. [Troubleshooting Procedures](#troubleshooting-procedures)
4. [Incident Response](#incident-response)
5. [Maintenance & Upgrades](#maintenance--upgrades)

---

## Monitoring & Alerting

### Metrics & Dashboards

**Required Metrics (expose via Prometheus `/metrics` endpoint):**

| Metric | Type | Target Threshold | Alert |
|--------|------|------------------|-------|
| `http_requests_total` | Counter | N/A | None (baseline) |
| `http_request_duration_seconds` | Histogram | p99 < 500ms | p99 > 1000ms |
| `authentication_failures_total` | Counter | < 5% of auth attempts | > 10% failure rate |
| `dpop_validation_failures_total` | Counter | < 2% | > 5% failure rate |
| `rate_limit_exceeded_total` | Counter | < 1% of requests | > 5% rate-limited |
| `jwt_replay_detected_total` | Counter | 0 (investigate any) | > 0 |
| `dpop_nonce_cache_hits` | Counter | high (cached nonces) | None |
| `dpop_nonce_cache_misses` | Counter | low (new nonces) | > 20% misses |
| `redis_connection_pool_size` | Gauge | 10 | < 5 connections |
| `redis_latency_milliseconds` | Histogram | p99 < 10ms | p99 > 50ms |
| `idempotency_retries_total` | Counter | low | > 10% retries |

**Dashboard Recommendations:**
- Real-time request rate (req/sec, colored by status code)
- Authentication source breakdown (JWT, DPoP, ACR, scope)
- Error rate by endpoint
- Redis connection pool and latency
- Rate limit saturation (% of quota used per partition)
- DPoP nonce cache hit rate

### Alert Rules (Prometheus/Alertmanager)

```yaml
groups:
  - name: sentinel_sre
    rules:
      # Authentication Failures
      - alert: HighAuthenticationFailureRate
        expr: |
          rate(authentication_failures_total[5m]) > 0.1
          / rate(http_requests_total[5m])
        for: 5m
        annotations:
          summary: "Authentication failure rate > 10%"
          runbook: "k8s.example.com/runbook/auth-failure"

      # JWT Replay Detection
      - alert: JwtReplayDetected
        expr: increase(jwt_replay_detected_total[5m]) > 0
        for: 1m
        severity: critical
        annotations:
          summary: "Token replay detected"
          runbook: "k8s.example.com/runbook/replay-attack"

      # Rate Limiting Saturation
      - alert: RateLimitSaturation
        expr: |
          rate(rate_limit_exceeded_total[5m])
          / rate(http_requests_total[5m]) > 0.05
        for: 10m
        severity: warning
        annotations:
          summary: "Rate limiting engaged; > 5% of requests throttled"
          runbook: "k8s.example.com/runbook/rate-limit-saturation"

      # Redis Latency
      - alert: RedisHighLatency
        expr: |
          histogram_quantile(0.99, redis_latency_milliseconds)
          > 50
        for: 5m
        severity: warning
        annotations:
          summary: "Redis p99 latency > 50ms"
          runbook: "k8s.example.com/runbook/redis-latency"

      # Redis Unavailable
      - alert: RedisDown
        expr: up{job="redis"} == 0
        for: 1m
        severity: critical
        annotations:
          summary: "Redis is down; authentication blocking"
          runbook: "k8s.example.com/runbook/redis-down"

      # DPoP Proof Failures
      - alert: HighDpopFailureRate
        expr: |
          rate(dpop_validation_failures_total[5m])
          / rate(http_requests_total[5m]) > 0.05
        for: 5m
        severity: warning
        annotations:
          summary: "DPoP validation failure rate > 5%"
          runbook: "k8s.example.com/runbook/dpop-validation"

      # Nonce Cache Degradation
      - alert: DpopNonceCacheMisses
        expr: |
          rate(dpop_nonce_cache_misses[5m])
          / (rate(dpop_nonce_cache_hits[5m]) + rate(dpop_nonce_cache_misses[5m]))
          > 0.2
        for: 10m
        severity: warning
        annotations:
          summary: "DPoP nonce cache miss rate > 20%"
          runbook: "k8s.example.com/runbook/nonce-cache-degradation"

      # Idempotency Conflicts
      - alert: HighIdempotencyConflicts
        expr: |
          rate(idempotency_retries_total{outcome="conflict"}[5m])
          / rate(http_requests_total[5m]) > 0.1
        for: 5m
        severity: warning
        annotations:
          summary: "Idempotency conflicts > 10%; possible timeout issue"
          runbook: "k8s.example.com/runbook/idempotency-conflicts"
```

---

## Common Alerts & Response

### Alert: JWT Replay Detected

**Trigger:** `jwt_replay_detected_total > 0`

**Severity:** CRITICAL

**Possible Causes:**
1. Attacker captured token and replayed it
2. Client bug (re-using same token)
3. Keycloak token issue (issuing duplicate JTIs)
4. Redis cache corruption

**Immediate Response (within 5 minutes):**

1. **Confirm Alert:**
   ```bash
   kubectl logs -f deployment/sentinel --selector=app=sentinel | grep "jti_already_used"
   ```

2. **Check for coordinated attack:**
   ```bash
   # Count replays per subject
   kubectl logs -f deployment/sentinel | jq -s 'group_by(.user_id) | map({user: .[0].user_id, count: length})'
   
   # If single user: likely client bug
   # If many users: likely attack
   ```

3. **Log event to SIEM:**
   ```
   Event: JWT_REPLAY_DETECTED
   Severity: CRITICAL
   Timestamp: [alert_time]
   Affected_Subjects: [list of users]
   Count: [number of replays]
   ```

**Investigation (within 30 minutes):**

4. **Check Keycloak for token issuance issues:**
   ```bash
   # SSH to Keycloak pod
   kubectl exec -it pod/keycloak-0 -- /bin/sh
   
   # Check event log for duplicate JTI issuance
   cat /opt/keycloak/data/events.log | grep "duplicate_jti"
   ```

5. **Verify Redis JTI cache state:**
   ```bash
   # Connect to Redis
   redis-cli -h redis-master -p 6379
   
   # Check for corrupted keys
   KEYS "jti:token:*" | head -20
   
   # Verify oldest entry (should be recent)
   SCAN 0 MATCH "jti:token:*" COUNT 100
   ```

6. **Identify affected users:**
   - Extract user IDs from logs
   - Contact support team; prepare notification

**Mitigation (within 1 hour):**

7. **For client bug (single user):**
   - Contact client development team
   - Recommend: Regenerate DPoP proof per-request (do not cache proofs)

8. **For attack (many users):**
   - Enable temporary rate limiting: `POST /admin/config { "rate_limit_strict": true }`
   - Trigger Keycloak token revocation:
     ```bash
     curl -X POST http://keycloak:8080/admin/realms/sentinel/tokens/revoke \
       -H "Authorization: Bearer $KEYCLOAK_ADMIN_TOKEN"
     ```
   - Notify security team; begin forensics

**Post-Incident (within 24 hours):**

9. **Root Cause Analysis:**
   - Review Keycloak logs for JTI generation issues
   - Check client implementations for replay behavior
   - Verify Redis persistence and snapshots
   - Update SIEM baseline (alert threshold or whitelisting)

10. **Preventive Actions:**
    - Implement JTI uniqueness validation in Keycloak (if not present)
    - Add client-side DPoP generation verification tests
    - Increase Redis backup frequency

### Alert: High Authentication Failure Rate (> 10%)

**Trigger:** `rate(authentication_failures_total[5m]) / rate(http_requests_total[5m]) > 0.1`

**Severity:** WARNING

**Possible Causes:**
1. Keycloak public key rotated; Sentinel using stale key
2. Clock skew between Sentinel and Keycloak
3. Token format changed (realm config updated)
4. Network issue between Sentinel and Keycloak
5. Legitimate misconfiguration (client using wrong issuer)

**Immediate Response (within 5 minutes):**

1. **Check for specific failure reasons:**
   ```bash
   kubectl logs -f deployment/sentinel --selector=app=sentinel \
     | jq 'select(.event_type == "authentication_failed") | {reason: .error_code, count: 1}' \
     | jq -s 'group_by(.reason) | map({reason: .[0].reason, count: length}) | sort_by(.count) | reverse'
   ```

2. **Classify failures by type:**
   - **"invalid_signature"** → Keycloak key rotated or Sentinel has stale key
   - **"token_expired"** → Likely legitimate; check if clients aware of expiration
   - **"invalid_audience"** → Token audience claim doesn't match Sentinel expected audience
   - **"invalid_issuer"** → Realm realm config changed

3. **Check recent deployments:**
   ```bash
   kubectl rollout history deployment/sentinel
   kubectl describe deployment/sentinel | grep -A 5 "Image:"
   ```

**Investigation (within 15 minutes):**

4. **Verify Keycloak public key:**
   ```bash
   # Fetch current key from Keycloak
   curl -s http://keycloak:8080/realms/sentinel/protocol/openid-connect/certs | jq '.keys[0]'
   
   # Check Sentinel config for cached key
   kubectl exec pod/sentinel-0 -- cat /etc/sentinel/keycloak-key.json
   
   # If different hash → stale key issue
   ```

5. **Check system clocks:**
   ```bash
   # Sentinel server time
   kubectl exec pod/sentinel-0 -- date +%s
   
   # Keycloak server time
   kubectl exec pod/keycloak-0 -- date +%s
   
   # Diff should be < 5 seconds
   ```

6. **Verify network connectivity:**
   ```bash
   # From Sentinel pod
   kubectl exec pod/sentinel-0 -- curl -v http://keycloak:8080/health
   
   # If timeout → network issue
   ```

**Mitigation (within 30 minutes):**

7. **If stale key:**
   - Restart Sentinel deployment (forces key reload):
     ```bash
     kubectl rollout restart deployment/sentinel
     ```
   - Monitor new deployment; watch for recovery

8. **If clock skew:**
   - Restart NTP on affected node:
     ```bash
     NTP_SERVER=ntp.example.com
     systemctl restart chrony  # or ntpd
     timedatectl set-ntp on
     ```

9. **If audience/issuer mismatch:**
   - Verify Keycloak realm config:
     ```bash
     curl -s -H "Authorization: Bearer $KC_TOKEN" \
       http://keycloak:8080/admin/realms/sentinel | jq '.accountUrl, .displayName'
     ```
   - Compare with Sentinel config:
     ```bash
     kubectl get configmap sentinel-config -o jsonpath='{.data.appsettings\.json}' | jq '.Keycloak'
     ```
   - Update Sentinel config if mismatch; redeploy

**Post-Incident:**

10. **Monitor for recovery:**
    - Watch for auth failure rate to drop below 5% within 2 minutes
    - If not, escalate to level 2 on-call

### Alert: Redis High Latency (p99 > 50ms)

**Trigger:** `histogram_quantile(0.99, redis_latency_milliseconds) > 50`

**Severity:** WARNING

**Possible Causes:**
1. Redis CPU saturated (eviction, replication)
2. Network latency (congested link, packet loss)
3. Large value sizes (cache lines > 1MB)
4. Slow Redis commands (SCAN, KEYS on large dataset)
5. Persistence operations (RDB snapshot, AOF rewrite)

**Immediate Response (within 5 minutes):**

1. **Check Redis INFO:**
   ```bash
   redis-cli -h redis-master -p 6379 INFO stats | grep -E "total_commands_processed|instantaneous_ops_per_sec|rejected_connections"
   ```

2. **Monitor current load:**
   ```bash
   redis-cli -h redis-master -p 6379 LATENCY LATEST
   ```

3. **Check number of connections:**
   ```bash
   redis-cli -h redis-master -p 6379 INFO clients | grep connected_clients
   # Expected: < 50; Warning: > 100
   ```

4. **Check memory usage:**
   ```bash
   redis-cli -h redis-master -p 6379 INFO memory | grep used_memory_percent
   # Expected: < 70%; Warning: > 90%
   ```

**Investigation (within 15 minutes):**

5. **Identify slow commands:**
   ```bash
   redis-cli -h redis-master -p 6379 SLOWLOG GET 10 | head -20
   ```

6. **Check for persistence activity:**
   ```bash
   redis-cli -h redis-master -p 6379 INFO persistence | grep -E "rdb_bgsave_in_progress|aof_rewrite_in_progress"
   ```

7. **Analyze key distribution:**
   ```bash
   redis-cli -h redis-master -p 6379 DEBUG OBJECT <key>
   # Check encoding, serialized_length
   ```

**Mitigation (within 30 minutes):**

8. **If CPU saturated:**
   - Scale Redis horizontally (add replica):
     ```bash
     kubectl apply -f - <<EOF
     apiVersion: v1
     kind: Pod
     metadata:
       name: redis-replica-1
     spec:
       containers:
       - name: redis
         image: redis:7.4-alpine
         command: ["redis-server", "--slaveof", "redis-master", "$REDIS_PORT"]
     EOF
     ```
   - Update Sentinel connection to use read replicas for nonce reads

9. **If memory full:**
   - Check for key leaks:
     ```bash
     redis-cli -h redis-master -p 6379 KEYS "nonce:*" | wc -l
     # Expected: < 10,000; Warning: > 100,000
     ```
   - Manually evict stale keys:
     ```bash
     for key in $(redis-cli KEYS "nonce:*:stale"); do redis-cli DEL $key; done
     ```
   - Increase Redis memory limit (if not at system limit)

10. **If persistence ongoing:**
    - Move persistence to replica:
      ```bash
      CONFIG SET stop-writes-on-bgsave-error no
      BGSAVE  # Background save to unblock
      ```
    - Wait for completion before restarting

**Post-Incident:**

11. **Update baselines:**
    - Increase alert threshold if latency spikes are normal
    - OR add scaling trigger: auto-add Redis replicas if p99 > 30ms for 10 minutes

### Alert: Rate Limit Saturation (> 5% Throttled)

**Trigger:** `rate(rate_limit_exceeded_total[5m]) / rate(http_requests_total[5m]) > 0.05`

**Severity:** WARNING

**Possible Causes:**
1. Legitimate usage spike (high traffic, many users)
2. DoS attack (coordinated high-rate requests)
3. Client bug (retry loop without backoff)
4. Rate limit misconfiguration (quota too low)

**Immediate Response (within 5 minutes):**

1. **Check rate limit partition breakdown:**
   ```bash
   kubectl logs -f deployment/sentinel --selector=app=sentinel \
     | jq 'select(.event_type == "rate_limit_exceeded") | .partition' \
     | sort | uniq -c | sort -rn
   ```

2. **Classify saturation:**
   - **Per-identity partition:** Auth endpoints (refresh, logout) hitting quota
   - **Per-IP partition:** Many anonymous requests from same IP(s)
   - **Both partitions:** Broad attack or legitimate spike

3. **Check originating IPs:**
   ```bash
   kubectl logs -f deployment/sentinel --selector=app=sentinel \
     | jq 'select(.event_type == "rate_limit_exceeded") | {ip: .remote_ip, partition: .partition}' \
     | sort | uniq -c | sort -rn | head -10
   ```

**Investigation (within 15 minutes):**

4. **Correlate with traffic increase:**
   ```bash
   # Check total request rate
   kubectl logs -f deployment/sentinel --selector=app=sentinel \
     | jq '.timestamp' | tail -1000 | jq 'count' / 60  # req/sec
   
   # Expected: 100-500 req/sec; Warning: > 1000 req/sec
   ```

5. **Identify attack signature (if under attack):**
   - Check for same User-Agent across failed requests
   - Check for same endpoint (/v1/auth/refresh flood)
   - Check for random User-Agents (bot scanner)

6. **Check upstream metrics:**
   ```bash
   # AWS ELB / Azure Load Balancer
   # Increase in 4xx errors, 503 responses
   # Spike in active connections
   ```

**Mitigation (within 30 minutes):**

7. **If legitimate spike:**
   - Increase rate limit quota temporarily:
     ```bash
     kubectl patch configmap sentinel-config --patch-file - <<EOF
     data:
       appsettings.json: |
         { "RateLimiting": { "PerIdentityQuota": 60, "PerIpQuota": 120 } }
     EOF
     ```
   - Restart Sentinel pods to apply
   - Monitor; revert if necessary

8. **If DoS attack:**
   - Enable emergency IP blocklist:
     ```bash
     kubectl apply -f - <<EOF
     apiVersion: v1
     kind: ConfigMap
     metadata:
       name: blocked-ips
     data:
       ips: |
         192.0.2.1
         192.0.2.2
         ...  # list of attacking IPs
     EOF
     ```
   - Deploy network policy to drop traffic from blocked IPs:
     ```bash
     kubectl apply -f network-policy-block-ips.yaml
     ```

9. **If client bug (retry loop):**
   - Identify client (User-Agent, client_id)
   - Reach out to client team with diagnostic data
   - Temporarily increase per-client quota while they fix

**Post-Incident:**

10. **Review and update quotas:**
    - Analysis: what was normal peak? (99th percentile)
    - Set quota to 1.5x normal peak for headroom
    - Document quota rationale in runbook

11. **Implement gradient backoff:**
    - Clients seeing 429 should retry with exponential backoff + jitter
    - Monitor for compliance

---

## Troubleshooting Procedures

### No DPoP-Nonce in Response

**Symptom:** Client requests `/v1/profile`, receives 400 but no `DPoP-Nonce` header.

**Likely Causes:**
1. Sentinel middleware misconfiguration (challenge nonce issuance disabled)
2. Redis nonce store unreachable (fails silently)
3. Client received 400 from upstream (WAF, LB) not from Sentinel

**Troubleshooting Steps:**

```bash
# 1. Verify middleware is enabled
kubectl get configmap sentinel-config -o yaml | grep -i dpop

# 2. Check Sentinel logs for exceptions
kubectl logs -f deployment/sentinel --selector=app=sentinel \
  | grep -E "(DpopValidation|nonce_store|exception)" | head -20

# 3. Verify Redis connectivity from Sentinel
kubectl exec pod/sentinel-0 -- /bin/sh -c \
  "redis-cli -h redis-master -p 6379 ping"
# Expected output: PONG

# 4. Test nonce generation manually
kubectl exec pod/sentinel-0 -- /bin/sh -c \
  "redis-cli -h redis-master -p 6379 SET test:nonce testvalue EX 60"
# Expected: OK

# 5. Check upstream (WAF, LB) is not filtering DPoP-Nonce header
curl -v -H "Authorization: Bearer <token>" https://api.sentinel.local/v1/profile 2>&1 | grep -i dpop
```

**Resolution:**

- **If middleware disabled:** Update configmap to enable; restart pods
- **If Redis disconnect:** Check connectivity; restart Redis; verify connection string
- **If upstream filtering:** Update WAF/LB rules to allow DPoP-Nonce header

### High DPoP Proof Validation Failures

**Symptom:** Clients report frequent 400 errors; metric `dpop_validation_failures_total` increasing.

**Likely Causes:**
1. Client clock skew (proof `iat` too old or future)
2. Client using wrong JWK (key rotation on client side not synced)
3. Wrong HTTP method in proof (client proof says GET, request is POST)
4. Proof expired (> 60s old)

**Troubleshooting Steps:**

```bash
# 1. Check for clock skew alerts
kubectl logs -f deployment/sentinel --selector=app=sentinel \
  | jq 'select(.error_code == "proof_clock_skew") | .message'

# If many: sync system clocks
ntpdate -u ntp.example.com

# 2. Check for signature verification failures
kubectl logs -f deployment/sentinel --selector=app=sentinel \
  | jq 'select(.error_code == "proof_signature_invalid") | .message'

# 3. Check for method/URI mismatch
kubectl logs -f deployment/sentinel --selector=app=sentinel \
  | jq 'select(.error_code == "proof_method_uri_mismatch") | {htm: .proof_htm, actual: .request_method}'

# 4. Enable verbose DPoP validation logging
kubectl patch deployment sentinel --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/env", "value": [{"name": "SENTINE_LOG_LEVEL", "value": "Debug"}]}]'
kubectl rollout restart deployment/sentinel

# 5. Capture sample proofs from clients
# Client sends DPoP: <proof_jwt>
# Decode proof (base64 decode; check claims)
echo "<proof_jwt>" | cut -d'.' -f2 | base64 -d | jq '.'
```

**Resolution:**

- **If clock skew:** Sync client/server clocks; verify NTP is running
- **If key rotation:** Distribute new public key to clients; rollback if needed
- **If method/URI:** Update client to populate proof.htm and proof.htu correctly
- **If expiration:** Increase client-side timeout for proof generation

### Idempotency Conflicts (409 Responses)

**Symptom:** Logout requests return 409 Conflict frequently.

**Likely Causes:**
1. Client retrying too quickly (faster than 5m in-progress timeout)
2. Logout operation hanging (> 5m duration)
3. Idempotency-Key header not sent (requests treated as new each time)

**Troubleshooting Steps:**

```bash
# 1. Check idempotency logs
kubectl logs -f deployment/sentinel --selector=app=sentinel \
  | jq 'select(.event_type == "idempotency_conflict") | {idempotency_key: .idempotency_key, retry_count: .retry_count}'

# 2. Check logout operation duration
kubectl logs -f deployment/sentinel --selector=app=sentinel \
  | jq 'select(.endpoint == "/v1/auth/logout") | {duration_ms: .duration_ms, status: .status_code}'

# 3. Inspect Redis idempotency keys to find stuck operations
redis-cli -h redis-master -p 6379 KEYS "idempotency:*:in_progress" | while read key; do
  echo "$key: $(redis-cli -h redis-master -p 6379 TTL $key)"
done

# 4. Find stale operations (TTL < 0 but key still exists)
redis-cli -h redis-master -p 6379 SCAN 0 MATCH "idempotency:*:in_progress" \
  | xargs -I {} redis-cli -h redis-master -p 6379 TTL {}
```

**Resolution:**

- **If client retrying too quickly:** Educate client on idempotency semantics; retry after 2-3 seconds minimum
- **If operation hanging:** Check Keycloak connectivity; if slow, increase in-progress timeout from 5m to 15m
- **If Idempotency-Key missing:** Ensure clients always set header (UUID format); verify on wire with tcpdump

---

## Incident Response

### Incident: Suspected Token Compromise (Batch Replay Detected)

**Escalation:** CRITICAL → Page on-call security team immediately

**Timeline:**

**T+0 (Alert triggered)**
- Alert: `jwt_replay_detected_total > 0`
- Responsible: On-call SRE

**T+2 (Immediate confirmation)**

1. Confirm alert is not false positive:
   ```bash
   # Check recent security events
   kubectl logs -f deployment/sentinel --selector=app=sentinel -n production \
     | jq 'select(.event_type == "jwt_replay_detected")' | head -20
   ```

2. Count affected users:
   ```bash
   COUNT=$(kubectl logs --tail=1000 deployment/sentinel \
     | jq -s 'map(select(.event_type == "jwt_replay_detected")) | length')
   echo "Replays in last 1000 logs: $COUNT"
   ```

3. If COUNT > 10 over < 5 minutes → **Assume breach; escalate immediately**

**T+5 (Escalation & War Room)**

- Page: Security Lead, Infrastructure Lead, Product Lead
- Open war room (Slack channel #incident-security-token)
- Set incident severity: SEV-1 (Critical)

**T+10 (Isolation & Containment)**

1. Pause new token issuance:
   ```bash
   kubectl patch configmap sentinel-config -p '{"data": {"authentication_paused": "true"}}'
   kubectl rollout restart deployment/sentinel
   ```

2. Revoke all refresh tokens issued in last 24h:
   ```bash
   # Via Keycloak admin API
   curl -X POST http://keycloak:8080/admin/realms/sentinel/tokens/revoke \
     -H "Authorization: Bearer $KC_ADMIN_TOKEN" \
     -d '{"client_id": "*"}' \
     -H "Content-Type: application/json"
   ```

3. Blacklist affected user sessions:
   ```bash
   # Extract user IDs from replay logs
   USERS=$(kubectl logs -f deployment/sentinel | jq -r '.user_id' | sort -u)
   
   # For each user, add to session blacklist
   for user in $USERS; do
     redis-cli -h redis-master SET "blacklist:session:$user" "compromised" EX 86400
   done
   ```

4. Notify affected users:
   - Template: "Your session was terminated due to security event. Please log in again."
   - Delivery: Email, in-app notification
   - Timeline: Within 15 minutes

**T+30 (Investigation & Root Cause)**

1. Collect forensic data:
   ```bash
   # Export logs for analysis
   kubectl logs deployment/sentinel --tail=10000 > /tmp/sentinel-incident.log
   
   # Export Redis state
   redis-cli -h redis-master BGSAVE
   # Wait for RDB completion; copy to S3/Azure Blob
   
   # Check Keycloak audit log for irregular events
   ```

2. Analyze attack patterns:
   - Unique attacker IPs: `jq '.remote_ip' sentinel-incident.log | sort -u | wc -l`
   - Time of first replay: `jq '.timestamp' sentinel-incident.log | min`
   - Token issuance source: `jq '.issued_by' sentinel-incident.log | sort | uniq -c`

3. Determine scope:
   - **Contained:** Replays detected within 5 min; < 100 affected users → revoke and move on
   - **Breach:** Replays over hours; > 1000 affected users → escalate to executive + PR

**T+1h (Comms & Notifications)**

1. Post-incident notification to customers:
   - Status: "Security event detected and contained; no data loss"
   - Cause: "Unauthorized token reuse attempt; attacker identity unknown"
   - Action: "Users affected have been logged out; re-authentication required"
   - Prevention: "Replay detection enabled; tokens automatically invalidated"

2. Internal notification:
   - Engineering: "Review client DPoP generation code for replay vectors"
   - Security: "Conduct threat hunt for other breaches"
   - Product: "Consider MFA requirement for high-risk operations"

**T+24h (Post-Incident Review)**

1. RCA (Root Cause Analysis):
   ```bash
   # Did we find the vector?
   # - Client logging tokens insecurely?
   # - Keycloak issuing duplicate JTIs?
   # - Redis persistence snapshot exfiltration?
   # - Insider threat?
   
   # Recommendation: Implement mandatory code review for token handling
   ```

2. Prevent future incidents:
   - Add rate limiting on token refresh (10 req/min per user)
   - Enable token binding to device fingerprint (TBD w/ product)
   - Implement anomalous token usage detection
   - Add JWT signing key rotation every 90 days

---

## Maintenance & Upgrades

### Keycloak Realm Configuration Backup

**Frequency:** Daily automated, manual backup before changes  
**Retention:** 30 days rolling

```bash
# Automated backup (cron job)
0 2 * * * /usr/local/bin/keycloak-backup.sh

# Manual backup before realm changes
#!/bin/bash
set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/backups/sentinel-realm-$TIMESTAMP.json"

kubectl exec pod/keycloak-0 -- \
  /opt/keycloak/bin/kcadm.sh export \
  --realm sentinel \
  > $BACKUP_FILE

echo "Backup saved: $BACKUP_FILE"

# Verify backup integrity
jq '.' $BACKUP_FILE > /dev/null && echo "✓ Backup valid"
```

### Redis Cluster Health Check

**Frequency:** Daily; twice daily during peak traffic  
**On-call:** SRE responsible

```bash
#!/bin/bash
# redis-health-check.sh

echo "=== Redis Cluster Health ==="

# Primary
echo "Primary:"
redis-cli -h redis-master -p 6379 INFO replication | grep role

# Replicas
for i in {1..2}; do
  echo "Replica $i:"
  redis-cli -h redis-replica-$i -p 6379 INFO replication | grep role
done

# Check for divergence
PRIMARY_OFFSET=$(redis-cli -h redis-master -p 6379 INFO replication | grep master_repl_offset | cut -d':' -f2)
REPLICA1_OFFSET=$(redis-cli -h redis-replica-1 -p 6379 INFO replication | grep slave_repl_offset | cut -d':' -f2)

DIFF=$((PRIMARY_OFFSET - REPLICA1_OFFSET))
if [ $DIFF -gt 1000 ]; then
  echo "⚠️  WARNING: Replica lag > 1000 bytes; investigate replication"
  # Trigger alert
fi
```

### Sentinel Pod Deployment Checklist

**Before deploying new version:**

```
PRE-DEPLOYMENT
☐ Review changelog and breaking changes
☐ Run security scan on new image: `trivy image ghcr.io/nikatanats/sentinel:v1.0.0`
☐ Verify integration tests pass: `dotnet test`
☐ Verify load test: `k6 run load-test.js` (target: < 500ms p99)
☐ Backup current Redis state: `redis-cli BGSAVE`
☐ Notify #incident channel of planned deployment window

DEPLOYMENT (Blue-Green)
☐ Deploy new version to blue environment (0 traffic)
☐ Smoke tests: curl -u user:pass https://blue.api.sentinel.local/v1/health
☐ Monitor errors for 2 minutes; if green → proceed
☐ Gradually shift traffic: 10% → blue (monitor 5 min)
☐ Shift remaining 90% → blue
☐ Keep green environment running for 1h rollback window

POST-DEPLOYMENT
☐ Verify no increase in auth failures: rate(auth_failure[5m]) < 2%
☐ Verify no increase in DPoP failures: rate(dpop_failure[5m]) < 1%
☐ Verify Redis latency steady: p99 < 10ms
☐ Check notification: "Deployment successful" → #incident
☐ After 1h: decommission green environment
```

---

## Dashboards & Tools

### Key Grafana Dashboards

1. **Sentinel Main (SLO Dashboard)**
   - Request rate (total, by status code)
   - Error rate (by error type)
   - Auth success rate (SLO target: 99.5%)
   - DPoP success rate (SLO target: 98%)

2. **Rate Limiting & Abuse**
   - Rate limit hit rate per partition
   - Top IPs by 429 response
   - Top clients by 429 response

3. **Infrastructure & Dependencies**
   - Redis latency and pool size
   - Keycloak availability and latency
   - Pod restart count and CPU/memory usage

4. **Security Events**
   - JWT replay detections (CRITICAL)
   - DPoP failures by reason
   - Nonce cache hit rate
   - Session blacklist churn

### Query Examples

```promql
# SLO: Auth success rate
(1 - (rate(authentication_failures_total[5m]) / rate(http_requests_total{endpoint="/v1/auth/*"}[5m]))) * 100

# Rate limit saturation trend (6h rolling)
rate(rate_limit_exceeded_total[5m]) / rate(http_requests_total[5m]) * 100

# Redis latency p99
histogram_quantile(0.99, rate(redis_latency_milliseconds_bucket[5m]))

# DPoP proof failures by reason
sum by (reason) (rate(dpop_validation_failures_total[5m]))
```

---

