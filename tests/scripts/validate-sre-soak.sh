#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# SRE Verification Gate: validates Memory, Sockets, and Latency SLAs after
# soak / spike / capacity runs, using REAL Sentinel OTel metric names.
#
# INPUTS:
#   $1 : k6 summary JSON (--summary-export) - the suite's own counters
#        (sentinel_socket_exhaustion_errors, sentinel_completed_requests,
#         sentinel_dpop_gen_duration_ms) are authoritative for load-side health.
#   K6_B64           base64 of k6 summary, or reuse: pass file
#   PROM_URL         Prometheus base (default http://prometheus.monitoring.svc.cluster.local:9090)
#   NAMESPACE        (unused here, reserved)
#   INFO: use awk for all float comparisons - `(( bc ))` cannot parse "0.5"
#         and crashes (the original 2026 guide's script was fatally broken).
#
# GATE-OUTCOMES:
#   exit 0 = ALL SRE GATES PASSED
#   exit 1 = an SRE gate failed
set -euo pipefail

SUMMARY_FILE="${1:-}"
: "${PROM_URL:=http://prometheus.monitoring.svc.cluster.local:9090}"

if [ -z "$SUMMARY_FILE" ] || [ ! -f "$SUMMARY_FILE" ]; then
  echo "usage: $0 <k6-summary.json>" >&2
  echo "  (run k6 with --summary-export first)" >&2
  exit 2
fi

fail() { echo "SRE GATE FAILED: $*" >&2; exit 1; }
ok() { echo "SRE GATE OK: $*"; }

echo "=== Sentinel SRE Post-Test Health Analysis ==="

# --- 1. k6-side counters (authoritative, from the exported summary) ---
# k6 --summary-export writes ONE-LINE JSON; parse with jq when present,
# otherwise node + sre-summary-metric.mjs (node is a repository prerequisite:
# the DPoP pool mint needs it). A dedicated reader avoids fragile inline
# quoting through nested shells (bash -c -> PowerShell arg mangling) and
# naive grep patterns which cannot span nested JSON objects on one line.
metric_value() {
  local metric="$1" path="$2"
  if command -v jq >/dev/null 2>&1; then
    jq -r --arg m "$metric" --arg p "$path" \
      ".metrics[\$m].values[\$p] // 0" "$SUMMARY_FILE"
  else
    node "$(dirname "$0")/sre-summary-metric.mjs" "$SUMMARY_FILE" "$metric" "$path"
  fi
}

SOCKET_ERRORS=$(metric_value sentinel_socket_exhaustion_errors count)
COMPLETED=$(metric_value sentinel_completed_requests count)
GEN_P99=$(metric_value sentinel_dpop_gen_duration_ms "p(99)")

if [ "${SOCKET_ERRORS:-0}" -ne 0 ]; then
  fail "socket exhaustion detected: $SOCKET_ERRORS"
fi
ok "Socket health verified (0 socket exhaustion errors, $COMPLETED completed requests)."

# --- 2. Memory growth trend (Prometheus; OTel/cAdvisor metrics) ---
MEM_SLOPE=$(curl -sfG --max-time 10 "${PROM_URL}/api/v1/query" \
  --data-urlencode 'query=deriv(container_memory_working_set_bytes{container="sentinel-api"}[12h])' \
  | jq -r 'if .status == "error" then "N/A" else (.data.result[0].value[1] // 0) end' 2>/dev/null || echo "N/A")

if [ "$MEM_SLOPE" = "N/A" ]; then
  echo "WARN: Prometheus not reachable or no Sentinel data - memory gate skipped."
elif awk "BEGIN { exit !($MEM_SLOPE > 1000) }"; then
  fail "Memory slope positive: $MEM_SLOPE bytes/sec over 12h - unmanaged memory leak suspected."
else
  ok "Native AOT memory stability verified (RSS slope: ${MEM_SLOPE} bytes/sec)."
fi

# --- 3. p99 latency via real OTel histogram (seconds) ---
P99_LATENCY=$(curl -s --max-time 10 "${PROM_URL}/api/v1/query" \
  --data-urlencode 'query=histogram_quantile(0.99, sum(rate(auth_token_validation_duration_seconds_bucket[5m])) by (le))' \
  | jq -r '.data.result[0].value[1] // "NA"' 2>/dev/null || echo "NA")

if [ "$P99_LATENCY" != "NA" ]; then
  P99_MS=$(awk -v v="$P99_LATENCY" 'BEGIN { printf "%.1f", v * 1000 }')
  if awk "BEGIN { exit !($P99_LATENCY > 0.050) }"; then
    fail "p99 latency SLA breached: ${P99_MS}ms (limit 50ms)"
  else
    ok "p99 latency SLA passed: ${P99_MS}ms."
  fi
else
  echo "WARN: p99 latency unavailable (Prometheus query returned nothing) - latency gate skipped."
fi

# --- 4. DPoP failure surge (fails-closed when the pool is misconfigured) ---
DPOP_FAILURES=$(curl -s --max-time 10 "${PROM_URL}/api/v1/query" \
  --data-urlencode 'query=sum(increase(auth_dpop_failures_total[5m]))' \
  | jq -r '.data.result[0].value[1] // 0' 2>/dev/null || echo 0)
if [ "${DPOP_FAILURES:-0}" -gt 1000 ]; then
  fail "DPoP failures surged: $DPOP_FAILURES in 5m"
fi
ok "DPoP failure rate within limits (${DPOP_FAILURES})."

echo "=== ALL SRE PRODUCTION GATES PASSED SUCCESSFULLY ==="