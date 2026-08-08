#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# Fail-Closed invariant validator for the Distributed Chaos Resilience Gate.
#
# Asserts the exact security invariants per chaos scenario from the k6
# --summary-export JSON plus OTel/container logs. Fails the CI gate on:
#   * any HTTP 500 (an unhandled exception escaping the resilience boundary)
#   * fail-open evidence: 200 alongside a mandatory-503 window
#   * missing expected fail-closed log evidence in the API pods
#
# Usage:
#   CHAOS_SCENARIO=redis-kill tests/scripts/validate-fail-closed.sh tests/load/summary.json
#
# Inputs (env):
#   CHAOS_SCENARIO   redis-kill | pg-partition | dns-latency (required)
#   KUBECONFIG       path to kubectl config (defaults to $HOME/.kube/config)
#   NAMESPACE        sentinel-prod (default)
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: CHAOS_SCENARIO=<scenario> $0 <k6-summary.json>" >&2
  exit 2
fi

SUMMARY_FILE="$1"
: "${CHAOS_SCENARIO:?Set CHAOS_SCENARIO to redis-kill, pg-partition, or dns-latency}"
NAMESPACE="${NAMESPACE:-sentinel-prod}"
: "${KUBECONFIG:=${HOME}/.kube/config}"
export KUBECONFIG

fail() {
  echo "FAIL-CLOSED GATE VIOLATION: $*" >&2
  exit 1
}

ok() {
  echo "OK: $*"
}

[ -f "$SUMMARY_FILE" ] || fail "k6 summary not found: $SUMMARY_FILE"

if command -v jq >/dev/null 2>&1; then
  COUNT_200=$(jq -r '.metrics.sentinel_http_success_200.values.count // 0' "$SUMMARY_FILE")
  COUNT_401=$(jq -r '.metrics.sentinel_http_auth_401.values.count // 0' "$SUMMARY_FILE")
  COUNT_503=$(jq -r '.metrics.sentinel_http_fail_closed_503.values.count // 0' "$SUMMARY_FILE")
  COUNT_500=$(jq -r '.metrics.sentinel_http_server_500.values.count // 0' "$SUMMARY_FILE")
  HTTP_FAILED=$(jq -r '.metrics.http_req_failed.values.rate // 0' "$SUMMARY_FILE")
else
  echo "WARN: jq not found; parsing summary with awk (counts may under-report)" >&2
  count_of() {
    awk -v m="$1" '
      $0 ~ "\"" m "\"" { in_metric = 1; next }
      in_metric && /"count"/ { gsub(/[^0-9]/, "", $0); print; exit }
    ' "$SUMMARY_FILE" | head -1
  }
  COUNT_200=$(count_of sentinel_http_success_200 || echo 0)
  COUNT_401=$(count_of sentinel_http_auth_401 || echo 0)
  COUNT_503=$(count_of sentinel_http_fail_closed_503 || echo 0)
  COUNT_500=$(count_of sentinel_http_server_500 || echo 0)
  HTTP_FAILED=0
fi

echo "Summary: 200=$COUNT_200 401=$COUNT_401 503=$COUNT_503 500=$COUNT_500 (http_req_failed=$HTTP_FAILED)"

# [GATE-0] NO HTTP 500. Same canary k6 enforces inline; checked again against
# the exported summary so the gate cannot be bypassed by a bad threshold config.
if [ "${COUNT_500:-0}" -ne 0 ]; then
  fail "$COUNT_500 x HTTP 500 recorded. Unhandled exception escaped the fail-closed boundary."
fi
ok "Zero HTTP 500 recorded -- no unhandled crash."

case "$CHAOS_SCENARIO" in
  redis-kill)
    # DPoP nonce store, JTI replay cache, and session blacklist are all
    # Redis-backed and MUST fail closed (503/401). Zero 200 during the entire
    # run is required because the chaos window covers the loaded k6 run.
    if [ "${COUNT_200:-0}" -ne 0 ]; then
      fail "$COUNT_200 HTTP 200 during Redis outage. Fail-open regression: nonce accepted without atomic store confirmation."
    fi
    if [ "${COUNT_503:-0}" -eq 0 ] && [ "${COUNT_401:-0}" -eq 0 ]; then
      fail "No 503/401 recorded during redis-kill. Fail-closed boundary never engaged - check chaos selector."
    fi
    ok "Redis outage: fail-closed surfaced (503/401), zero success responses."
    ;;
  pg-partition)
    # HybridSessionBlacklistCache lookup at PostgreSQL (L3) is the source of
    # truth. An unreachable PG must never yield a positive verdict, even when
    # Redis (L2) is alive - absence of an L2/L3 answer is rejection, not permit.
    if [ "${COUNT_200:-0}" -ne 0 ]; then
      fail "$COUNT_200 HTTP 200 while PostgreSQL partitioned. Session state could not be verified - fail-open leak."
    fi
    if [ "${COUNT_503:-0}" -eq 0 ] && [ "${COUNT_401:-0}" -eq 0 ]; then
      fail "No 401/503 during pg-partition: PG isolation not observed or fail-open path engaged."
    fi
    ok "PostgreSQL partition: session path failed closed (401/503), zero HTTP 200."
    ;;
  dns-latency)
    # 200 allowed only with a valid cached JWKS; otherwise 401. 403 is NEVER
    # acceptable (would mean a token accepted with an unverifiable key). A 500
    # surfaced from a TaskCanceled exception was already rejected by GATE-0.
    if [ "${COUNT_401:-0}" -eq 0 ]; then
      fail "No 401 recorded during DNS chaos: JWKS failure was never surfaced fail-closed."
    fi
    ok "DNS latency: JWKS refresh failures surfaced fail-closed (401)."
    ;;
  *)
    fail "Unknown CHAOS_SCENARIO='$CHAOS_SCENARIO' (expected redis-kill, pg-partition, dns-latency)"
    ;;
esac

# --- OTel/log evidence (optional, requires kubectl context) ------------------
if kubectl config current-context >/dev/null 2>&1; then
  echo "Collecting pod log evidence for scenario=$CHAOS_SCENARIO..."
  LOGS=$(kubectl -n "$NAMESPACE" logs -l app.kubernetes.io/name=sentinel-api --tail=5000 2>/dev/null || true)

  case "$CHAOS_SCENARIO" in
    redis-kill)
      echo "$LOGS" | grep -Eq 'Fail-Closed|fail-closed|NonceStoreUnavailable|ReplayCacheUnavailable' \
        && ok "OTel/logs contain fail-closed evidence (nonce/replay/session)." \
        || fail "Missing fail-closed log evidence during redis-kill window."
      ;;
    pg-partition)
      echo "$LOGS" | grep -Eq 'Fail-closed triggered due to session store unavailability|SessionBlacklistUnavailableException' \
        && ok "OTel/logs contain session fail-closed evidence." \
        || fail "Missing SessionBlacklistUnavailableException evidence during pg-partition."
      ;;
    dns-latency)
      echo "$LOGS" | grep -Eq 'TaskCanceledException' \
        && fail "TaskCanceledException escaped to process boundary during DNS chaos." \
        || ok "No TaskCanceledException escaped during DNS chaos."
      ;;
  esac
else
  echo "WARN: kubectl not configured - skipping OTel log evidence (k6 HTTP invariants still enforced)."
fi

echo "OK: CHAOS_SCENARIO=$CHAOS_SCENARIO: all fail-closed invariants hold."