#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# wait-for-stack.sh - blocks until the DAST stack is ready:
#   1. sentinel-api /healthz            (host port 5260)
#   2. Keycloak sentinel-dast realm discovery (https://localhost:8443)
#   3. the DAST auth proxy /proxy-health (host port 8081)
#
# NOTE: the readiness curl to Keycloak uses --insecure because the local CA
# (`infra/certs/ca.crt`) is trusted by the COMPONENTS (proxy, API) at runtime;
# this script is only a liveness probe on a host shell, it performs no
# handshake-dependent security decision.
set -euo pipefail

MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-180}"

wait_http() {
  local url="$1" name="$2" extra=("${@:3}")
  local i
  for i in $(seq 1 "$MAX_WAIT_SECONDS"); do
    if curl -fs "${extra[@]}" -o /dev/null "$url" 2>/dev/null; then
      echo "[ok] $name is up"
      return 0
    fi
    sleep 1
  done
  echo "[fatal] $name did not become reachable at $url within ${MAX_WAIT_SECONDS}s" >&2
  return 1
}

wait_http "http://localhost:5260/healthz" "sentinel-api"
wait_http "https://localhost:8443/realms/sentinel-dast/.well-known/openid-configuration" "keycloak sentinel-dast realm" "--insecure"
wait_http "http://localhost:8081/proxy-health" "dast-auth-proxy"

echo "DAST stack ready."