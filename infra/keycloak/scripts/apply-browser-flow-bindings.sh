#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# apply-browser-flow-bindings.sh - binds clients to the government-aal3-browser
# WebAuthn flow AFTER realm import.
#
# WHY THIS EXISTS: Keycloak's single-file realm import resolves client
# authenticationFlowBindingOverrides BEFORE the custom flows are registered
# (verified on 26.6.4: import aborts with "Unable to resolve auth flow binding
# override for: browser"). The flow itself imports declaratively; only the
# client -> flow binding must be applied via the admin API post-import.
#
# Required environment:
#   KC_ADMIN_URL         Keycloak base URL (e.g. https://keycloak.staging.sentinel.io)
#   KC_REALM             realm (default sentinel)
#   KC_ADMIN_USER / KC_ADMIN_PASSWORD  or  KC_ADMIN_TOKEN (master realm)
#   KCADM_BIN            optional explicit path to kcadm.sh
# Optional:
#   BINDINGS             "clientId1=flowAlias1 clientId2=flowAlias2" (default
#                        "sentinel-api-client=government-aal3-browser")
#
# Idempotent: re-running is a no-op update.
set -euo pipefail

KC_ADMIN_URL="${KC_ADMIN_URL:?KC_ADMIN_URL is required}"
KC_REALM="${KC_REALM:-sentinel}"
BINDINGS="${BINDINGS:-sentinel-api-client=government-aal3-browser}"

KCADM="${KCADM_BIN:-kcadm.sh}"
DOCKER_FALLBACK="${DOCKER_FALLBACK:-}"
if ! command -v "$KCADM" >/dev/null 2>&1; then
  if [ "$DOCKER_FALLBACK" = "true" ] && command -v docker >/dev/null 2>&1; then
    # kcadm persists its session under Java user.home (the passwd home of the
    # uid; the image's keycloak user has home=/opt/keycloak, root=/root). A
    # named volume at /root/.keycloak keeps the session across the --rm
    # invocations (each kcadm call is a separate container).
    KCADM="docker run --rm -u root -v kcadm-credentials:/root/.keycloak --entrypoint /opt/keycloak/bin/kcadm.sh quay.io/keycloak/keycloak:26.6.4"
  else
    echo "::error::kcadm.sh not found. Install the Keycloak CLI, set KCADM_BIN, or use DOCKER_FALLBACK=true." >&2
    exit 1
  fi
fi
# Under MSYS (Git Bash on Windows) docker.exe path-converts /opt/... into a
# Windows path; MSYS_NO_PATHCONV=1 keeps the in-container path intact.
if [ -n "${MSYSTEM:-}" ]; then
  kcadm() { MSYS_NO_PATHCONV=1 $KCADM "$@"; }
else
  kcadm() { $KCADM "$@"; }
fi

echo "==> authenticating kcadm against ${KC_ADMIN_URL}"
if [ -n "${KC_ADMIN_TOKEN:-}" ]; then
  kcadm config credentials --server "$KC_ADMIN_URL" --realm master --token "$KC_ADMIN_TOKEN" >/dev/null
else
  kcadm config credentials --server "$KC_ADMIN_URL" --realm master --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" >/dev/null
fi

# python3 is a Windows Store alias stub under Git Bash; prefer the real interpreter.
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  PYTHON_CMD="python3"
else
  PYTHON_CMD="python"
fi

for pair in $BINDINGS; do
  client_id="${pair%%=*}"
  flow_alias="${pair#*=}"
  [ -n "$client_id" ] && [ -n "$flow_alias" ] || { echo "::error::malformed BINDINGS entry: $pair" >&2; exit 1; }

  flow_id=$(kcadm get authentication/flows -r "$KC_REALM" 2>/dev/null | \
    $PYTHON_CMD -c 'import json,sys; d=json.load(sys.stdin); print(next((f["id"] for f in d if f["alias"]==sys.argv[1]), ""))' "$flow_alias" 2>/dev/null || echo "")
  [ -n "$flow_id" ] || { echo "::error::flow '$flow_alias' not found in realm '$KC_REALM'" >&2; exit 1; }

  client_id_internal=$(kcadm get clients -r "$KC_REALM" -q clientId="$client_id" 2>/dev/null | \
    $PYTHON_CMD -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")' 2>/dev/null || echo "")
  [ -n "$client_id_internal" ] || { echo "::error::client '$client_id' not found in realm '$KC_REALM'" >&2; exit 1; }

  body=$(kcadm get "clients/$client_id_internal" -r "$KC_REALM" 2>/dev/null | \
    $PYTHON_CMD -c 'import json,sys,subprocess; d=json.load(sys.stdin); d["authenticationFlowBindingOverrides"]={"browser":sys.argv[1]}; print(json.dumps(d))' "$flow_id")

  kcadm update "clients/$client_id_internal" -r "$KC_REALM" -b "$body"
  echo "    client '$client_id' -> browser flow '$flow_alias' (${flow_id})"
done

echo "==> browser flow bindings applied for realm ${KC_REALM}"
