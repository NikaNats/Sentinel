#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# Native AOT serialization gate for the Reflection-Fallback hardening effort.
#
# The project ships with JsonSerializerIsReflectionEnabledByDefault=false, so the
# JIT test suites behave like Native AOT for System.Text.Json and any reflection
# fallback already fails fast at test time. This gate closes the loop by publishing
# the AdversarialTestHost (which wires the full Sentinel.AspNetCore / DPoP / Redis /
# SSF / SdJwt pipeline and deliberately avoids EF Core) as a TRUE Native AOT binary
# and sweeping its endpoint matrix, failing on:
#   * any HTTP 5xx (an unhandled exception, e.g. NotSupportedException from a
#     serializer without metadata, escaping into a 500)
#   * a "Reflection-based serialization has been disabled" / NotSupportedException
#     in the host log
#   * the app failing to boot under AOT
#
# Usage:
#   tests/scripts/validate-native-aot.sh [linux-x64|linux-arm64|win-x64]
#
# Env:
#   AOT_PORT   bind port for the published binary (default 5080)
#   AOT_RID    target runtime identifier (defaults to first positional arg or linux-x64)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RID="${1:-${AOT_RID:-linux-x64}}"
PORT="${AOT_PORT:-5080}"
PROJECT="$REPO_ROOT/tests/Sentinel.Tests.Load/AdversarialTestHost.csproj"
PUBLISH_DIR="$REPO_ROOT/artifacts/aot/$RID"
BASE_URL="http://localhost:$PORT"
HOST_LOG="$REPO_ROOT/artifacts/aot/host.log"

fail() {
  echo "NATIVE-AOT GATE VIOLATION: $*" >&2
  echo "--- Host log tail (last 80 lines) ---" >&2
  tail -n 80 "$HOST_LOG" >&2 || true
  exit 1
}

ok() {
  echo "OK: $*"
}

mkdir -p "$REPO_ROOT/artifacts/aot"

echo "==> Publishing $RID Native AOT binary"
# IL2026/IL3050 are trimming/AOT analyzer warnings from EF Core's DbContext ctor and
# Options.ValidateDataAnnotations (Sentinel.AspNetCore/Keycloak). They are a documented,
# separate limitation of true NativeAOT for the full Sentinel graph, NOT the
# System.Text.Json reflection-fallback contract this gate enforces, and neither path
# is executed by the AdversarialTestHost at runtime. Downgrade exactly those two from
# errors to warnings (WarningsNotAsErrors is used so the repo's NoWarn/CA suppressions
# stay intact); the gate's real verdict is the runtime endpoint sweep below.
# NOTE: %3B (not ';') is required inside -p: values - MSBuild's switch parser treats a
# literal semicolon as a switch separator ("MSB1006: Property is not valid").
dotnet publish "$PROJECT" \
  --configuration Release \
  --runtime "$RID" \
  --self-contained \
  -p:PublishAot=true \
  -p:WarningsNotAsErrors=IL2026%3BIL3050 \
  -p:SkipGetBuildVersion=true \
  -p:NBGV_Disable=true \
  -o "$PUBLISH_DIR"

BINARY="$PUBLISH_DIR/AdversarialTestHost"
if [ ! -x "$BINARY" ]; then
  # Windows publish produces an .exe; look for it as a fallback.
  if [ -x "$PUBLISH_DIR/AdversarialTestHost.exe" ]; then
    BINARY="$PUBLISH_DIR/AdversarialTestHost.exe"
  else
    fail "Native AOT binary not produced at $PUBLISH_DIR"
  fi
fi

echo "==> Booting native binary on :$PORT"
"$BINARY" --urls "$BASE_URL" >"$HOST_LOG" 2>&1 &
APP_PID=$!

cleanup() {
  kill "$APP_PID" 2>/dev/null || true
  wait "$APP_PID" 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Waiting for healthz"
READY=false
for _ in $(seq 1 60); do
  if curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; then
    READY=true
    break
  fi
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

if [ "$READY" = "false" ]; then
  fail "Native binary did not become healthy. See log."
fi
ok "Native binary booted and /healthz responds"

# expected_status is a regex; 5xx is always rejected.
check() {
  local name="$1" method="$2" path="$3" expected="$4" data="${5:-}"
  local code
  if [ -n "$data" ]; then
    code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" \
      -H 'Content-Type: application/json' -d "$data" || true)
  else
    code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE_URL$path" || true)
  fi

  if [[ "$code" =~ ^5 ]]; then
    fail "$method $path -> $code (5xx: unhandled exception / missing serializer metadata)"
  fi
  if ! [[ "$code" =~ $expected ]]; then
    fail "$method $path -> $code (expected ~$expected)"
  fi
  ok "$method $path -> $code"
}

# GET probes (anonymous).
check "healthz"        GET  "/healthz"                          "^200$"
check "root"           GET  "/"                                 "^200$"
check "profile"        GET  "/api/v1/showcase/profile"          "^200$"

# DTO-bound POST endpoints (anonymous / auth-required).
# The mock endpoints return 200 (no real token flow is wired in this host); the
# contract asserted here is "no 5xx, correct status, no serializer failures".
check "token-exchange" POST "/api/system/security/auth/token-exchange" \
  "^200$" '{"externalToken":"fake","providerName":"google","codeVerifier":"abc"}'
check "refresh"        POST "/api/system/security/auth/refresh" \
  "^200$" '{"refreshToken":"mock"}'
check "backchannel"    POST "/api/system/security/auth/backchannel-logout" "^200$"

# Auth-required endpoints MUST be rejected with 401/403/400, never 5xx.
check "change-password" POST "/api/system/security/auth/change-password" \
  "^40[013]$" '{"newPassword":"Strong$Secure9513"}'
check "logout"         POST "/api/system/security/auth/logout" \
  "^40[013]$" '{"refreshToken":"mock"}'
check "sessions"       GET  "/api/system/security/auth/sessions" "^40[013]$"
check "documents"      GET  "/api/v1/documents"                  "^40[013]$"
check "documents-post" POST "/api/v1/documents"                  "^40[013]$" '{"title":"t","content":"c"}'
check "finance"        POST "/api/v1/finance/transfer"           "^40[013]$" \
  '{"transactionId":"txn-1","amount":10,"currency":"USD","destinationAccount":"acc-1"}'
check "ssf-events"     POST "/api/system/security/ssf/events"    "^40[013]$" '{"set":"mock"}'
check "showcase-context" GET "/api/v1/showcase/security-context" "^40[013]$"
check "showcase-protected" GET "/api/v1/showcase/test/protected" "^40[013]$"
check "showcase-stepup"   GET "/api/v1/showcase/test/step-up"    "^40[013]$"

echo "==> Scanning host log for reflection-fallback / serializer failures"
if grep -Ei "NotSupportedException|Reflection-based serialization has been disabled|JsonSerializerIsReflectionEnabledByDefault" "$HOST_LOG"; then
  fail "Host log contains serializer/reflection fallback evidence."
fi

ok "No 5xx responses and no serializer reflection-fallback evidence"
echo
echo "NATIVE-AOT GATE PASSED ($RID)"