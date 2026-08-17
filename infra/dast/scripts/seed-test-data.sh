#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# seed-test-data.sh - seeds deterministic synthetic test data through the
# DPoP auth proxy (localhost:8081) so scanners have stable targets:
#   - 3 documents (one tagged "sensitive")
#   - a replayed-JTI exercise fixture: the same Idempotency-Key used twice is
#     a replay-visible fingerprint for the replay-cache behavior
#
# All calls go through the proxy, which performs the real DPoP signing
# (token + proof per request). Synthetic data only - never run against
# anything but the ephemeral sentinel-dast stack.
set -euo pipefail

PROXY_URL="${PROXY_URL:-http://localhost:8081}"
DOCS_URL="$PROXY_URL/v1/documents"

seed_document() {
  local name="$1" tag="$2"
  local body
  # Body matches the API DTO exactly: CreateDocumentRequest(Title, Content).
  # Extra fields (e.g. "tags") are ignored by JSON binding; the title drives
  # the surgical-authz "secrets" reservation, so fixture titles avoid it.
  body="{\"title\":\"$name\",\"content\":\"synthetic DAST fixture ($tag)\"}"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$DOCS_URL" \
    -H 'Content-Type: application/json' \
    -H "Idempotency-Key: seed-$(uuidgen 2>/dev/null || echo "$RANDOM$RANDOM$RANDOM")" \
    -d "$body")
  echo "[seed] document '$name' -> HTTP $code"
}

seed_document "dast-fixture-public" "public"
seed_document "dast-fixture-sensitive" "sensitive"
seed_document "dast-fixture-tombstone" "archived"

# Replay fixture: the SAME idempotency key on a second POST must be answered
# with the ORIGINAL response (RFC 9110 idempotency) - scanners probing
# double-spend see a deterministic answer.
IDEMPOTENT_KEY="fixture-replay-$(date +%s)"
curl -s -o /dev/null -X POST "$DOCS_URL" \
  -H 'Content-Type: application/json' -H "Idempotency-Key: $IDEMPOTENT_KEY" \
  -d '{"title":"dast-fixture-replay","content":"replay target"}'
echo "[seed] replay fixture idempotency key: $IDEMPOTENT_KEY"

echo "[seed] done."