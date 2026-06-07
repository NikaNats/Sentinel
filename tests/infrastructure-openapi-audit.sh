#!/usr/bin/env bash
# tests/infrastructure-openapi-audit.sh
set -euo pipefail

echo "=== Gate 1: OpenAPI Schema Drift Audit ==="

COMMIT_SPEC="docs/OPENAPI_3_1.yaml"
GENERATED_SPEC="docs/generated_openapi.json"

if [ ! -f "$GENERATED_SPEC" ]; then
  echo "ERROR: Generated specification is missing. Run 'dotnet build -c Release' first."
  exit 1
fi

if ! npx -y @apidevtools/swagger-cli validate "$COMMIT_SPEC"; then
  echo "CRITICAL: Committed docs/OPENAPI_3_1.yaml is not a valid OpenAPI schema!"
  exit 1
fi

TEMP_JSON=$(mktemp)
npx -y @apidevtools/swagger-cli bundle "$COMMIT_SPEC" --outfile "$TEMP_JSON"

COMMIT_PATHS=$(mktemp)
GENERATED_PATHS=$(mktemp)

jq -S '.paths | map_values(keys)' "$TEMP_JSON" > "$COMMIT_PATHS"
jq -S '.paths | map_values(keys)' "$GENERATED_SPEC" > "$GENERATED_PATHS"

if ! diff -u "$COMMIT_PATHS" "$GENERATED_PATHS" > /dev/null; then
  echo "❌ FAIL: API Contract Drift Detected!"
  echo "The compiled .NET Minimal API routes/methods do not match docs/OPENAPI_3_1.yaml"
  echo "Please update your OpenAPI document with correct routes."
  echo "=== Route Diff Breakdown ==="
  diff -u "$COMMIT_PATHS" "$GENERATED_PATHS" || true
  rm -f "$TEMP_JSON" "$COMMIT_PATHS" "$GENERATED_PATHS"
  exit 1
else
  echo "✓ PASS: OpenAPI route registry is perfectly synchronized with .NET compilation."
  rm -f "$TEMP_JSON" "$COMMIT_PATHS" "$GENERATED_PATHS"
  exit 0
fi
