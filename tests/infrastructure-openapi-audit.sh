#!/usr/bin/env bash
# tests/infrastructure-openapi-audit.sh
# SOTA Gate 1: OpenAPI Schema Drift Audit
set -euo pipefail

echo "=== SOTA Gate 1: OpenAPI Schema Drift Audit ==="

COMMIT_SPEC="docs/OPENAPI_3_1.yaml"
GENERATED_SPEC="docs/generated_openapi.json"

if [ ! -f "$GENERATED_SPEC" ]; then
  echo "ERROR: Generated specification is missing. Run 'dotnet build -c Release' first."
  exit 1
fi

# Use swagger-cli to validate the committed spec structure
if ! npx -y @apidevtools/swagger-cli validate "$COMMIT_SPEC"; then
  echo "CRITICAL: Committed docs/OPENAPI_3_1.yaml is not a valid OpenAPI 3.1 schema!"
  exit 1
fi

# Convert YAML to temporary JSON for exact comparison
TEMP_JSON=$(mktemp)
npx -y @apidevtools/swagger-cli bundle "$COMMIT_SPEC" --outfile "$TEMP_JSON"

# Compare two JSON files structurally (ignoring formatting)
# jq uses sorted keys for accurate diff
if ! diff -u <(jq -S . "$TEMP_JSON") <(jq -S . "$GENERATED_SPEC") > /dev/null; then
  echo "❌ FAIL: API Contract Drift Detected!"
  echo "The compiled .NET Minimal API routes or schemas do not match docs/OPENAPI_3_1.yaml"
  echo "Please update the committed OpenAPI YAML file with your code changes."
  echo "=== Diff Breakdown ==="
  diff -u <(jq -S . "$TEMP_JSON") <(jq -S . "$GENERATED_SPEC") || true
  rm -f "$TEMP_JSON"
  exit 1
else
  echo "✓ PASS: OpenAPI schema is perfectly synchronized with .NET compilation."
  rm -f "$TEMP_JSON"
  exit 0
fi