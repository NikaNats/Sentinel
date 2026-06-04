#!/usr/bin/env bash
set -euo pipefail

echo "Starting infrastructure TLS and Zero Trust audit..."

KEYCLOAK_HOST="localhost:8443"
API_CONTAINER_NAME="sentinel-api"

echo -n "Test 1: Verify TLS 1.2 is blocked on Keycloak... "
if timeout 2 openssl s_client -connect "$KEYCLOAK_HOST" -tls1_2 < /dev/null 2>&1 | grep -q "no peer certificate available\|alert protocol version"; then
  echo "PASS (TLS 1.2 blocked)"
else
  echo "FAIL (TLS 1.2 is allowed)"
  exit 1
fi

echo -n "Test 2: Verify TLS 1.3 is supported... "
if timeout 2 openssl s_client -connect "$KEYCLOAK_HOST" -tls1_3 < /dev/null 2>&1 | grep -q "BEGIN CERTIFICATE"; then
  echo "PASS (TLS 1.3 active)"
else
  echo "FAIL (TLS 1.3 connection failed)"
  exit 1
fi

echo -n "Test 3: Verify OS Root CA trust inside the .NET container... "
if docker exec "$API_CONTAINER_NAME" curl -s -f -I https://keycloak:8443/realms/sentinel/.well-known/openid-configuration > /dev/null; then
  echo "PASS (CA trusted by container OS)"
else
  echo "FAIL (container does not trust Root CA or Keycloak is unreachable)"
  exit 1
fi

echo "All infrastructure security gates passed."
