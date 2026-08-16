#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# Generates a self-signed CA + server cert + PKCS#12 keystore for the local
# OIDF FAPI 2.0 Conformance Suite stack. Idempotent: overwrites its own
# artifacts on every run (they are test-only, never used in production).
#
# Usage:  bash infra/fapi-conformance/certs/generate-fapi-certs.sh
#         FAPI_KEYSTORE_PASSWORD=sentinel-fapi  (must match .env)
set -euo pipefail

# Self-locating: always write artifacts next to this script regardless of CWD.
cd "$(dirname "${BASH_SOURCE[0]}")"

umask 077

KEYSTORE_PASS="${FAPI_KEYSTORE_PASSWORD:-sentinel-fapi}"
DAYS=365

CA_KEY="ca.key"
CA_CRT="ca.crt"
SRV_KEY="server.key"
SRV_CSR="server.csr"
SRV_CRT="server.crt"
PKCS12="keystore.p12"
TRUSTSTORE="truststore.p12"
SAN_CNF="san.cnf"

# Regeneration is idempotent: remove previous artifacts before rewriting.
rm -f "$CA_KEY" "$CA_CRT" "$CA_CRT".srl "$SRV_KEY" "$SRV_CSR" "$SRV_CRT" "$PKCS12" "$TRUSTSTORE" "$SAN_CNF"

echo "==> Generating CA..."
openssl req -x509 -newkey rsa:4096 -days "$DAYS" -nodes \
  -keyout "$CA_KEY" -out "$CA_CRT" \
  -subj "/CN=Sentinel FAPI Suite CA/O=Sentinel" -sha256

echo "==> Generating server key + CSR..."
openssl req -newkey rsa:2048 -nodes \
  -keyout "$SRV_KEY" -out "$SRV_CSR" \
  -subj "/CN=localhost/O=Sentinel FAPI Suite" -sha256

cat > "$SAN_CNF" <<EOF
[v3_ext]
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = fapi-suite-server
DNS.3 = fapi-proxy
DNS.4 = host.docker.internal
IP.1  = 127.0.0.1
EOF

echo "==> Signing server cert..."
openssl x509 -req -in "$SRV_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" \
  -CAcreateserial -out "$SRV_CRT" -days "$DAYS" \
  -extfile "$SAN_CNF" -extensions v3_ext -sha256

echo "==> Building PKCS#12 keystore for Spring Boot..."
openssl pkcs12 -export \
  -in "$SRV_CRT" -inkey "$SRV_KEY" \
  -out "$PKCS12" -name fapi-suite \
  -passout "pass:${KEYSTORE_PASS}"

echo "==> Building PKCS#12 truststore for outbound TLS (Keycloak's CA)..."
# Java 9+ reads PKCS12 truststores natively; the suite's JVM uses this to
# trust the infra/certs CA that signs Keycloak's dev certificate.
openssl pkcs12 -export -nokeys \
  -in "$CA_CRT" \
  -out "$TRUSTSTORE" \
  -passout "pass:${KEYSTORE_PASS}"

chmod 400 "$CA_KEY" "$SRV_KEY"
chmod 444 "$CA_CRT" "$SRV_CRT" "$PKCS12" "$TRUSTSTORE"

rm -f "$SRV_CSR" "$SAN_CNF" "$CA_CRT".srl

echo "✓ Certificates generated in $(pwd)"
ls -lh "$CA_CRT" "$SRV_CRT" "$PKCS12" "$TRUSTSTORE"