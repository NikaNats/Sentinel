#!/usr/bin/env bash
set -eu
export MSYS_NO_PATHCONV=1

# Self-locating: always write artifacts next to this script regardless of the
# invoking CWD (CI runs `bash infra/certs/generate-certs.sh` from the repo root).
cd "$(dirname "${BASH_SOURCE[0]}")"

umask 077

# Regeneration is idempotent: previously generated keys are read-only (chmod 400),
# so they must be removed before openssl can rewrite them.
rm -f ca.key keycloak.key ca.crt keycloak.crt ca.srl ca.ext keycloak.ext keycloak.csr

cat <<EOF > ca.ext
[req]
distinguished_name = req_distinguished_name
prompt = no
[req_distinguished_name]
CN = Sentinel Enterprise Root CA
O = Sentinel Security
C = GE
[ca_ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

openssl req -x509 \
  -nodes \
  -days 3650 \
  -newkey rsa:4096 \
  -keyout ca.key \
  -out ca.crt \
  -config ca.ext \
  -extensions ca_ext \
  -sha384

# Generate EC private key portably (no /dev/fd process substitution)
openssl ecparam -name secp384r1 -genkey -noout -out keycloak.key

openssl req -new \
  -key keycloak.key \
  -out keycloak.csr \
  -subj "/CN=keycloak/O=Sentinel Security/C=GE"

cat <<EOF > keycloak.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = keycloak
DNS.2 = localhost
DNS.3 = keycloak.keycloak.svc
DNS.4 = keycloak.keycloak.svc.cluster.local
IP.1 = 127.0.0.1
EOF

openssl x509 -req \
  -in keycloak.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out keycloak.crt \
  -days 365 \
  -extfile keycloak.ext \
  -sha256

chmod 400 ca.key
chmod 444 keycloak.key
chmod 444 ca.crt keycloak.crt

rm -f ca.ext keycloak.csr keycloak.ext ca.srl

echo "=== CA & Keycloak Certificates generated successfully ==="