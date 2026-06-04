#!/usr/bin/env bash
set -euo pipefail

# 1. Create a Private Root Certificate Authority (CA)
openssl req -x509 \
  -nodes \
  -days 3650 \
  -newkey rsa:4096 \
  -keyout ca.key \
  -out ca.crt \
  -subj "/CN=Sentinel Enterprise Root CA/O=Sentinel Security/C=GE"

# 2. Create the Certificate Signing Request (CSR) for Keycloak
openssl req -nodes \
  -newkey rsa:2048 \
  -keyout keycloak.key \
  -out keycloak.csr \
  -subj "/CN=keycloak/O=Sentinel Security/C=GE"

# 3. Create the SAN (Subject Alternative Name) extension config
cat <<EOF > keycloak.ext
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = keycloak
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# 4. Sign Keycloak's leaf certificate using our Private Root CA
openssl x509 -req \
  -in keycloak.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out keycloak.crt \
  -days 365 \
  -extfile keycloak.ext

# 5. Harden permissions: restrict private keys but allow read access for Keycloak container
# Keycloak container runs as non-root UID 1000, so we grant read access to the group/others safely
chmod 644 ca.crt keycloak.crt
chmod 640 ca.key keycloak.key

# Grant Keycloak container (UID 1000) permission to read the private key/cert.
if command -v chown >/dev/null 2>&1; then
  if [ "$(id -u)" -eq 0 ]; then
    chown 1000:0 keycloak.key keycloak.crt
  elif command -v sudo >/dev/null 2>&1; then
    sudo chown 1000:0 keycloak.key keycloak.crt
  else
    echo "WARNING: Unable to chown keycloak.key/keycloak.crt to UID 1000 (sudo not available)."
  fi
fi
