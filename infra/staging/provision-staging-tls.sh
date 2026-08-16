#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# provision-staging-tls.sh - provisions a public-CA TLS certificate for the
# staging Keycloak used by the OIDF FAPI 2.0 Conformance Gate (DOC-0017 Phase 1).
#
# The cloud-hosted Conformance Suite rejects self-signed certificates; the
# keycloak-staging deployment and ingress both mount secret
# "keycloak-staging-tls" (tls.crt / tls.key), so provisioning this secret is a
# hard prerequisite for any hosted certification run.
#
# Issuer selection:
#   --issuer cert-manager   (default) Let's Encrypt via cert-manager
#                            ClusterIssuer "letsencrypt-prod" - requires
#                            cert-manager installed and public DNS records.
#   --issuer acm            AWS Certificate Manager - requires the aws CLI,
#                            valid AWS credentials and a DNS zone in Route 53.
#
# Idempotent: re-running validates the existing certificate instead of
# reissuing. Exit code 0 only when a live, public-CA certificate exists in the
# secret and matches the requested host.
#
# Requirements: kubectl, jq; cert-manager or aws CLI per issuer above.
set -euo pipefail

HOST="${STAGING_HOST:-keycloak.staging.sentinel.io}"
NAMESPACE="${STAGING_NAMESPACE:-staging}"
SECRET="${STAGING_TLS_SECRET:-keycloak-staging-tls}"
ISSUER="cert-manager"
CONTEXT="${KUBE_CONTEXT:-}"

usage() {
    cat <<'EOF'
Usage: provision-staging-tls.sh [--issuer cert-manager|acm] [--host FQDN]

Environment:
  STAGING_HOST / STAGING_NAMESPACE / STAGING_TLS_SECRET  overrides (defaults:
  keycloak.staging.sentinel.io / staging / keycloak-staging-tls)
  KUBE_CONTEXT  kubectl context to target, if not the current one
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --issuer) ISSUER="${2:?--issuer requires a value}"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "$ISSUER" != "cert-manager" && "$ISSUER" != "acm" ]]; then
    echo "error: --issuer must be cert-manager or acm (got: $ISSUER)" >&2
    exit 2
fi

kubectl_cmd=(kubectl)
if [[ -n "$CONTEXT" ]]; then
    kubectl_cmd+=(--context "$CONTEXT")
fi

echo "==> provisioning TLS for ${HOST} (issuer: ${ISSUER}) in ${NAMESPACE}/${SECRET}"

# DNS pre-flight: the issuer must be able to resolve the host.
echo "==> DNS check: ${HOST}"
if ! getent hosts "$HOST" >/dev/null 2>&1 && ! nslookup "$HOST" >/dev/null 2>&1; then
    echo "!! warning: ${HOST} does not resolve. Point an A/CNAME record at the" >&2
    echo "   ingress external IP before the issuer can complete a challenge." >&2
fi

"${kubectl_cmd[@]}" get namespace "$NAMESPACE" >/dev/null 2>&1 ||
    "${kubectl_cmd[@]}" create namespace "$NAMESPACE"

provision_cert_manager() {
    if ! "${kubectl_cmd[@]}" get clusterissuer letsencrypt-prod >/dev/null 2>&1; then
        echo "==> creating ClusterIssuer letsencrypt-prod"
        "${kubectl_cmd[@]}" apply -f - <<'EOF'
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: sre@sentinel.io
    privateKeySecretRef:
      name: letsencrypt-prod-account-key
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
    else
        echo "==> ClusterIssuer letsencrypt-prod already present"
    fi

    if ! "${kubectl_cmd[@]}" get certificate -n "$NAMESPACE" "$SECRET" >/dev/null 2>&1; then
        echo "==> creating Certificate ${NAMESPACE}/${SECRET}"
        "${kubectl_cmd[@]}" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: $SECRET
  namespace: $NAMESPACE
spec:
  secretName: $SECRET
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
    - $HOST
EOF
    else
        echo "==> Certificate ${NAMESPACE}/${SECRET} already present - revalidating"
    fi

    echo "==> waiting for certificate readiness (ACME challenge may take a few minutes)"
    if ! "${kubectl_cmd[@]}" wait --for=condition=Ready -n "$NAMESPACE" "certificate/$SECRET" --timeout=300s; then
        echo "!! certificate not ready. Diagnose:" >&2
        "${kubectl_cmd[@]}" describe -n "$NAMESPACE" "certificate/$SECRET" >&2
        exit 1
    fi
}

provision_acm() {
    command -v aws >/dev/null 2>&1 || { echo "error: aws CLI is required for --issuer acm" >&2; exit 2; }
    if ! aws acm list-certificates --query "CertificateSummaryList[?DomainName=='$HOST']" --output text | grep -q .; then
        echo "==> requesting ACM certificate for $HOST"
        ARN=$(aws acm request-certificate --domain-name "$HOST" \
            --validation-method DNS --query CertificateArn --output text)
        echo "==> certificate requested: $ARN"
        echo "==> add the following DNS validation records in Route 53, then wait:"
        aws acm describe-certificate --certificate-arn "$ARN" \
            --query "Certificate.DomainValidationOptions[].ResourceRecord" --output json | jq -r '.[] | "\(.Name) IN CNAME \(.Value)"'
        echo "==> awaiting issuance (up to 10 minutes)..."
        aws acm wait certificate-validated --certificate-arn "$ARN"
    else
        ARN=$(aws acm list-certificates --query "CertificateSummaryList[?DomainName=='$HOST'].CertificateArn" --output text)
        echo "==> ACM certificate already exists: $ARN"
    fi

    echo "==> exporting certificate into secret ${NAMESPACE}/${SECRET}"
    CERT_ARN=$(aws acm describe-certificate --certificate-arn "$ARN" \
        --query "Certificate.CertificateArn" --output text)
    CERT_PEM=$(aws acm get-certificate --certificate-arn "$CERT_ARN" \
        --query Certificate --output text)
    KEY_PEM=$(aws acm get-certificate --certificate-arn "$CERT_ARN" \
        --query CertificateChain --output text 2>/dev/null || true)

    "${kubectl_cmd[@]}" create secret tls "$SECRET" -n "$NAMESPACE" \
        --cert=<(printf '%s\n' "$CERT_PEM") \
        --key=<(printf '%s\n' "$KEY_PEM") \
        --dry-run=client -o yaml | "${kubectl_cmd[@]}" apply -f -
}

case "$ISSUER" in
    cert-manager) provision_cert_manager ;;
    acm) provision_acm ;;
esac

# Verify the secret actually holds a live certificate for the host.
echo "==> verifying secret ${NAMESPACE}/${SECRET}"
if ! "${kubectl_cmd[@]}" get secret -n "$NAMESPACE" "$SECRET" -o jsonpath='{.data.tls\.crt}' \
    | base64 -d | openssl x509 -noout -subject -issuer -dates -checkhost "$HOST" >/dev/null 2>&1; then
    echo "!! secret ${NAMESPACE}/${SECRET} does not contain a valid certificate for ${HOST}" >&2
    exit 1
fi

"${kubectl_cmd[@]}" get secret -n "$NAMESPACE" "$SECRET" -o jsonpath='{.data.tls\.crt}' \
    | base64 -d | openssl x509 -noout -subject -issuer -dates -checkhost "$HOST"

echo "==> done. Keycloak and the ingress will pick up the certificate automatically."
echo "==> verify externally: openssl s_client -connect ${HOST}:443 -servername ${HOST} -tls1_3"
