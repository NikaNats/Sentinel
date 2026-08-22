#!/usr/bin/env bash
set -euo pipefail
export MSYS_NO_PATHCONV=1

kubectl -n sentinel-test apply -f dpop-runner.yaml >/dev/null
kubectl -n sentinel-test wait --for=jsonpath='{.status.phase}'=Running pod/dpop-runner --timeout=120s >/dev/null

echo "== copying scripts into runner =="
kubectl cp dpop-dance.sh sentinel-test/dpop-runner:/tmp/dance.sh
kubectl cp tests/scripts/mint-dpop-pool.mjs sentinel-test/dpop-runner:/tmp/mint-dpop-pool.mjs
kubectl cp tests/scripts/sign-dpop-proof.mjs sentinel-test/dpop-runner:/tmp/sign.mjs

echo "== executing in-cluster DPoP dance (issuer-aligned: https://keycloak:8443) =="
kubectl -n sentinel-test exec dpop-runner -- sh /tmp/dance.sh
