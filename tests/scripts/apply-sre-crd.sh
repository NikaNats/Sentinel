#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# apply-sre-crd.sh - apply an SRE k6 CRD with the runner image injected.
#
# The static CRDs (infra/k8s/sre/) default to the KinD image tag
# (sentinel-k6-dpop:local). Real clusters cannot pull it, so this helper
# substitutes the registry image before apply:
#
#   KinD (defaults):   tests/scripts/apply-sre-crd.sh infra/k8s/sre/crd-spike-20k.yaml
#   EKS/AKS/GKE:       SRE_RUNNER_IMAGE=ghcr.io/<org>/k6-dpop:<tag> \
#                        tests/scripts/apply-sre-crd.sh infra/k8s/sre/crd-spike-20k.yaml
#   mutable tags:      SRE_PULL_POLICY=Always ... (pin digest or use unique tags
#                      to avoid always-latest drift)
#
# Requires: kubectl, sed.
set -euo pipefail

CRD="${1:-}"
IMAGE="${SRE_RUNNER_IMAGE:-sentinel-k6-dpop:local}"
PULL_POLICY="${SRE_PULL_POLICY:-IfNotPresent}"

if [[ -z "$CRD" || ! -f "$CRD" ]]; then
  echo "usage: $0 <crd-file> [SRE_RUNNER_IMAGE=<registry>/k6-dpop:<tag>]" >&2
  exit 2
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

sed -e "s|image: sentinel-k6-dpop:local|image: $IMAGE|" \
    -e "s|imagePullPolicy: IfNotPresent|imagePullPolicy: $PULL_POLICY|" \
    "$CRD" > "$TMP"

echo "==> applying $CRD with image=$IMAGE (pullPolicy=$PULL_POLICY)"
kubectl apply -f "$TMP"