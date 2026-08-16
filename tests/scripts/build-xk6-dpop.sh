#!/usr/bin/env bash
# Copyright (c) 2026 Sentinel contributors. Licensed under the MIT License.
#
# build-xk6-dpop.sh - builds the distributed k6 runner image with the
# Go-native DPoP signer (tests/load/xk6-dpop) via tests/load/Dockerfile.xk6.
#
# Usage:
#   tests/scripts/build-xk6-dpop.sh                    # local image tag
#   IMAGE=ghcr.io/your-org/k6-dpop:v1 bash tests/scripts/build-xk6-dpop.sh
#
# Requires: docker. See docs/SRE_LOAD_TESTING_RUNBOOK.md §6.
set -euo pipefail

IMAGE="${IMAGE:-sentinel-k6-dpop:local}"

docker build -f tests/load/Dockerfile.xk6 -t "$IMAGE" .

echo "==> k6-DPoP runner image ready: $IMAGE"
echo "    KinD:    kind load docker-image $IMAGE --name <cluster>"
echo "    EKS/AKS: docker push $IMAGE (then set CRD runner.image + imagePullPolicy: Always)"