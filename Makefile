.PHONY: build test mutation lint sec-scan up down infra-audit chaos-up chaos-down chaos-inject chaos-load chaos-validate chaos-gate all

build:
	dotnet restore Sentinel.slnx --locked-mode
	dotnet build Sentinel.slnx -c Release

test:
	dotnet test Sentinel.slnx --logger "console;verbosity=detailed"

mutation:
	dotnet tool restore
	dotnet stryker --config-file stryker-config.json

lint:
	dotnet format Sentinel.slnx --verify-no-changes

sec-scan:
	@echo "Running local container scan (requires Trivy installed)..."
	docker build -t sentinel-api:local -f src/Sentinel.AspNetCore/Dockerfile .
	trivy image --severity CRITICAL,HIGH --ignore-unfixed sentinel-api:local

up:
	docker-compose up --build -d

down:
	docker-compose down -v

infra-audit: up
	@echo "Waiting for containers to become healthy..."
	sleep 15
	bash tests/infrastructure-tls-audit.sh

# ─── Distributed Chaos Engineering (KinD + Chaos Mesh + k6) ───────────────────
# A KinD cluster with Chaos Mesh (eBPF) and the Sentinel stack. Run each chaos
# scenario against the deployed stack and validate the fail-closed invariants.
# Requires: kind, kubectl, helm, k6 on PATH.

CHAOS_NS ?= sentinel-prod
CHAOS_SCENARIO ?= redis-kill
# Scenario → manifest mapping:
#   redis-kill   → redis-pod-kill.yaml
#   pg-partition → postgres-network-partition.yaml
#   dns-latency  → dns-latency-keycloak.yaml
CHAOS_MANIFEST ?= $(patsubst %,tests/chaos/redis-pod-kill.yaml,$(CHAOS_SCENARIO))
ifeq ($(CHAOS_SCENARIO),pg-partition)
CHAOS_MANIFEST = tests/chaos/postgres-network-partition.yaml
endif
ifeq ($(CHAOS_SCENARIO),dns-latency)
CHAOS_MANIFEST = tests/chaos/dns-latency-keycloak.yaml
endif
K6_RATE ?= 5000
K6_DURATION ?= 90s

chaos-up:
	@test -n "$$CLUSTER_NAME" || echo "Using cluster sentinel-chaos"
	kind create cluster --name sentinel-chaos || true
	docker build -t sentinel-api:chaos -f src/Sentinel.AspNetCore/Dockerfile .
	kind load docker-image sentinel-api:chaos --name sentinel-chaos
	kubectl apply -f infra/k8s/redis-deployment.yaml
	kubectl apply -f infra/k8s/postgres-deployment.yaml
	kubectl apply -f infra/k8s/keycloak-deployment.yaml
	kubectl -n sentinel-prod wait --for=condition=available deployment/redis --timeout=180s
	kubectl -n sentinel-prod wait --for=condition=available deployment/postgres --timeout=180s
	kubectl -n keycloak wait --for=condition=available deployment/keycloak --timeout=300s
	helm repo add chaos-mesh https://charts.chaos-mesh.org || true
	helm repo update
	helm upgrade --install chaos-mesh chaos-mesh/chaos-mesh \
		--namespace=chaos-mesh --create-namespace \
		--set bpfki.create=true \
		--set dashboard.securityMode=false

chaos-down:
	kind delete cluster --name sentinel-chaos || true

chaos-inject:
	kubectl apply -f $(CHAOS_MANIFEST)

chaos-load:
	k6 run --quiet \
		--summary-export tests/load/chaos-summary-$(CHAOS_SCENARIO).json \
		-e K6_LOAD_URL=https://sentinel-api.sentinel-prod.svc.cluster.local \
		-e K6_RATE=$(K6_RATE) -e K6_DURATION=$(K6_DURATION) \
		-e K6_SCENARIO=$(CHAOS_SCENARIO) \
		-e K6_TOKEN="$${K6_TOKEN:-placeholder}" \
		tests/load/chaos-load-test.js

chaos-validate:
	bash tests/scripts/validate-fail-closed.sh tests/load/chaos-summary-$(CHAOS_SCENARIO).json

chaos-clean:
	-kubectl delete -f $(CHAOS_MANIFEST) --ignore-not-found=true

chaos-gate: chaos-up chaos-inject chaos-load chaos-clean chaos-validate
	@echo "Chaos gate passed for scenario=$(CHAOS_SCENARIO)"

all: build lint test sec-scan infra-audit
