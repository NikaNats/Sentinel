.PHONY: build test mutation lint sec-scan up down infra-audit fapi-conformance fapi-conformance-local chaos-up chaos-down chaos-inject chaos-load chaos-validate chaos-gate all

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

# ─── OIDF FAPI 2.0 Conformance ─────────────────────────────────────────────
# Remote mode: runs the official OpenID Foundation FAPI 2.0 Conformance Suite
# against the PUBLICLY REACHABLE staging Keycloak and archives the certificate
# + evidence manifest under artifacts/fapi/. Requires the FAPI_SUITE_* /
# KC_ADMIN_* environment variables (see docs/OIDF_FAPI_CONFORMANCE_RUNBOOK.md).
fapi-conformance:
	@echo "==> Running OIDF FAPI 2.0 Conformance Suite (remote mode)..."
	FAPI_MODE=remote \
	bash infra/dast/scripts/run-fapi-conformance.sh

# ─── OIDF FAPI 2.0 Conformance Suite (local self-hosted) ───────────────────
# Stands up the OIDF suite (MongoDB + conformance-server + nginx proxy) via
# infra/fapi-conformance/docker-compose.yml, against Keycloak + Sentinel API
# from the root docker-compose.yml. Suite URL: https://localhost:8443.

FAPI_COMPOSE = infra/fapi-conformance/docker-compose.yml
FAPI_ENV     = infra/fapi-conformance/.env

.PHONY: fapi-certs fapi-up fapi-down fapi-suite-logs fapi-conformance-local

fapi-certs:  ## Generate self-signed certs for the local OIDF suite
	bash infra/fapi-conformance/certs/generate-fapi-certs.sh

fapi-up: fapi-certs  ## Start the local OIDF Conformance Suite
	@test -f $(FAPI_ENV) || { cp $(FAPI_ENV).example $(FAPI_ENV); echo "Created $(FAPI_ENV) — edit FAPI_SUITE_TOKEN, then re-run 'make fapi-up'"; exit 1; }
	docker compose -f $(FAPI_COMPOSE) --env-file $(FAPI_ENV) up -d --build
	@echo "Waiting for suite to become healthy..."
	@for i in $$(seq 1 60); do \
		if curl -ksf https://localhost:8443/api/info > /dev/null 2>&1; then \
			echo "✓ OIDF suite is up at https://localhost:8443"; exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "ERROR: suite did not become healthy (see: make fapi-suite-logs)"; exit 1

fapi-down:  ## Tear down the local OIDF Conformance Suite
	docker compose -f $(FAPI_COMPOSE) down -v --remove-orphans

fapi-suite-logs:  ## Tail local OIDF suite logs
	docker compose -f $(FAPI_COMPOSE) logs -f conformance-server

fapi-conformance-local:  ## Run FAPI 2.0 conformance against the local stack
	@test -f $(FAPI_ENV) || { echo "ERROR: $(FAPI_ENV) missing. Run 'make fapi-up' first."; exit 1; }
	FAPI_MODE=local \
	FAPI_SUITE_URL=https://localhost:8443 \
	FAPI_SUITE_TOKEN=$$(grep '^FAPI_SUITE_TOKEN=' $(FAPI_ENV) | cut -d= -f2-) \
	ISSUER_URL=$$(grep '^KEYCLOAK_ISSUER=' $(FAPI_ENV) | cut -d= -f2-) \
	RESOURCE_URL=$$(grep '^SENTINEL_API_URL=' $(FAPI_ENV) | cut -d= -f2-) \
	KC_ADMIN_URL=$$(grep '^KC_ADMIN_URL=' $(FAPI_ENV) | cut -d= -f2-) \
	KC_ADMIN_USER=$$(grep '^KC_ADMIN_USER=' $(FAPI_ENV) | cut -d= -f2-) \
	KC_ADMIN_PASSWORD=$$(grep '^KC_ADMIN_PASSWORD=' $(FAPI_ENV) | cut -d= -f2-) \
	KC_REALM=$$(grep '^KC_REALM=' $(FAPI_ENV) | cut -d= -f2-) \
	FAPI_PROVISION_HOOK=infra/keycloak/scripts/provision-fapi-conformance-clients.sh \
	bash infra/dast/scripts/run-fapi-conformance.sh

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

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# SRE Load / Soak / Capacity (k6-operator CRDs + real DPoP pool)
# Requires: node, k6, kubectl, jq on PATH. Uses the REAL OTel metric names
# (see sre-alerts.yaml); run make sre-gate after k6-operator is installed.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

SRE_POOL ?= tests/load/dpop-pool.json
SRE_MODE ?= soak
SRE_RPS ?= 3500
SRE_DURATION ?= 90s

sre-mint:
	node tests/scripts/mint-dpop-pool.mjs --output $(SRE_POOL) --count 120

sre-run:
	k6 run --quiet \
		--summary-export tests/load/sre-summary.json \
		-e TARGET_URL=$${SRE_URL:-https://sentinel-api.sentinel-prod.svc.cluster.local} \
		-e TEST_MODE=$(SRE_MODE) -e SOAK_RPS=$(SRE_RPS) \
		-e SOAK_DURATION=$(SRE_DURATION) \
		-e K6_POOL_FILE=$(SRE_POOL) \
		-e K6_NONCE=1 -e K6_INSECURE=1 \
		tests/load/sentinel-sre-suite.js

sre-validate:
	bash tests/scripts/validate-sre-soak.sh tests/load/sre-summary.json

sre-gate: sre-mint sre-run sre-validate
	@echo "SRE gate passed (mode=$(SRE_MODE))"

all: build lint test sec-scan infra-audit
