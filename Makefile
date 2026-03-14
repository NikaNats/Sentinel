.PHONY: build test lint sec-scan up down all

build:
	dotnet restore Sentinel.sln --locked-mode
	dotnet build Sentinel.sln -c Release

test:
	dotnet test Sentinel.sln --logger "console;verbosity=detailed"

lint:
	dotnet format Sentinel.sln --verify-no-changes

sec-scan:
	@echo "Running local container scan (requires Trivy installed)..."
	docker build -t sentinel-api:local -f src/Sentinel.Presentation/Dockerfile .
	trivy image --severity CRITICAL,HIGH --ignore-unfixed sentinel-api:local

up:
	docker-compose up --build -d

down:
	docker-compose down -v

all: build lint test sec-scan
