# Container Build Readiness

Last Updated: 2026-03-29
Status: Not Release-Ready

## 1. Current Reality

The repository contains docker-compose.yml that references:

- build context: .
- dockerfile: src/Sentinel.AspNetCore/Dockerfile

At this time, an active Dockerfile is not present at that location (or elsewhere in repository root tree via standard Dockerfile naming), so container image build cannot be considered production-ready.

## 2. Baseline Inputs

- Runtime target: net10.0
- SDK pin: 10.0.201
- Compose services: postgres, keycloak, redis, sentinel-api

## 3. Readiness Assessment

| Area | Status | Notes |
|---|---|---|
| Build specification exists in compose | Partial | Compose references a Dockerfile path |
| Dockerfile exists at referenced path | Gap | Missing file prevents image build |
| Runtime image hardening | Gap | Cannot validate until Dockerfile exists |
| Multi-stage build flow | Gap | Cannot validate until Dockerfile exists |
| Non-root execution | Gap | Cannot validate until Dockerfile exists |
| Dependency lock/restore posture | Partial | repo uses locked restore in build commands |

## 4. Required Remediation

1. Add Dockerfile at src/Sentinel.AspNetCore/Dockerfile (or update compose to correct path).
2. Use explicit net10 SDK and ASP.NET runtime base images.
3. Implement multi-stage build (restore/build/publish + minimal runtime stage).
4. Run as non-root in final image.
5. Disable diagnostics in production runtime image.
6. Validate image with security scan and startup smoke test.

## 5. Recommended Dockerfile Requirements

Minimum checklist:

1. Build stage:
	- mcr.microsoft.com/dotnet/sdk:10.0
	- dotnet restore --locked-mode
	- dotnet publish -c Release
2. Runtime stage:
	- mcr.microsoft.com/dotnet/aspnet:10.0
	- non-root user
	- only published output copied
3. Security posture:
	- DOTNET_EnableDiagnostics=0
	- no secrets baked into image
	- minimal surface area runtime layer

## 6. Validation Procedure

After Dockerfile remediation:

1. docker build -f src/Sentinel.AspNetCore/Dockerfile -t sentinel-api:local .
2. docker run --rm -p 8080:8080 sentinel-api:local
3. smoke test health endpoint
4. trivy image --severity HIGH,CRITICAL sentinel-api:local
5. docker-compose up --build to validate integrated stack

## 7. Release Gate Criteria

Container readiness can be marked Ready only when all are true:

1. Referenced Dockerfile exists and builds reproducibly.
2. Runtime image launch and health checks pass.
3. Vulnerability scan findings are triaged and accepted.
4. Non-root and minimal runtime controls are verified.
5. Compose stack boots successfully with sentinel-api enabled.

Until then, container release status remains Not Release-Ready.
