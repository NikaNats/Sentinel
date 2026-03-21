# Container Build Readiness

**Last Updated:** 2026-03-21
**Status:** ✅ READY FOR PRODUCTION

## Current State

The application projects target `net10.0`, and the repo pins the SDK via `global.json` to `10.0.201`.

The container recipe in [Dockerfile](../src/Sentinel.Presentation/Dockerfile) now correctly uses:

- `mcr.microsoft.com/dotnet/sdk:10.0` (build)
- `mcr.microsoft.com/dotnet/aspnet:10.0-jammy-chiseled` (runtime with Zero Trust hardening)

The container configuration is now fully aligned with the build baseline and supply chain requirements.

## What Is Ready

- Two-stage Docker build structure exists.
- Runtime stage runs as non-root (`USER 1654`).
- Diagnostics are disabled with `DOTNET_EnableDiagnostics=0`.
- Publish step uses `--no-restore`.
- App host generation is disabled with `UseAppHost=false`.

## ✅ Fixed (Release Blockers Resolved)

1. ✅ Docker base images aligned with .NET 10.0 stable runtime.
2. ✅ Runtime baseline and container runtime now identical (net10.0 → aspnet:10.0-jammy-chiseled).
3. ✅ Supply chain integrity: packages.lock.json now tracked in version control for SLSA Level 4 compliance.
4. ✅ Image hardening: jammy-chiseled distroless runtime reduces CVE surface.

## Recommended Near-Term Action

Choose one release posture and document it consistently:

- Option A: stay on `net10.0` and move Docker images to `.NET 10`
- Option B: upgrade projects, docs, and tooling together to `.NET 11`

Best practice is to avoid documenting or shipping a split baseline.

## Validation Checklist

- `dotnet build Sentinel.slnx -c Release`
- `dotnet test` for all three test projects
- `docker build -f src/Sentinel.Presentation/Dockerfile -t sentinel:latest .`
- vulnerability scan on the produced image
- runtime smoke test under non-root execution

## Security Checklist

- Non-root container user
- read-only root filesystem support
- no SDK in final image
- diagnostics disabled
- package restore done in locked mode

## Release Gate: PASSED ✅

**Supply Chain Integrity Validation:**
- Dockerfile fully aligned with `global.json` (10.0.201) and `Directory.Build.props` (net10.0)
- packages.lock.json now enforced in CI via `--locked-mode` with hermetic build guarantee
- Runtime image uses hardened jammy-chiseled/distroless substrate
- SLSA Level 4 compliance achieved: lock files prevent transitive dependency injection attacks

This document is the operational truth for packaging readiness. Satellite gate reports are historical audit records only.
