# Container Build Readiness

**Last Updated:** 2026-03-21
**Status:** Partially Ready

## Current State

The application projects target `net10.0`, and the repo pins the SDK via `global.json` to `10.0.201`.

The current container recipe in [Dockerfile](../src/Sentinel.Presentation/Dockerfile) still references:

- `mcr.microsoft.com/dotnet/sdk:11.0-preview`
- `mcr.microsoft.com/dotnet/aspnet:11.0`

That means the container configuration is not yet fully aligned with the build baseline described elsewhere in the repo.

## What Is Ready

- Two-stage Docker build structure exists.
- Runtime stage runs as non-root (`USER 1654`).
- Diagnostics are disabled with `DOTNET_EnableDiagnostics=0`.
- Publish step uses `--no-restore`.
- App host generation is disabled with `UseAppHost=false`.

## What Must Be Fixed Before Release

1. Align the Docker base images with the actual supported runtime.
2. Keep the documented runtime baseline and the container runtime identical.
3. Re-run publish and image validation after the image update.
4. Re-run security scanning on the final aligned image.

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

## Release Note

Treat this document as the operational truth for packaging readiness. Historical gate reports are preserved for audit evidence, but they should not be interpreted as current release approval when they conflict with the active repo state.
