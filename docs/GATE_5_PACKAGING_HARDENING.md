# Gate 5 Packaging And Hardening

**Last Updated:** 2026-03-21
**Document Type:** Historical hardening notes with current-state overlay

## Purpose

This document records the packaging hardening intent established during the Gate 5 workstream and updates it to reflect the current repository shape.

## Hardening Controls Still Relevant

- Two-stage container build
- locked package restore
- non-root runtime user
- disabled diagnostics in runtime container
- Release builds with analyzers and warnings-as-errors

## Current Repository Shape

- Application projects target `net10.0`
- SDK selection is pinned by `global.json`
- Tests are split into unit, integration, and security projects
- Security surface now includes SD-JWT, SSF/CAE, and RAR validation paths

## Current Gap

The container recipe still references `.NET 11` preview images while the application projects target `net10.0`. Until that is aligned, packaging should be described as hardened in structure but not fully baseline-aligned for release.

## Best-Practice Packaging Checklist

1. Keep project TFMs, `global.json`, and Docker images aligned.
2. Run all modular test projects before image publication.
3. Scan the produced image after every base-image update.
4. Keep the final image minimal and rootless.
5. Treat documentation drift as a release blocker for security-sensitive systems.

## Superseded Details

Earlier references to a single `Sentinel.Tests` project and old test counts are no longer current.

## See Also

- [BUILD_CONFIGURATION_GUIDE.md](BUILD_CONFIGURATION_GUIDE.md)
- [CONTAINER_BUILD_READINESS.md](CONTAINER_BUILD_READINESS.md)
