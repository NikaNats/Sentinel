# Build Configuration Guide

**Last Updated:** 2026-03-21

## Overview

This repository builds as a `net10.0` solution and uses a split test layout:

- `src/Sentinel.Domain`
- `src/Sentinel.Application`
- `src/Sentinel.Infrastructure`
- `src/Sentinel.Presentation`
- `tests/Sentinel.Tests.Unit`
- `tests/Sentinel.Tests.Integration`
- `tests/Sentinel.Tests.Security`

## Source Of Truth

Build behavior is controlled from three places:

1. `global.json`
   - Pins the local SDK selection to `10.0.201`.
2. Project files (`*.csproj`)
   - Each application and test project explicitly targets `net10.0`.
3. `Directory.Build.props`
   - Centralizes nullable context, implicit usings, analyzer mode, warnings-as-errors, and shared `NoWarn` entries.

Best practice in this repo is to treat the individual project files as the authoritative target framework definition. If `Directory.Build.props` and a project file ever disagree, the project file value is the one release documentation should describe.

## Current Build Baseline

- SDK selection: `.NET SDK 10.0.201`
- Target framework: `net10.0`
- Nullable: enabled
- Implicit usings: enabled
- Analyzer mode: `All`
- Warnings as errors: enabled
- XML docs: generated

## Analyzer Policy

The repo is intentionally strict:

- `TreatWarningsAsErrors=true`
- Centralized `NoWarn` exists only for explicitly accepted exceptions
- Tests inherit the same baseline but still use `IsTestProject=true` in each test project

Best practice:

- Prefer fixing analyzer findings over suppressing them.
- If a suppression is required, document the reason at the narrowest possible scope.
- Do not rely on global suppression lists to hide correctness or disposal problems.

## Test Project Layout

The old monolithic test layout has been split by execution intent:

- `Sentinel.Tests.Unit`
  - Fast logic tests with no containers
- `Sentinel.Tests.Integration`
  - Real flow tests with infrastructure dependencies
- `Sentinel.Tests.Security`
  - Abuse-path and downgrade tests

This separation is the expected CI shape and should be preserved.

## Recommended Commands

```powershell
dotnet restore Sentinel.slnx
dotnet build Sentinel.slnx -c Release
dotnet test tests/Sentinel.Tests.Unit/Sentinel.Tests.Unit.csproj -c Release
dotnet test tests/Sentinel.Tests.Integration/Sentinel.Tests.Integration.csproj -c Release
dotnet test tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj -c Release
```

## Release Hygiene

Before shipping:

1. Build in `Release`.
2. Run all three test projects separately.
3. Keep `packages.lock.json` current.
4. Keep `global.json`, project TFMs, and container runtime images aligned.

## Known Documentation Note

The repo currently contains a mixed historical state where some packaging assets still reference `.NET 11` preview container images while the application projects target `net10.0`. That mismatch is documented in [CONTAINER_BUILD_READINESS.md](CONTAINER_BUILD_READINESS.md) and should be treated as an operational follow-up, not as the active application build baseline.
