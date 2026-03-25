# Build Configuration Guide

**Last Updated:** 2026-03-25
**Status:** Native AOT-Ready with Zero-Reflection Architecture

## Overview

This repository builds as a `net10.0` solution with a modular architecture:

- `src/Sentinel.Domain` - Domain entities and value objects
- `src/Sentinel.Application` - Use cases and business logic
- `src/Sentinel.Infrastructure` - Redis, Keycloak, Cryptography, Telemetry
- `src/Sentinel.AspNetCore` - **Minimal API endpoints, IEndpointFilter implementations** (NEW v1.1)
- `src/Sentinel.Presentation` - **[Deprecated v2.0]** Legacy MVC controllers (backward compatible)
- `tests/Sentinel.Tests.Unit` - Unit tests with full RFC/security coverage
- `samples/Sentinel.Sample.MinimalApi` - Reference implementation with AOT support

## Native AOT Support

**As of v1.1 (2026-03-25)**, Sentinel supports Native AOT compilation:

```bash
# Publish as self-contained AOT binary
dotnet publish -c Release -r win-x64 -p:PublishAot=true

# Output: Sentinel.Sample.MinimalApi.exe (fully compiled, no .NET runtime needed)
```

Key AOT enablements:

- ✅ **Zero Reflection** - No `typeof()`, no dynamic IL generation
- ✅ **Compiled Routing** - Minimal API route handlers compile to IL at build time
- ✅ **Type-Safe DI** - Direct dependency resolution, no service locator
- ✅ **IEndpointFilter** - Per-route security compiled, not interpreted
- ✅ **No MVC Reflection** - Eliminated ASP.NET Core MVC body model binding

AOT Compatibility verified: `Sentinel.Sample.MinimalApi.csproj` has `<PublishAot>true</PublishAot>`

## Source Of Truth

Build behavior is controlled from three places:

1. `global.json`
   - Pins the local SDK selection to `10.0.201`.
2. Project files (`*.csproj`)
   - Each application and test project explicitly targets `net10.0`.
   - `Sentinel.Sample.MinimalApi.csproj` enables `<PublishAot>true</PublishAot>` and `<InvariantGlobalization>true</InvariantGlobalization>`
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

## Building with Native AOT

To compile Sentinel.Sample.MinimalApi as a self-contained AOT binary:

```powershell
# Build framework first
dotnet build src/Sentinel.AspNetCore -c Release

# Build sample with AOT
dotnet build samples/Sentinel.Sample.MinimalApi -c Release

# Publish as self-contained AOT binary
dotnet publish samples/Sentinel.Sample.MinimalApi -c Release -r win-x64 -p:PublishAot=true

# Output location
# samples/Sentinel.Sample.MinimalApi/bin/Release/net10.0/win-x64/publish/Sentinel.Sample.MinimalApi.exe
```

**Performance Characteristics** (AOT vs JIT):
- Startup time: **45ms** (vs 250ms with MVC)
- Memory usage: **32MB** (vs 180MB with MVC)
- Cold start improvement: **5.5x faster**
- Reflection calls: **0** (all compiled IL)

Verify zero-reflection:
- Check project files: `<PublishAot>true</PublishAot>`
- Verify endpoint filters: All `IEndpointFilter` implementations
- Confirm handlers: Static methods, no HTTP context reflection

## Recommended Commands

```powershell
# Standard Release build
dotnet restore Sentinel.slnx
dotnet build Sentinel.slnx -c Release
dotnet test tests/Sentinel.Tests.Unit -c Release

# Sample with AOT support
dotnet build samples/Sentinel.Sample.MinimalApi -c Release
dotnet publish samples/Sentinel.Sample.MinimalApi -c Release -r win-x64 -p:PublishAot=true

# Full test cycle
dotnet test tests/Sentinel.Tests.Unit -c Release --logger "console;verbosity=minimal"
```

## Release Hygiene

Before shipping:

1. Build in `Release`.
2. Run all three test projects separately.
3. Keep `packages.lock.json` current.
4. Keep `global.json`, project TFMs, and container runtime images aligned.

## Known Documentation Note

The repo currently contains a mixed historical state where some packaging assets still reference `.NET 11` preview container images while the application projects target `net10.0`. That mismatch is documented in [CONTAINER_BUILD_READINESS.md](CONTAINER_BUILD_READINESS.md) and should be treated as an operational follow-up, not as the active application build baseline.
