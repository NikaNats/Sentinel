# Build Configuration & Tooling Guide

> **Document ID**: CFG-0001
> **Status**: APPROVED
> **Scope**: Repository build, compilation-safety, and secure release gates
> **Target Baseline**: .NET 10.0 (SDK 10.0.300+)

## 1. Build Baseline & compiler Enforcements

The Sentinel repository enforces a strict, zero-warning cryptographic build baseline. All projects transitively inherit these compiler policies through central configuration files.

### Global Invariants:
- **SDK Pinned:** .NET SDK `10.0.300+` (enforced via `global.json`).
- **Target Framework Monoculture (TFM):** `net10.0` (with multi-targeting ready).
- **Null Safety:** `Nullable: enabled` strictly checked (warnings treated as errors).
- **Modern C# Compiler:** `ImplicitUsings: enabled` with C# 13/14 language features active.
- **Strict Quality Gate:** `TreatWarningsAsErrors: true` across all configurations.
- **Static Analysis:** `AnalysisLevel: latest-all` (Roslyn analyzers active on every build).
- **Documentation:** `GenerateDocumentationFile: true` (all public/internal APIs must be fully documented).

These settings are centralized in three primary files in the repository root:
1. `global.json` (SDK lock)
2. `Directory.Build.props` (Compiler flags and signing rules)
3. `Directory.Packages.props` (Central Package Management)

## 2. Central Build Files

### 2.1 `global.json`
Ensures that all local developer environments and CI/CD runners build the solution using the exact same .NET SDK version, preventing runtime behavior drift:
```json
{
  "sdk": {
    "version": "10.0.300",
    "rollForward": "latestFeature"
  }
}
```

### 2.2 `Directory.Build.props`
Centralizes common compiler settings, static analysis levels, and our **SOTA Hybrid Strong-Name Signing** configuration.

### 2.3 `Directory.Packages.props` (Central Package Management)
Enforces Central Package Management (CPM). Individual project files (`.csproj`) are **prohibited** from defining explicit `Version` attributes on `<PackageReference>` elements. All versions must be centrally registered inside `Directory.Packages.props` to prevent transitive dependency drift and vulnerabilities.

## 3. Standard Build & Test Commands

### 3.1 Fast Local Compilation
To restore and build the entire solution with strict compiler checks:
```powershell
dotnet restore Sentinel.slnx --locked-mode
dotnet build Sentinel.slnx -c Release
```

### 3.2 Automated Test Execution
To run the standard unit, security, and integration test suites:
```powershell
dotnet test Sentinel.slnx -c Release --logger "console;verbosity=normal"
```

### 3.3 Systematic Concurrency Testing (Microsoft Coyote)
To run the programmatic xUnit concurrency test suite under Coyote's systematic scheduling engine:
```powershell
# 1. Compile the concurrency suite (triggers the post-build binary rewriter)
cd tests/Sentinel.Tests.Concurrency
dotnet build -c Release

# 2. Run the programmatic xUnit tests
dotnet test -c Release
```

### 3.4 Real-world Network Chaos Engineering (Toxiproxy)
To execute the container-based network chaos test suite:
```powershell
dotnet test tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj --filter "FullyQualifiedName~Chaos" -c Release
```

### 3.5 Micro-benchmarks (BenchmarkDotNet)
To run high-precision, zero-allocation micro-benchmarks on cryptographic hot paths:
```powershell
dotnet run -c Release --project tests/Sentinel.Benchmarks
```

### 3.6 Generative Fuzz Testing (SharpFuzz)
To execute coverage-guided generative fuzzing against DPoP and SD-JWT parsers:
```powershell
cd tests/Sentinel.FuzzTests
powershell -ExecutionPolicy Bypass -File .\run-fuzzing.ps1
```

### 3.7 Acceptance & E2E Testing (Reqnroll)
To execute the high-assurance end-to-end acceptance suite validating FAPI 2.0 and CAEP SSF:
```powershell
# The test runner automatically manages the entire local Docker (Redis + Keycloak) 
# and Minimal API host lifecycle under AcceptanceTestHooks.
dotnet test tests/Sentinel.Tests.Acceptance/Sentinel.Tests.Acceptance.csproj -c Release
```

## 4. Strong-Name Signing (Hybrid Model)

To protect corporate binary identity and prevent intermediate DLL tampering, Sentinel enforces strong-name signing. To avoid "cold-clone" failures and external contributor build blocks, we implement a **SOTA Hybrid Signing Model**:

1.  **Local Developer / Contributor Builds (Unsigned fallback):**
    - If the private key `Sentinel.snk` is absent (default clone state), MSBuild automatically falls back to `Sentinel.public.snk` and enables `<PublicSign>true</PublicSign>`.
    - If neither key is present, assembly signing is gracefully disabled locally to allow instant compilation, avoiding any compiler errors.
2.  **Staging / Release Packaging (Secure signing):**
    - Release builds in CI/CD inject the base64-encoded private key via GitHub Secrets (`SENTINEL_SNK_BASE64`) and compile with `-p:SignSentinelRelease=true`.
    - This fully signs the released NuGet packages (`.nupkg` and `.snupkg`) while keeping the private key out of source control.

To compile and pack with full strong-name signing enabled:
```powershell
dotnet pack Sentinel.slnx -c Release -p:SignSentinelRelease=true -o ./artifacts
```

## 5. Native AOT & Trimming Considerations

The reference Minimal API host (`Sentinel.Sample.MinimalApi`) is configured with `<PublishAot>true</PublishAot>` to prove Native AOT compatibility.

### Architectural Rules for Trimming:
1.  **No Reflection-based Serialization:** All HTTP request/response DTOs, collection types, and framework error models (e.g. `ProblemDetails`) **must** be registered inside a dedicated `JsonSerializerContext` (e.g., `AspNetCoreJsonContext` and `SampleJsonContext`).
2.  **Registering JSON Contexts:** Ensure all contexts are registered in the DI serializer options at startup:
    ```csharp
    builder.Services.Configure<Microsoft.AspNetCore.Http.Json.JsonOptions>(options =>
    {
        options.SerializerOptions.TypeInfoResolverChain.Insert(0, SampleJsonContext.Default);
    });
    ```
3.  **No Anonymous Types:** Returning anonymous objects (`new { token = "..." }`) inside route handlers is **strictly prohibited**. It requires runtime reflection and crashes under AOT with `NotSupportedException`. Always use named C# records registered in your JSON context.

## 6. Hardened Container Packaging

The repository contains a production-ready, highly secure multi-stage Docker build located at `src/Sentinel.AspNetCore/Dockerfile`.

### Hardening Controls Deployed:
- **Distroless Runtime:** Uses `mcr.microsoft.com/dotnet/aspnet:10.0` as the minimal execution layer (no shell, no package manager, minimizing attack surface).
- **Non-Root Execution:** Runs under a dedicated unprivileged user (`USER sentinel` / UID 1654) to mitigate container escape exploits.
- **Disabled Diagnostics:** `DOTNET_EnableDiagnostics=0` is set to block runtime profiling, heap dumps, and memory scanning vectors.
- **TLS 1.3 & mTLS Ready:** Hardened to negotiate TLS 1.3 exclusively for service-to-service secure mesh topologies.

## 7. Troubleshooting

### Obsolete `ContainerBuilder` Warnings
If you receive obsolete warnings regarding `new ContainerBuilder()` during Testcontainers execution, ensure you pass the image string directly to the constructor to support modern Testcontainers v4 API standards:
```csharp
var container = new ContainerBuilder("ghcr.io/shopify/toxiproxy:2.11.0")
```

### Typeload / `System.Runtime` Mismatch in Coyote CLI
If the external Coyote CLI (`coyote test ...`) fails to load `System.Runtime, Version=10.0.0.0` at runtime, use the **Programmatic xUnit Integration** via `TestingEngine` instead. This executes Coyote directly inside the native .NET 10 test host, completely resolving TFM version conflicts.

### `CA1859` / `CS0053` Inconsistent Accessibility Loops
If a code analyzer demands a concrete type (`CA1859`), but the concrete type implements an interface explicitly (causing `CS0053` on public properties), suppress the performance analyzer rule locally inside your dedicated test or fuzzing projects:
```csharp
#pragma warning disable CA1859
IDpopProofValidator validator = new DpopProofValidator(replayCache, options);
#pragma warning restore CA1859
