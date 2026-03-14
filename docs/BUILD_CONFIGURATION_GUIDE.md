# Build Configuration Guide (Directory.Build.props)

**File:** [Directory.Build.props](../Directory.Build.props)  
**Scope:** All projects in the Sentinel monorepo inherit these settings  
**Last Updated:** 2026-03-15

---

## Overview

`Directory.Build.props` is a centralized MSBuild configuration file that enforces consistent build behavior across all projects (Sentinel.Domain, Sentinel.Application, Sentinel.Infrastructure, Sentinel.Presentation, Sentinel.Tests).

Inheritance: MSBuild automatically imports this file in all .csproj files within the directory tree, eliminating duplication and ensuring consistency.

---

## Key Sections

### 1. Centralized Artifacts Layout

```xml
<UseArtifactsOutput>true</UseArtifactsOutput>
<ArtifactsPath>$(MSBuildThisFileDirectory)artifacts</ArtifactsPath>
```

**What it does:**
- All build output (bin/, obj/) → single `artifacts/` folder at repo root
- Prevents project-level pollution of bin/obj/bin/obj/... nesting
- Simplifies CI/CD cleanup (single `artifacts/` delete)

**CI/CD Impact:**
- Docker builds: fast cleanup with `RUN rm -rf artifacts/`
- Cache key: `artifacts/` folder is single point for caching

**When to override:** Never (standard .NET 8+ modern practice)

---

### 2. SDK & Language Standards

```xml
<TargetFramework>net11.0</TargetFramework>
<LangVersion>latest</LangVersion>
<Nullable>enable</Nullable>
<EnableConfigurationBindingGenerator>true</EnableConfigurationBindingGenerator>
```

**What it does:**
- Targets .NET 11 (Sentinel's platform requirement)
- Uses latest C# (11.0 features: raw strings, list patterns, generic attributes)
- Strict null-safety enabled (catches NullReferenceException at compile-time)
- Configuration binding source generator: compile-time IConfiguration.Bind<T>() codegen

**AOT/Trim Benefit:**
- Source-generated config binding replaces reflection → tree-safe
- No warnings for Bind<T>() in trimmed/AOT projects

**When to override:**
- **Never for TargetFramework:** All must target net11.0
- **Never for Nullable/LangVersion:** Security requirement (null-safety)
- **Only to suppress:** In legacy code blocks with `#nullable disable`

---

### 3. Aggressive Code Analysis (Zero-Warning Policy)

```xml
<AnalysisLevel>latest-all</AnalysisLevel>
<EnforceCodeStyleInBuild>true</EnforceCodeStyleInBuild>
<TreatWarningsAsErrors Condition="'$(Configuration)' == 'Release' Or '$(CI)' == 'true'">true</TreatWarningsAsErrors>
<NoWarn>$(NoWarn);CS1591;CA1014;NETSDK1210;NU1608</NoWarn>
```

**What it does:**
- Enables all latest .NET analyzers (CA*, CS*, SYSLIB*, IDE*)
- Enforces code style consistency (EditorConfig rules)
- **Release/CI builds:** warnings promoted to errors (build failure on issues)
- **Suppressed warnings:** Only intentional noise (missing docs, legacy CLSCompliant, preview framework notices)

**Purpose:**
- Zero-warning policy ensures code quality doesn't degrade
- Catches security issues early (CA1416: platform-specific API, CA1806: unused return value)
- Prevents technical debt accumulation

**Common Violations & Fixes:**

| Warning | Cause | Fix |
|---------|-------|-----|
| CS1591 | Missing XML doc comment | Add `/// <summary>` or suppress with `<NoWarn>` in file |
| CA1305 | Missing IFormatProvider | Use `string.Format(CultureInfo.InvariantCulture, ...)` |
| CA1416 | Platform-specific API | Use `RuntimeInformation.IsOSPlatform()` guards |
| IDE0180 | `use pattern matching` | Convert if-chain to switch expression |
| NU1608 | Package version conflict | Update lock files or suppress if intentional |

**When to override:**
- **Never temporarily:** Run `dotnet build -c Release` locally first
- **Only in .csproj if project-specific:** Add `<TreatWarningsAsErrors>false</TreatWarningsAsErrors>` (not recommended)

---

### 4. Native AOT Compatibility

```xml
<PropertyGroup Condition="'$(IsTestProject)' != 'true' And ('$(OutputType)' == 'Exe' Or '$(PublishAot)' == 'true')">
  <IsAotCompatible>true</IsAotCompatible>
  <EnableTrimAnalyzer>true</EnableTrimAnalyzer>
  <EnableAotAnalyzer>true</EnableAotAnalyzer>
</PropertyGroup>
```

**What it does:**
- **Executables only:** Sentinel.Presentation (API) runs trim/AOT analyzers
- **Libraries (Domain, Application, Infrastructure):** No analyzer overhead; code must still be AOT-compatible
- Detects reflection, dynamic dispatch, serialization issues at build time

**AOT Violations Caught:**
- `typeof(T)` in generic contexts without metadata preservation
- `MethodInfo.Invoke()` or `PropertyInfo.GetValue()` without root descriptors
- `Activator.CreateInstance()` with runtime types
- Unsafe serializers (BinaryFormatter, LosFormatter)

**Sentinel-Specific:**
- DPoP proof JWT signing → static code (no reflection)
- DpopProofValidator → generic validation (no unsafe serialization)
- Keycloak public key caching → static JSON parsing (no dynamic deserialization)

**When to override:**
- **Never for production code:** Violates security & deployment model
- **Only for tests:** Set `Condition="'$(IsTestProject)' != 'true'"` excludes tests

---

### 5. Reproducible Builds & CI/CD

```xml
<Deterministic>true</Deterministic>
<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
<RestoreLockedMode Condition="'$(CI)' == 'true'">true</RestoreLockedMode>
```

**What it does:**
- **Deterministic:** Remove timestamp/GUID variance → reproducible binaries
- **Lock files:** Freeze transitive dependencies (packages.lock.json)
- **RestoreLockedMode in CI:** No upgrades/fallbacks; fail if lock file stale

**CI/CD Workflow:**
1. Local: `dotnet restore` → updates lock files (if needed)
2. Commit: lock files to git
3. CI: `dotnet restore --locked-mode` → exact dependencies or fail
4. Result: Reproducible build; no surprise upgrades breaking CI

**When to override:**
- **Lock file out of date?** Run locally:
  ```bash
  dotnet restore Sentinel.slnx  # Updates *.lock.json
  git add *.lock.json
  git commit -m "Update package locks"
  ```

---

### 6. Security Hardening

```xml
<NuGetAudit>true</NuGetAudit>
<NuGetAuditLevel>moderate</NuGetAuditLevel>
<EnableUnsafeBinaryFormatterSerialization>false</EnableUnsafeBinaryFormatterSerialization>
<ControlFlowGuard>Guard</ControlFlowGuard>
```

**What it does:**
- **NuGetAudit:** Scan all packages (transitive) for known vulnerabilities during restore
- **AuditLevel: moderate:** Block only critical/high severity (ignore low/moderate warnings)
- **Disable BinaryFormatter:** Prevent serialization gadget attacks (XmlSerializer, LosFormatter)
- **ControlFlowGuard (CFG):** OS-level protection against buffer overflows

**Example Audit Block:**
```
error NU1900: Package 'SomeLib 1.0.0' has known vulnerability CVE-2024-5678
Restore failed; update to 1.1.0 or later
```

**Fix:**
```bash
dotnet add package SomeLib --version 1.1.0  # Patched version
dotnet restore --locked-mode
```

**When to override:**
- **Never for production:** Security non-negotiable
- **If false positive:** Document in README with CVE reference + workaround

---

### 7. Code Quality Analyzers

```xml
<ItemGroup>
  <PackageReference Include="DotNet.ReproducibleBuilds" PrivateAssets="all"/>
  <PackageReference Include="Microsoft.CodeAnalysis.NetAnalyzers" PrivateAssets="all"/>
  <PackageReference Include="Microsoft.VisualStudio.Threading.Analyzers" PrivateAssets="all"/>
  <PackageReference Include="SecurityCodeScan.VS2019" PrivateAssets="all"/>
</ItemGroup>
```

**What they do:**
- **DotNet.ReproducibleBuilds:** Validates deterministic output (no timestamp embeddings)
- **NetAnalyzers:** IDisposable patterns, thread-safety, string formatting
- **Threading.Analyzers:** Concurrency issues, deadlock potential
- **SecurityCodeScan:** Cryptography best practices, LINQ injection, unsafe code

**Example Violations:**

| Analyzer | Warning | Fix |
|----------|---------|-----|
| NetAnalyzers | "Field is never assigned" (field assignment in constructor missing) | Initialize field |
| Threading.Analyzers | "Use ConfigureAwait(false)" | Change `await Task` to `await Task.ConfigureAwait(false)` |
| SecurityCodeScan | "Hardcoded password" | Move to IConfiguration; never commit secrets |

**When to override:**
- Add more analyzers in .csproj *only if project-specific*
  ```xml
  <!-- Sentinel.Presentation/.csproj -->
  <ItemGroup>
    <PackageReference Include="Meziantou.Analyzer" PrivateAssets="all"/>
  </ItemGroup>
  ```

---

### 8. Test Project Customization

```xml
<PropertyGroup Condition="'$(IsTestProject)' == 'true'">
  <NoWarn>$(NoWarn);CS1591;IDE0180</NoWarn>
  <SuppressTrimAnalysisWarnings>true</SuppressTrimAnalysisWarnings>
</PropertyGroup>
```

**What it does:**
- Test projects: relax documentation warnings (test code doesn't need XML docs)
- Suppress trim warnings: mocking frameworks (Moq, NSubstitute) use reflection legally
- Still run full code analysis (catch real issues)

**When to override:** None; this is intentional per-project customization

---

## Workflow: How to Work With This

### Local Development (Debug Build)

```bash
# Warnings are shown but don't fail build
dotnet build Sentinel.slnx -c Debug

# Output goes to artifacts/bin/Debug/net11.0/...
```

### Pre-Commit (Simulate CI)

```bash
# Release build: warnings → errors (simulates CI)
dotnet build Sentinel.slnx -c Release
dotnet test Sentinel.slnx -c Release
```

If this fails on your machine, fix before committing:
```bash
dotnet format  # Auto-fix style violations
# Review manual fixes (warnings)
```

### CI Pipeline (Strict Mode)

```bash
# CI environment (GitHub Actions, Azure Pipelines, etc.)
dotnet restore Sentinel.slnx --locked-mode  # Fail if lock stale
dotnet build Sentinel.slnx -c Release       # Warnings → errors
dotnet test Sentinel.slnx
```

---

## Troubleshooting

### "Build succeeded with warnings" (Local) but "Build failed" (CI)

**Cause:** Local build is Debug; CI runs Release → TreatWarningsAsErrors active.

**Fix:**
```bash
dotnet build -c Release  # Test locally with Release config
# Fix warnings
dotnet build -c Release  # Verify fix
```

### "NU1608 detected nuget unresolved version conflict"

**Cause:** Transitive dependency version mismatch (e.g., EF Core 10 and CodeAnalysis versions).

**Status:** Suppressed in `<NoWarn>` (acceptable conflict).

**Action:** No fix needed; this is expected with preview packages.

### "Trim analysis warning: System.Reflection.MethodInfo.Invoke"

**Cause:** Using Activator.CreateInstance() or MethodInfo.Invoke() in production code.

**Fix:** Replace with static factory pattern or source generators.

```csharp
// ❌ Unsafe (reflection)
var obj = Activator.CreateInstance(Type.GetType("Namespace.ClassName"));

// ✅ Safe (static)
var obj = new ClassName();
```

### "SecurityCodeScan: Hardcoded credential detected"

**Cause:** Connection string or API key in code.

**Fix:**
```csharp
// ❌ Never
const string ApiKey = "sk-1234567890";

// ✅ Always
var apiKey = configuration["ApiKeys:ServiceXyz"];
var apiKey = Environment.GetEnvironmentVariable("SERVICE_API_KEY");
```

---

## Best Practices

1. **Never commit with warnings (Release build):** CI will reject
2. **Update lock files regularly:** `dotnet restore`, commit *.lock.json
3. **Use `dotnet format` before push:** Catches style issues automatically
4. **Run full CI simulation locally:** `make all` (builds, tests, analysis, scan)
5. **AOT-safe code:** No reflection, dynamic dispatch, or unsafe serializers
6. **Security-first:** Treat vulnerabilities as build blockers

---

## References

- [Microsoft: Directory.Build.props Documentation](https://learn.microsoft.com/en-us/visualstudio/msbuild/customize-your-build)
- [Microsoft: Code Analyzers](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis)
- [Native AOT Deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot)
- [Reproducible Builds](https://reproducible-builds.org/)

