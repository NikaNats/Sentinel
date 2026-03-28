# Build Configuration Guide

Last Updated: 2026-03-29
Scope: Repository build, test, and release configuration

## 1. Build Baseline

Current baseline settings:

- SDK pin: 10.0.201 (global.json)
- Target framework: net10.0
- Nullable: enabled
- Implicit usings: enabled
- Treat warnings as errors: enabled
- Analyzer mode: All
- Documentation generation: enabled

These values are enforced through:

1. global.json
2. Directory.Build.props
3. per-project csproj files

If values diverge, treat csproj + global.json as runtime truth and update docs in the same change.

## 2. Central Build Files

### global.json

- Controls SDK selection for local and CI builds.

### Directory.Build.props

- Centralizes common compiler and analyzer policies.
- Enables strict quality posture by default.

### Directory.Packages.props

- Central package version management.
- Reduces drift across module package versions.

## 3. Standard Commands

### 3.1 Fast Local Validation

```powershell
dotnet restore Sentinel.slnx --locked-mode
dotnet build Sentinel.slnx -v minimal
```

### 3.2 Full Test Validation

```powershell
dotnet test tests/Sentinel.Tests.Unit -v minimal
dotnet test tests/Sentinel.Tests.Security -v minimal
dotnet test tests/Sentinel.Tests.Integration -v minimal
```

### 3.3 Convenience Targets

The root Makefile includes:

- make build
- make test
- make lint
- make sec-scan

## 4. Analyzer Policy

Repository policy is intentionally strict:

- warnings are errors by default
- suppressions must be explicit and justified
- test projects may add scoped suppressions where design analyzers conflict with test naming or fixture patterns

Best practices:

1. Fix the root cause before suppressing.
2. Prefer file-level or project-level narrowly scoped suppression.
3. Keep suppression rationale in code comments or PR description.

## 5. Native AOT and Trimming Considerations

The sample host is configured with PublishAot=true to validate AOT compatibility patterns.

Guidance:

1. Avoid reflection-based route handler construction.
2. Prefer named DTOs instead of anonymous object payloads in Minimal API handlers.
3. Avoid dynamic JSON serialization paths that trigger RequiresDynamicCode/RequiresUnreferencedCode warnings.
4. Use explicit types and deterministic route signatures for RequestDelegate source generation.

## 6. CI/CD Expectations

Minimum release gate:

1. locked restore succeeds
2. full solution build succeeds
3. unit + security + integration tests succeed
4. no undocumented analyzer suppressions introduced
5. docs and OpenAPI updated for external contract changes

## 7. Dependency and Reproducibility Practices

1. Commit lock files when changed by dependency updates.
2. Use central package management in Directory.Packages.props.
3. Avoid ad hoc package versions in individual projects unless strictly required.

## 8. Known Build/Packaging Gaps

Container packaging is not currently production-ready in this repository because an active app Dockerfile is not present, while docker-compose references one.

See CONTAINER_BUILD_READINESS.md for remediation steps.

## 9. Troubleshooting

### Restore or SDK mismatch

- Confirm dotnet --info includes SDK 10.0.201
- Re-run restore with --locked-mode to surface drift explicitly

### Analyzer failures in tests

- Check project-level NoWarn in the specific test csproj
- Ensure suppression is deliberate and scoped

### AOT/source generation failures

- Replace anonymous response types with named records
- Remove reflection-based construction in route handlers/tests where possible
- Keep route signatures simple and explicit
