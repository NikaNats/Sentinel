```markdown
# Sentinel Development Patterns

> Auto-generated skill from repository analysis

## Overview

This skill teaches you the core development patterns, coding conventions, and common workflows used in the Sentinel C# codebase. Sentinel is a C# project (no specific framework detected) that emphasizes modular middleware, robust testing, and maintainable documentation. You'll learn how to manage dependencies, refactor middleware, add features with tests, upgrade test infrastructure, enhance documentation, and expand the test suite—all following the project's established conventions.

---

## Coding Conventions

- **File Naming:**  
  Use PascalCase for all file names.  
  _Example:_  
  ```
  DpopValidationMiddleware.cs
  MtlsBindingMiddleware.cs
  ```

- **Import Style:**  
  Use relative imports within the project.  
  _Example:_  
  ```csharp
  using Sentinel.AspNetCore.Middleware;
  ```

- **Export Style:**  
  Use named exports for classes and methods.  
  _Example:_  
  ```csharp
  public class DpopValidationMiddleware
  {
      // ...
  }
  ```

- **Commit Messages:**  
  Use prefixes like `feat`, `fix`, or `refactor` followed by a concise description.  
  _Example:_  
  ```
  feat: Add DPoP validation middleware for enhanced security
  fix: Correct MTLS binding logic in middleware
  refactor: Update dependency injection for middleware components
  ```

---

## Workflows

### Dependency Upgrade Central Management
**Trigger:** When you need to update NuGet or Microsoft package dependencies for bug fixes, security, or compatibility.  
**Command:** `/upgrade-dependencies`

1. Edit `Directory.Packages.props` to bump package versions.
2. Optionally remove extra blank lines or clean up formatting.
3. Commit with a message referencing the updated packages.

_Example:_  
```xml
<!-- Directory.Packages.props -->
<PackageVersion Include="xunit" Version="3.0.0" />
```

---

### Middleware or Core Refactor With Test Update
**Trigger:** When improving, modernizing, or fixing middleware logic and ensuring tests remain valid.  
**Command:** `/refactor-middleware`

1. Refactor middleware/component (e.g., `DpopValidationMiddleware`, `MtlsBindingMiddleware`).
2. Update dependency injection or method signatures as needed.
3. Update related unit tests to match new signatures and behaviors.

_Example:_  
```csharp
// Before
public class DpopValidationMiddleware { ... }

// After
public class DpopValidationMiddleware
{
    public DpopValidationMiddleware(INewDependency dep) { ... }
}
```

---

### Feature Addition or Enhancement With Tests
**Trigger:** When introducing a new capability or extending an existing one, ensuring it is tested.  
**Command:** `/add-feature`

1. Implement or enhance the feature in `src/` or `samples/` (e.g., new endpoints, services, or filters).
2. Update or add related test files in `tests/` (unit, integration, or session).
3. Update project references or dependency injection as needed.

_Example:_  
```csharp
// src/Sentinel.AspNetCore/Endpoints/NewEndpoint.cs
public static class NewEndpoint
{
    public static void MapNewEndpoint(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/new", () => "Hello, world!");
    }
}
```

---

### Test Infrastructure Upgrade or Migration
**Trigger:** When modernizing the test stack, improving isolation, or resolving compatibility issues.  
**Command:** `/upgrade-test-infra`

1. Upgrade test framework packages (e.g., xUnit v2 to v3) in central props.
2. Update test project files (`.csproj`) and test code to match new framework requirements.
3. Refactor or delete obsolete files (e.g., `ProgramMarker.cs`, dummy `Program.cs`).
4. Test and ensure all test projects build and run.

_Example:_  
```xml
<!-- Directory.Packages.props -->
<PackageVersion Include="xunit" Version="3.0.0" />
```

---

### Documentation Major Rewrite or Expansion
**Trigger:** When improving onboarding, compliance, architecture, or operational documentation.  
**Command:** `/rewrite-docs`

1. Edit or rewrite one or more `docs/*.md` files for clarity, structure, or compliance.
2. Add headers, checklists, diagrams, or new sections as needed.
3. Commit with a message summarizing improvements.

---

### Add or Enhance Test Suite
**Trigger:** When introducing new types of automated testing or improving test coverage for reliability/security.  
**Command:** `/add-test-suite`

1. Create new test project directory and `.csproj` (e.g., `Sentinel.FuzzTests`, `Sentinel.Benchmarks`).
2. Add new test files (e.g., fuzzing harness, benchmarks, chaos tests).
3. Update solution and props files to include the new project.
4. Optionally add supporting scripts or corpus files.

_Example:_  
```csharp
// tests/Sentinel.Benchmarks/BasicBenchmarks.cs
[MemoryDiagnoser]
public class BasicBenchmarks
{
    [Benchmark]
    public void TestMethod() { /* ... */ }
}
```

---

## Testing Patterns

- **Framework:** Unknown (likely xUnit or similar, based on file patterns and package references).
- **Test File Pattern:**  
  Test files are named with the `*Tests.cs` suffix and organized by feature or middleware.
  _Example:_  
  ```
  DpopValidationMiddlewareTests.cs
  MtlsBindingMiddlewareTests.cs
  ```

- **Structure:**  
  - Tests are grouped in `tests/Sentinel.Tests.Unit/Unit/` and similar directories.
  - Each test class targets a specific middleware or feature.
  - Tests are updated alongside code changes to ensure coverage and correctness.

---

## Commands

| Command               | Purpose                                                                                   |
|-----------------------|-------------------------------------------------------------------------------------------|
| /upgrade-dependencies | Upgrade NuGet or Microsoft package dependencies using central management                  |
| /refactor-middleware  | Refactor core middleware/component and update corresponding unit tests                    |
| /add-feature          | Add or enhance a feature and implement corresponding unit/integration tests               |
| /upgrade-test-infra   | Upgrade or migrate the test infrastructure and update test projects accordingly           |
| /rewrite-docs         | Majorly rewrite, expand, or restructure documentation                                     |
| /add-test-suite       | Add new test suites (fuzz, chaos, concurrency, benchmarks) or enhance existing ones       |
```
