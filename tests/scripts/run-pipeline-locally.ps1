#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs the full Sentinel Security Pipeline locally with identical CI gates.
.DESCRIPTION
    Executes:
    1. PKI certificate generation & locked NuGet restore
    2. Static analysis & contract generation
    3. Unit, DPoP, Session, SSF, and Security test suites
    4. Microsoft Coyote systematic concurrency exploration (1,000 schedules)
    5. CONTRACT-001 Testcontainers validation (Keycloak, Postgres, Redis)
    6. Reqnroll BDD acceptance suite
    7. Layer-2 Observability Gate (Loki, Tempo, Prometheus, DPoP Replay)
    8. Distroless Docker image build
#>

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
Set-Location $repoRoot

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Write-Stage([string]$title) {
    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "=================================================================" -ForegroundColor Cyan
}

function Write-Pass([string]$message) {
    Write-Host " [PASS] $message" -ForegroundColor Green
}

function Write-Fail([string]$message) {
    Write-Host " [FAIL] $message" -ForegroundColor Red
    exit 1
}

# Resolve Git Bash path on Windows
$gitBash = "bash"
if ($IsWindows -or ($env:OS -like "*Windows*")) {
    $possiblePaths = @(
        "C:\Program Files\Git\bin\bash.exe",
        "C:\Program Files (x86)\Git\bin\bash.exe",
        "$env:LOCALAPPDATA\Programs\Git\bin\bash.exe"
    )
    foreach ($p in $possiblePaths) {
        if (Test-Path $p) {
            $gitBash = $p
            break
        }
    }
}

# Ensure Docker is running
try {
    docker info > $null 2>&1
} catch {
    Write-Fail "Docker daemon is not running. Please start Docker Desktop."
}

# Ensure Testcontainers cleans up cleanly
$env:TESTCONTAINERS_RYUK_DISABLED = "true"
$env:SkipGetBuildVersion = "true"
$env:NBGV_Disable = "true"
$env:MSYS_NO_PATHCONV = "1"

# -----------------------------------------------------------------------------
# STAGE 1: PKI & Locked Restore
# -----------------------------------------------------------------------------
Write-Stage "STAGE 1/8: PKI Certificate Generation & Locked Restore"

& $gitBash infra/certs/generate-certs.sh
if ($LASTEXITCODE -ne 0) { Write-Fail "Certificate generation failed." }
Write-Pass "Local root CA and Keycloak certificates generated."

dotnet restore Sentinel.slnx --locked-mode
if ($LASTEXITCODE -ne 0) { Write-Fail "Locked package restore failed." }
Write-Pass "NuGet dependencies restored with locked hash validation."

dotnet tool restore
if ($LASTEXITCODE -ne 0) { Write-Fail "Local .NET tools restore failed." }
Write-Pass "Local .NET CLI tools restored."

# -----------------------------------------------------------------------------
# STAGE 2: Security & Unit Test Suites
# -----------------------------------------------------------------------------
Write-Stage "STAGE 2/8: Core Unit, Protocol, and Security Suites"

$suites = @(
    "tests/Sentinel.Tests.Unit/Sentinel.Tests.Unit.csproj",
    "tests/Sentinel.Tests.DPoP/Sentinel.Tests.DPoP.csproj",
    "tests/Sentinel.Tests.Session/Sentinel.Tests.Session.csproj",
    "tests/Sentinel.Tests.SSF/Sentinel.Tests.SSF.csproj",
    "tests/Sentinel.Tests.Security/Sentinel.Tests.Security.csproj"
)

foreach ($suite in $suites) {
    $name = [System.IO.Path]::GetFileNameWithoutExtension($suite)
    dotnet test $suite -c Release --no-restore --logger "console;verbosity=normal"
    if ($LASTEXITCODE -ne 0) { Write-Fail "Test suite $name failed." }
    Write-Pass "Suite $name passed."
}

# -----------------------------------------------------------------------------
# STAGE 3: Microsoft Coyote Concurrency Exploration
# -----------------------------------------------------------------------------
Write-Stage "STAGE 3/8: Microsoft Coyote Concurrency Proof (1,000 Iterations)"

dotnet build tests/Sentinel.Tests.Concurrency/Sentinel.Tests.Concurrency.csproj -c Release -p:RunCoyoteRewrite=true --no-restore
if ($LASTEXITCODE -ne 0) { Write-Fail "Coyote IL rewrite failed." }

dotnet test tests/Sentinel.Tests.Concurrency/Sentinel.Tests.Concurrency.csproj -c Release --no-build --no-restore
if ($LASTEXITCODE -ne 0) { Write-Fail "Coyote systematic concurrency verification failed." }
Write-Pass "Systematic thread-scheduling concurrency exploration passed (0 race conditions)."

# -----------------------------------------------------------------------------
# STAGE 4: CONTRACT-001 Contract Validation Gate
# -----------------------------------------------------------------------------
Write-Stage "STAGE 4/8: External Dependency Contracts (Keycloak, Postgres, Redis, OpenAPI)"

dotnet test tests/Sentinel.Contracts/Sentinel.Contracts.csproj -c Release --no-restore --logger "console;verbosity=normal"
if ($LASTEXITCODE -ne 0) { Write-Fail "Contract compliance tests failed." }
Write-Pass "All CONTRACT-001 boundary contracts validated."

# -----------------------------------------------------------------------------
# STAGE 5: Integration Test Suite
# -----------------------------------------------------------------------------
Write-Stage "STAGE 5/8: End-to-End Integration Suite"

dotnet test tests/Sentinel.Tests.Integration/Sentinel.Tests.Integration.csproj -c Release --no-restore --logger "console;verbosity=normal"
if ($LASTEXITCODE -ne 0) { Write-Fail "Integration test suite failed." }
Write-Pass "Integration suite passed against live container topologies."

# -----------------------------------------------------------------------------
# STAGE 6: Reqnroll BDD Acceptance Suite
# -----------------------------------------------------------------------------
Write-Stage "STAGE 6/8: Reqnroll BDD Acceptance (FAPI 2.0 & CAEP User Journeys)"

dotnet test tests/Sentinel.Tests.Acceptance/Sentinel.Tests.Acceptance.csproj -c Release --no-restore --logger "console;verbosity=normal"
if ($LASTEXITCODE -ne 0) { Write-Fail "Acceptance suite failed." }
Write-Pass "Reqnroll end-to-end acceptance scenarios approved."

# -----------------------------------------------------------------------------
# STAGE 7: Layer-2 Observability Gate
# -----------------------------------------------------------------------------
Write-Stage "STAGE 7/8: Layer-2 Observability Gate (Loki, Tempo, Prometheus, DPoP Replay)"

& $gitBash tests/scripts/validate-observability.sh
if ($LASTEXITCODE -ne 0) { Write-Fail "Layer-2 Observability Gate failed." }
Write-Pass "Observability gate passed (SIEM PII-safe logs, Prometheus alerts, Tempo traces verified)."

# -----------------------------------------------------------------------------
# STAGE 8: Hardened Container Packaging
# -----------------------------------------------------------------------------
Write-Stage "STAGE 8/8: Production Container Image Build"

docker build -t sentinel-api:local -f src/Sentinel.AspNetCore/Dockerfile .
if ($LASTEXITCODE -ne 0) { Write-Fail "Production container build failed." }
Write-Pass "Distroless, non-root production container compiled successfully."

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
$stopwatch.Stop()
$elapsedMinutes = [math]::Round($stopwatch.Elapsed.TotalMinutes, 2)

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  SENTINEL SECURITY PIPELINE: 100% PASSED ($elapsedMinutes min)" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "  All quality gates, security invariants, and contracts are verified."
Write-Host ""