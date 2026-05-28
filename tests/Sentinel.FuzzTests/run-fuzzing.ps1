# 1. Compile in Release mode
dotnet build -c Release

# 2. Resolve binary paths
$binPath = Resolve-Path "bin/Release/net10.0"
$corpusDir = New-Item -ItemType Directory -Path "./corpus" -Force

# 3. Create seed corpus if not present
if (-not (Test-Path (Join-Path $corpusDir "seed.txt"))) {
    Set-Content -Path (Join-Path $corpusDir "seed.txt") -Value "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7fX0.eyIncXRpIjoiMSJ9.signature"
}

Write-Host "Starting Pure .NET Generative Fuzzing..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop fuzzing when satisfied." -ForegroundColor Cyan

# 4. RUN: გაუშვით ფაზერი პირდაპირ პროექტიდან
dotnet run -c Release -- dpop ./corpus
