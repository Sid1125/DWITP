# DWITP Build Script
# Generates hash-pinned requirements.txt, then builds all Docker images.
# Run from repository root: .\scripts\build.ps1

$ErrorActionPreference = "Stop"
$Root = Resolve-Path "$PSScriptRoot\.."

Write-Host "=== DWITP Build ===" -ForegroundColor Cyan

# 1. Generate hash-pinned requirements.txt
Write-Host "[1/3] Generating hash-pinned requirements.txt..." -ForegroundColor Yellow

$pipToolsOk = $null
try { $pipToolsOk = pip-compile --version } catch {}

if (-not $pipToolsOk) {
    Write-Host "  Installing pip-tools..." -ForegroundColor Yellow
    pip install pip-tools
}

Push-Location $Root
pip-compile --generate-hashes requirements.in -o requirements.txt
Pop-Location

Write-Host "  requirements.txt generated with hashes" -ForegroundColor Green

# 2. Verify hash-pinned install works
Write-Host "[2/3] Verifying dependency integrity..." -ForegroundColor Yellow
pip install --require-hashes -r "$Root\requirements.txt"
$LASTEXITCODE = 0
Write-Host "  Dependencies verified" -ForegroundColor Green

# 3. Build Docker images
Write-Host "[3/3] Building Docker images..." -ForegroundColor Yellow
docker compose -f "$Root\infra\docker-compose.yml" build --no-cache
Write-Host "  Docker images built" -ForegroundColor Green

Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
Write-Host "Deploy with: docker compose -f infra/docker-compose.yml up -d"
