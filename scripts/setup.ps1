# DWITP Setup Script (Windows / PowerShell)
# Prerequisites: Docker Desktop, Python 3.12+, Git
# Run from repository root: .\scripts\setup.ps1

$ErrorActionPreference = "Stop"
$Root = Resolve-Path "$PSScriptRoot\.."

Write-Host "=== DWITP Setup ===" -ForegroundColor Cyan

# 1. Check prerequisites
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

$dockerOk = $null
try { $dockerOk = docker --version } catch {}
if (-not $dockerOk) {
    Write-Error "Docker is required. Install Docker Desktop first."
    exit 1
}
Write-Host "  Docker: $dockerOk"

$pythonVersion = $null
try { $pythonVersion = python --version } catch {}
if (-not $pythonVersion -or $pythonVersion -notmatch "3\.12\.") {
    try { $pythonVersion = py -3.12 --version } catch {}
    if (-not $pythonVersion -or $pythonVersion -notmatch "3\.12\.") {
        Write-Error "Python 3.12.x required. Install from https://www.python.org/downloads/release/python-3129/"
        exit 1
    }
    function Invoke-Python { py -3.12 @args }
} else {
    function Invoke-Python { python @args }
}
Write-Host "  Python: $pythonVersion"

# 2. Create Python virtual environment
Write-Host "[2/6] Creating Python virtual environment..." -ForegroundColor Yellow
$venvPath = "$Root\.venv"
if (-not (Test-Path $venvPath)) {
    Invoke-Python -m venv $venvPath
    Write-Host "  Virtual environment created at $venvPath"
} else {
    Write-Host "  Virtual environment already exists"
}

# 3. Activate venv and install dependencies
Write-Host "[3/6] Installing Python dependencies..." -ForegroundColor Yellow
& "$venvPath\Scripts\pip" install --upgrade pip
& "$venvPath\Scripts\pip" install -r "$Root\requirements.in"
& "$venvPath\Scripts\pip" install pip-tools
& "$venvPath\Scripts\pip-compile" --generate-hashes "$Root\requirements.in" -o "$Root\requirements.txt"
& "$venvPath\Scripts\pip" install --require-hashes -r "$Root\requirements.txt"

# 4. Download spaCy model
Write-Host "[4/6] Downloading spaCy model..." -ForegroundColor Yellow
& "$venvPath\Scripts\python" -m spacy download en_core_web_sm

# 5. Build Docker images
Write-Host "[5/6] Building Docker images..." -ForegroundColor Yellow
Set-Location $Root
docker compose -f infra/docker-compose.yml --env-file .env build

# 6. Copy .env.example if .env doesn't exist
Write-Host "[6/6] Setting up environment..." -ForegroundColor Yellow
if (-not (Test-Path "$Root\.env")) {
    Copy-Item "$Root\.env.example" "$Root\.env"
    Write-Host "  Created .env from .env.example - update passwords before deploying!"
} else {
    Write-Host "  .env already exists"
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Edit .env with secure passwords"
Write-Host "  2. Start services: docker compose -f infra/docker-compose.yml --env-file .env up -d"
Write-Host "  3. Access dashboard at http://localhost:8080"
Write-Host "  4. Activate venv: .\.venv\Scripts\Activate.ps1"
