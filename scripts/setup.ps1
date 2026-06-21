# DWITP Setup — Windows / PowerShell
# Prerequisites: Docker Desktop (with the WSL2 backend running), Git.
#                Python 3.12+ only needed for the optional local test env.
# Run from the repository root:  .\scripts\setup.ps1
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..").Path
$EnvFile = Join-Path $Root "infra\.env"

Write-Host "=== DWITP Setup ===" -ForegroundColor Cyan

# ── Step 1: Prerequisites ──────────────────────────────────────────
Write-Host "[1/3] Checking prerequisites..." -ForegroundColor Yellow
try { $null = docker --version } catch { Write-Error "Docker is required. Install Docker Desktop and start it."; exit 1 }
try { $null = docker compose version } catch { Write-Error "The Docker Compose plugin is required ('docker compose')."; exit 1 }
try { $null = docker info } catch { Write-Error "The Docker daemon is not running. Start Docker Desktop and retry."; exit 1 }
Write-Host "  Docker:  $(docker --version)"

# ── Step 2: Environment (infra/.env) ───────────────────────────────
Write-Host "[2/3] Generating infra/.env..." -ForegroundColor Yellow
function New-Hex([int]$n = 24) {
    $b = New-Object byte[] $n
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    ($b | ForEach-Object { $_.ToString('x2') }) -join ''
}
function New-FernetKey {
    $b = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    [Convert]::ToBase64String($b).Replace('+', '-').Replace('/', '_')   # url-safe = valid Fernet key
}
if (Test-Path $EnvFile) {
    Write-Host "  infra/.env already exists - keeping it (delete it to regenerate)."
} else {
    $dashPw = New-Hex 24
    $lines = @(
        "# DWITP environment - generated $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
        "POSTGRES_PASSWORD=$(New-Hex 24)"
        "OPENSEARCH_PASSWORD=Dw1tp-$(New-Hex 12)"
        "NEO4J_PASSWORD=$(New-Hex 24)"
        "RABBITMQ_PASSWORD=$(New-Hex 24)"
        "TOR_CONTROL_PASSWORD=$(New-Hex 24)"
        "DASHBOARD_USERNAME=analyst"
        "DASHBOARD_PASSWORD=$dashPw"
        "DASHBOARD_SECRET_KEY=$(New-Hex 32)"
        "AUDIT_ENCRYPTION_KEY=$(New-FernetKey)"
        "PI_CAMPAIGN_THRESHOLD=5"
        "GRAPH_ANALYTICS_INTERVAL=300"
    )
    # WriteAllLines => UTF-8 WITHOUT BOM. Docker's .env parser chokes on a BOM, so
    # do NOT use Set-Content/Out-File here (they emit a BOM on Windows PowerShell).
    [System.IO.File]::WriteAllLines($EnvFile, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "  Wrote infra/.env with fresh random secrets." -ForegroundColor Green
    Write-Host "  Dashboard login: analyst / $dashPw" -ForegroundColor Green
}

# ── Step 3: Build images ───────────────────────────────────────────
Write-Host "[3/3] Building Docker images (first build downloads base images)..." -ForegroundColor Yellow
# --env-file is explicit so the build resolves vars regardless of the caller's CWD.
docker compose --env-file "$EnvFile" -f "$Root\infra\docker-compose.yml" build
Write-Host "  Images built." -ForegroundColor Green

Write-Host ""
Write-Host "=== Setup complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Start the stack:"
Write-Host "  cd infra; docker compose up -d"
Write-Host ""
Write-Host "  Dashboard:  https://127.0.0.1:8079   (self-signed cert - accept the warning)"
Write-Host "  Login:      analyst / (DASHBOARD_PASSWORD in infra\.env)"
Write-Host "  Logs:       cd infra; docker compose logs -f"
Write-Host "  Stop:       cd infra; docker compose down        (add -v to wipe all data)"
Write-Host ""
Write-Host "(Optional) local test env - only needed for pytest, not to run the stack:"
Write-Host "  py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1"
Write-Host "  pip install -r requirements.in; python -m spacy download en_core_web_sm; pytest tests\"
