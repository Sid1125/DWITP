# DWITP Build — Windows / PowerShell
# Builds all Docker images from the committed (hash-locked) requirements.txt.
# Run from the repository root:  .\scripts\build.ps1  [-NoCache]
#
# NOTE: this does NOT regenerate requirements.txt. The committed file is the
# source of truth and the Dockerfiles add a few packages on top of it
# (opensearch-py, telethon, networkx, scipy). To re-pin after changing deps,
# edit requirements.in and run scripts/pin-hashes.sh.
param([switch]$NoCache)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..").Path

Write-Host "=== DWITP Build ===" -ForegroundColor Cyan
try { $null = docker info } catch { Write-Error "Docker daemon is not running."; exit 1 }

$composeArgs = @("-f", "$Root\infra\docker-compose.yml", "build")
if ($NoCache) { $composeArgs += "--no-cache" }
docker compose @composeArgs

Write-Host ""
Write-Host "=== Build complete ===" -ForegroundColor Green
Write-Host "Deploy with:  cd infra; docker compose up -d"
