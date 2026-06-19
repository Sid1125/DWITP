# DWITP Secret Rotation Script (PowerShell)
# IR-12: Automated secret rotation for compromised crawler scenarios.
# Usage: .\scripts\rotate-secrets.ps1 [-Apply]
#   Without -Apply: prints new secrets to stdout (dry-run)
#   With -Apply:   updates .env file

param(
    [switch]$Apply
)

function Generate-Password {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes) -replace '[^a-zA-Z0-9]', '' -replace '.{32}', '$&' -replace '.$'
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
$envFile = Join-Path $projectDir ".env"

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output "# DWITP Secret Rotation — $timestamp"
Write-Output "#"

$newRabbitPass = Generate-Password
$newTorPass = Generate-Password
$newRabbitUser = "dwitp_rotated_$(Get-Date -UFormat %s)"

Write-Output "RABBITMQ_USER=${newRabbitUser}"
Write-Output "RABBITMQ_PASSWORD=${newRabbitPass}"
Write-Output "TOR_CONTROL_PASSWORD=${newTorPass}"
Write-Output ""
Write-Output "# Secrets NOT affected by crawler compromise:"
Write-Output "# POSTGRES_PASSWORD, OPENSEARCH_PASSWORD, NEO4J_PASSWORD"
Write-Output "# (no DB credentials in crawler container)"

if ($Apply) {
    if (-not (Test-Path $envFile)) {
        Write-Error ".env file not found at $envFile"
        exit 1
    }

    (Get-Content $envFile) -replace '^RABBITMQ_USER=.*', "RABBITMQ_USER=${newRabbitUser}" |
        Set-Content $envFile
    (Get-Content $envFile) -replace '^RABBITMQ_PASSWORD=.*', "RABBITMQ_PASSWORD=${newRabbitPass}" |
        Set-Content $envFile
    (Get-Content $envFile) -replace '^TOR_CONTROL_PASSWORD=.*', "TOR_CONTROL_PASSWORD=${newTorPass}" |
        Set-Content $envFile

    Write-Output "# Secrets written to ${envFile}"
    Write-Output "# Run: docker compose -f infra/docker-compose.yml up -d --force-recreate crawler rabbitmq tor"
    Write-Output "# Rotation complete."
}
