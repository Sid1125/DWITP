#!/usr/bin/env bash
# DWITP Secret Rotation Script
# IR-12: Automated secret rotation for compromised crawler scenarios.
# Usage: ./scripts/rotate-secrets.sh [--apply]
#   Without --apply: prints new secrets to stdout (dry-run)
#   With --apply:   updates .env file and restarts affected services
set -euo pipefail

SECRETS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${SECRETS_DIR}/.env"

generate_password() {
    head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32
}

echo "# DWITP Secret Rotation — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "#"

NEW_RABBITMQ_PASS=$(generate_password)
NEW_TOR_PASS=$(generate_password)
NEW_RABBITMQ_USER="dwitp_rotated_$(date +%s)"

echo "RABBITMQ_USER=${NEW_RABBITMQ_USER}"
echo "RABBITMQ_PASSWORD=${NEW_RABBITMQ_PASS}"
echo "TOR_CONTROL_PASSWORD=${NEW_TOR_PASS}"
echo ""
echo "# Secrets NOT affected by crawler compromise:"
echo "# POSTGRES_PASSWORD, OPENSEARCH_PASSWORD, NEO4J_PASSWORD"
echo "# (no DB credentials in crawler container)"

if [ "${1:-}" = "--apply" ]; then
    if [ ! -f "$ENV_FILE" ]; then
        echo "ERROR: .env file not found at $ENV_FILE" >&2
        exit 1
    fi

    sed -i "s/^RABBITMQ_USER=.*/RABBITMQ_USER=${NEW_RABBITMQ_USER}/" "$ENV_FILE"
    sed -i "s/^RABBITMQ_PASSWORD=.*/RABBITMQ_PASSWORD=${NEW_RABBITMQ_PASS}/" "$ENV_FILE"
    sed -i "s/^TOR_CONTROL_PASSWORD=.*/TOR_CONTROL_PASSWORD=${NEW_TOR_PASS}/" "$ENV_FILE"

    echo "# Secrets written to ${ENV_FILE}"

    echo "# Restarting affected services..."
    docker compose -f "${SECRETS_DIR}/infra/docker-compose.yml" up -d --force-recreate \
        crawler rabbitmq tor

    echo "# Rotation complete. Crawler, RabbitMQ, and Tor restarted with new credentials."
fi
