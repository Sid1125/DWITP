#!/usr/bin/env bash
# DWITP Setup — Debian 12 / Ubuntu 24.04
# Prerequisites: Docker Engine 24+, Python 3.12+, OpenSSL
# Usage: ./scripts/setup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== DWITP Setup ==="

# ─── Step 1: Prerequisites ────────────────────────────────────────
echo "[1/6] Prerequisites..."
for cmd in docker python3 openssl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "  ERROR: $cmd is required"
        exit 1
    fi
done
echo "  docker:   $(docker --version)"
echo "  python3:  $(python3 --version)"
echo "  openssl:  $(openssl version | cut -d' ' -f2)"

# ─── Step 2: Environment ──────────────────────────────────────────
echo "[2/6] Environment..."
if [ -f .env ]; then
    echo "  .env exists, keeping existing"
else
    cat > .env <<EOF
# DWITP Environment — generated $(date -u +%Y-%m-%d)
POSTGRES_PASSWORD=$(openssl rand -base64 24)
OPENSEARCH_PASSWORD=$(openssl rand -base64 24)
NEO4J_PASSWORD=$(openssl rand -base64 24)
RABBITMQ_PASSWORD=$(openssl rand -base64 24)
TOR_CONTROL_PASSWORD=$(openssl rand -base64 24)
DASHBOARD_PASSWORD=$(openssl rand -base64 24)
DASHBOARD_SECRET_KEY=$(openssl rand -base64 32)
AUDIT_ENCRYPTION_KEY=$(openssl rand -base64 32)
OLLAMA_MODEL=mistral:7b
PI_CAMPAIGN_THRESHOLD=5
EOF
    chmod 600 .env
    echo "  Generated .env with random passwords"
fi

# ─── Step 3: Virtual environment ──────────────────────────────────
echo "[3/6] Virtual environment..."
VENV="$ROOT/.venv"
if [ ! -d "$VENV" ]; then
    python3 -m venv "$VENV"
    echo "  Created $VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# ─── Step 4: Dependencies ─────────────────────────────────────────
echo "[4/6] Dependencies..."
pip install --quiet --upgrade pip
pip install --quiet --upgrade -r requirements.in
python3 -m spacy download en_core_web_sm --quiet 2>/dev/null || \
    pip install --quiet "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.7.1/en_core_web_sm-3.7.1-py3-none-any.whl"
echo "  $(pip list --format=columns | wc -l) packages installed"

# ─── Step 5: Docker images ────────────────────────────────────────
echo "[5/6] Docker images..."
docker compose --env-file .env -f infra/docker-compose.yml build --quiet 2>/dev/null || \
    docker compose --env-file .env -f infra/docker-compose.yml build
echo "  Images built"

# ─── Step 6: Smoke test ───────────────────────────────────────────
echo "[6/6] Smoke test..."
python3 -m pytest tests/ --quiet --tb=short -x 2>/dev/null && \
    echo "  Tests:  all passed" || \
    echo "  Tests:  some failed (run 'pytest tests/' to inspect)"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "  Start:     docker compose --env-file .env -f infra/docker-compose.yml up -d"
echo "  Health:    ./scripts/healthcheck.sh"
echo "  E2E test:  ./scripts/e2e_test.sh"
echo "  Dashboard: http://localhost:8080"
echo "  Logs:      docker compose -f infra/docker-compose.yml logs -f"
echo "  Shell:     source .venv/bin/activate"

