#!/usr/bin/env bash
# DWITP Setup — Linux / macOS (Debian 12, Ubuntu 24.04, etc.)
# Prerequisites: Docker Engine 24+ with the compose plugin, OpenSSL.
#                (Python 3.12 only needed for the optional local test env.)
# Usage: ./scripts/setup.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ENV_FILE="$ROOT/infra/.env"

echo "=== DWITP Setup ==="

# ─── Step 1: Prerequisites ────────────────────────────────────────
echo "[1/3] Checking prerequisites..."
for cmd in docker openssl; do
    command -v "$cmd" &>/dev/null || { echo "  ERROR: '$cmd' is required but not found."; exit 1; }
done
docker compose version &>/dev/null || { echo "  ERROR: the Docker Compose plugin is required ('docker compose')."; exit 1; }
docker info &>/dev/null || { echo "  ERROR: the Docker daemon is not running. Start Docker and retry."; exit 1; }
echo "  docker:  $(docker --version)"
echo "  compose: $(docker compose version --short 2>/dev/null || echo present)"

# ─── Step 2: Environment (infra/.env) ─────────────────────────────
echo "[2/3] Generating infra/.env..."
if [ -f "$ENV_FILE" ]; then
    echo "  infra/.env already exists — keeping it (delete it to regenerate)."
else
    # Alphanumeric/hex secrets avoid shell/URL escaping problems in passwords.
    gen() { openssl rand -hex 24; }
    # Fernet key: 32 url-safe base64 bytes (REQUIRED by every service's audit log).
    fernet() { openssl rand -base64 32 | tr '+/' '-_'; }
    # OpenSearch demands a strong password (upper+lower+digit+symbol, 8+).
    os_pw="Dw1tp-$(openssl rand -hex 12)"
    cat > "$ENV_FILE" <<EOF
# DWITP environment — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
POSTGRES_PASSWORD=$(gen)
OPENSEARCH_PASSWORD=${os_pw}
NEO4J_PASSWORD=$(gen)
RABBITMQ_PASSWORD=$(gen)
TOR_CONTROL_PASSWORD=$(gen)
DASHBOARD_USERNAME=analyst
DASHBOARD_PASSWORD=$(gen)
DASHBOARD_SECRET_KEY=$(openssl rand -hex 32)
AUDIT_ENCRYPTION_KEY=$(fernet)
PI_CAMPAIGN_THRESHOLD=5
GRAPH_ANALYTICS_INTERVAL=300
EOF
    chmod 600 "$ENV_FILE"
    echo "  Wrote infra/.env with fresh random secrets (chmod 600)."
    echo "  Dashboard login: analyst / $(grep '^DASHBOARD_PASSWORD=' "$ENV_FILE" | cut -d= -f2)"
fi

# ─── Step 3: Build images ─────────────────────────────────────────
echo "[3/3] Building Docker images (first build downloads base images; be patient)..."
# --env-file is explicit so the build resolves vars regardless of the caller's CWD.
docker compose --env-file "$ENV_FILE" -f "$ROOT/infra/docker-compose.yml" build
echo "  Images built."

cat <<EOF

=== Setup complete ===

Start the stack:
  cd infra && docker compose up -d

Then:
  Dashboard:  https://127.0.0.1:8079      (self-signed cert — accept the warning)
  Login:      analyst / (DASHBOARD_PASSWORD in infra/.env)
  Health:     ./scripts/healthcheck.sh
  Logs:       cd infra && docker compose logs -f
  Stop:       cd infra && docker compose down        (add -v to wipe all data)

(Optional) local test env — only needed to run pytest, not to run the stack:
  python3 -m venv .venv && . .venv/bin/activate
  pip install -r requirements.in && python -m spacy download en_core_web_sm
  pytest tests/
EOF
