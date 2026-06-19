#!/bin/bash
# Wrapper entrypoint: fixes TLS key permissions as root, then chains to official entrypoint.
set -euo pipefail

# Fix TLS key ownership (tls-init creates as root:root 600)
if [ -f /etc/dwitp/tls/postgres/postgres.key ]; then
    chmod 600 /etc/dwitp/tls/postgres/postgres.key 2>/dev/null || true
    chown postgres:postgres /etc/dwitp/tls/postgres/postgres.key 2>/dev/null || true
fi
if [ -f /etc/dwitp/tls/ca/ca.key ]; then
    chmod 600 /etc/dwitp/tls/ca/ca.key 2>/dev/null || true
    chown postgres:postgres /etc/dwitp/tls/ca/ca.key 2>/dev/null || true
fi

# Chain to official postgres entrypoint
exec /usr/local/bin/docker-entrypoint.sh "$@"