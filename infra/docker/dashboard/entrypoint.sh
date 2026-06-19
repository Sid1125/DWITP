#!/bin/bash
set -e

if [ "${DASHBOARD_USE_HTTPS}" = "true" ]; then
    CERT_DIR=$(dirname "$DASHBOARD_HTTPS_CERT")
    mkdir -p "$CERT_DIR"

    if [ ! -f "$DASHBOARD_HTTPS_CERT" ] || [ ! -f "$DASHBOARD_HTTPS_KEY" ]; then
        echo "Generating self-signed TLS certificate..."
        openssl req -x509 -newkey rsa:4096 -keyout "$DASHBOARD_HTTPS_KEY" \
            -out "$DASHBOARD_HTTPS_CERT" -days 365 -nodes \
            -subj "/C=XX/O=DWITP/CN=dashboard" 2>/dev/null
        chmod 600 "$DASHBOARD_HTTPS_KEY"
        echo "Certificate generated: $DASHBOARD_HTTPS_CERT"
    fi
else
    echo "Dashboard running in HTTP mode (no TLS)"
fi

exec python -m src.dashboard.main
