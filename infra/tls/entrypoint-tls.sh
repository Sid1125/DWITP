#!/usr/bin/env bash
# Shared TLS bootstrap sourced from service entrypoints.
# Generates the internal CA (once) and a service-specific cert.
# Usage: source entrypoint-tls.sh <service-name>
set -euo pipefail

TLS_DIR="${TLS_DATA_DIR:-/etc/dwitp/tls}"
CA_DIR="$TLS_DIR/ca"
CA_CRT="$CA_DIR/ca.crt"
SERVICE_NAME="${1:?entrypoint-tls.sh: service name required}"
SERVICE_DIR="$TLS_DIR/$SERVICE_NAME"

# Generate CA if missing (only first service to run creates it)
/usr/local/bin/gen-ca.sh "$CA_DIR"

# Generate service cert if missing
/usr/local/bin/gen-cert.sh "$SERVICE_NAME" "$CA_DIR" "$SERVICE_DIR"

export TLS_CA_CRT="$CA_CRT"
export TLS_SERVICE_CRT="$SERVICE_DIR/$SERVICE_NAME.crt"
export TLS_SERVICE_KEY="$SERVICE_DIR/$SERVICE_NAME.key"
