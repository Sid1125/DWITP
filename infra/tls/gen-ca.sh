#!/usr/bin/env bash
# Generate self-signed CA for internal mTLS.
# Idempotent — skips if CA already exists.
set -euo pipefail

CA_DIR="${1:-/etc/dwitp/tls/ca}"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"

if [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ]; then
    exit 0
fi

mkdir -p "$CA_DIR"

openssl genrsa -out "$CA_KEY" 4096

openssl req -x509 -new -nodes -key "$CA_KEY" \
    -sha256 -days 3650 \
    -out "$CA_CRT" \
    -subj "/C=XX/O=DWITP/CN=Internal CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

chmod 600 "$CA_KEY"
chmod 644 "$CA_CRT"
echo "CA generated: $CA_CRT"
