#!/usr/bin/env bash
# Generate a TLS server cert signed by the internal CA.
# Usage: gen-cert.sh <service-name> [CA-dir] [output-dir]
set -euo pipefail

NAME="${1:?Usage: gen-cert.sh <service-name>}"
CA_DIR="${2:-/etc/dwitp/tls/ca}"
OUT_DIR="${3:-/etc/dwitp/tls/$NAME}"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"

if [ -f "$OUT_DIR/$NAME.key" ] && [ -f "$OUT_DIR/$NAME.crt" ]; then
    exit 0
fi

mkdir -p "$OUT_DIR"

openssl genrsa -out "$OUT_DIR/$NAME.key" 2048

openssl req -new -key "$OUT_DIR/$NAME.key" \
    -out "$OUT_DIR/$NAME.csr" \
    -subj "/C=XX/O=DWITP/CN=$NAME"

openssl x509 -req -in "$OUT_DIR/$NAME.csr" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$OUT_DIR/$NAME.crt" -days 365 -sha256 \
    -extfile <(echo "subjectAltName=DNS:$NAME,DNS:localhost")

rm -f "$OUT_DIR/$NAME.csr"
chmod 600 "$OUT_DIR/$NAME.key"
chmod 644 "$OUT_DIR/$NAME.crt"
echo "Certificate generated: $OUT_DIR/$NAME.crt"
