#!/usr/bin/env bash
# One-shot TLS init: generates internal CA + service certificates.
# Runs before any service starts, populates shared tls_data volume.
set -euo pipefail

TLS_DIR="${TLS_DATA_DIR:-/etc/dwitp/tls}"
CA_DIR="$TLS_DIR/ca"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"

SERVICES=(
    rabbitmq postgres neo4j
    crawler sanitizer analysis ai_layer db_writer dashboard
)

# Generate CA
mkdir -p "$CA_DIR"
if [ ! -f "$CA_CRT" ]; then
    openssl genrsa -out "$CA_KEY" 4096
    openssl req -x509 -new -nodes -key "$CA_KEY" \
        -sha256 -days 3650 \
        -out "$CA_CRT" \
        -subj "/C=XX/O=DWITP/CN=Internal CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    chmod 644 "$CA_CRT"
    chmod 600 "$CA_KEY"
    echo "CA: $CA_CRT"
fi

# Generate per-service certs
for NAME in "${SERVICES[@]}"; do
    SDIR="$TLS_DIR/$NAME"
    KEY="$SDIR/$NAME.key"
    CRT="$SDIR/$NAME.crt"

    if [ -f "$KEY" ] && [ -f "$CRT" ]; then
        continue
    fi

    mkdir -p "$SDIR"
    openssl genrsa -out "$KEY" 2048
    openssl req -new -key "$KEY" \
        -out "$SDIR/$NAME.csr" \
        -subj "/C=XX/O=DWITP/CN=$NAME"
    openssl x509 -req -in "$SDIR/$NAME.csr" \
        -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
        -out "$CRT" -days 365 -sha256 \
        -extfile <(echo "subjectAltName=DNS:$NAME,DNS:localhost")
    rm -f "$SDIR/$NAME.csr"
    # Server services need 600; client services need 644 for non-root users
    case "$NAME" in
        rabbitmq|postgres|neo4j|dashboard)
            chmod 600 "$KEY" ;;
        *)
            chmod 644 "$KEY" ;;
    esac
    chmod 644 "$CRT"
    echo "Cert: $CRT"

    # Neo4j expects standard PEM filenames
    if [ "$NAME" = "neo4j" ]; then
        ln -sf "$KEY" "$SDIR/private.key"
        ln -sf "$CRT" "$SDIR/public.crt"
        ln -sf "$CA_CRT" "$SDIR/trusted.crt"
        echo "  Neo4j PEM links: private.key, public.crt, trusted.crt"
    fi

    # Python services need CA cert for RMQ/DB client verification
    if [ "$NAME" = "rabbitmq" ] || [ "$NAME" = "postgres" ]; then
        ln -sf "$CA_CRT" "$SDIR/ca.crt"
    fi
done

echo "TLS init complete — $((${#SERVICES[@]})) service certs generated."
