#!/bin/bash
set -euo pipefail

# TLS bootstrap before RabbitMQ init
source /usr/local/bin/entrypoint-tls.sh rabbitmq

# Fix TLS key ownership for rabbitmq user (UID 100)
chown 100:100 "${TLS_SERVICE_KEY}" 2>/dev/null || true
chown 100:100 "${TLS_CA_CRT}" 2>/dev/null || true

# Write rabbitmq.conf with TLS settings (runs before official entrypoint picks it up)
cat > /etc/rabbitmq/rabbitmq.conf <<EOF
listeners.ssl.default = 5671
ssl_options.cacertfile = ${TLS_CA_CRT}
ssl_options.certfile = ${TLS_SERVICE_CRT}
ssl_options.keyfile = ${TLS_SERVICE_KEY}
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = false
# To enable mandatory mTLS, set to true AND ensure every producer/consumer
# has a valid client cert + the queue library correctly loads it.
# Test with: rabbitmq-diagnostics status --ssl
management.listener.port = 15671
management.listener.ssl = true
EOF

# Chain to official docker entrypoint
exec /usr/local/bin/docker-entrypoint.sh "$@"