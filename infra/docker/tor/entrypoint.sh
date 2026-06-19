#!/bin/sh
set -e

# Generate hashed control password from environment variable
if [ -n "$TOR_CONTROL_PASSWORD" ]; then
    HASHED=$(tor --hash-password "$TOR_CONTROL_PASSWORD" 2>/dev/null)
    sed "s/^#HashedControlPassword.*/HashedControlPassword $HASHED/" /etc/tor/torrc.template > /tmp/torrc
else
    # Fallback: no password (only accessible on internal network)
    sed '/^#HashedControlPassword/d' /etc/tor/torrc.template > /tmp/torrc
fi

exec tor -f /tmp/torrc
