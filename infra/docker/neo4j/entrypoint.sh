#!/bin/bash
# Neo4j entrypoint for overlay filesystems (Docker Desktop on Windows).
# Processes NEO4J_ env vars without relying on sed --in-place or chmod.
set -euo pipefail

NEO4J_HOME="${NEO4J_HOME:-/var/lib/neo4j}"
CONF="$NEO4J_HOME/conf/neo4j.conf"

# --- Handle NEO4J_AUTH ---
set_neo4j_password() {
    local auth="${1}"
    if [ "${auth}" = "none" ]; then
        return 0
    fi
    local user="${auth%%/*}"
    local pass="${auth#*/}"
    if [ -z "${user}" ] || [ -z "${pass}" ]; then
        echo "WARNING: NEO4J_AUTH malformed: ${auth}" >&2
        return 0
    fi
    # Only set password if the database has not been initialized yet
    if [ ! -f "${NEO4J_HOME}/data/dbms/auth.ini" ]; then
        echo "Setting initial Neo4j password for user '${user}'"
        neo4j-admin dbms set-initial-password "${pass}" 2>/dev/null || \
        neo4j-admin set-initial-password "${pass}" 2>/dev/null || true
    fi
}

if [ -n "${NEO4J_AUTH:-}" ]; then
    set_neo4j_password "${NEO4J_AUTH}"
fi

# --- Process other NEO4J_ env vars ---
for var in $(compgen -A variable | grep '^NEO4J_' | sort); do
    case "${var}" in
        NEO4J_AUTH|NEO4J_HOME|NEO4J_SHA256|NEO4J_TARBALL|NEO4J_EDITION)
            continue
            ;;
    esac
    local_name="${var#NEO4J_}"
    # Convert __ to _DOUBL_ (placeholder), then _ to ., then placeholder to _
    config_key=$(echo "${local_name}" | sed 's/__/\x01/g; s/_/./g; s/\x01/_/g' | tr '[:upper:]' '[:lower:]')
    config_value="${!var}"
    # Remove any existing line with this setting
    grep -v "^${config_key}=" "${CONF}" > "${CONF}.tmp" 2>/dev/null || true
    mv "${CONF}.tmp" "${CONF}"
    # Append the new setting
    echo "${config_key}=${config_value}" >> "${CONF}"
done

# --- Fix ownership (chmod still fails, so skip it) ---
chown -R neo4j:neo4j "${NEO4J_HOME}/conf" 2>/dev/null || true

# --- Allow all config files to be read by the neo4j user ---
# chmod is not supported on overlay, but we can ensure ownership is correct.
# The files should already be 644 or similar from the image; just verify they're readable.

# --- Start Neo4j ---
echo "Starting Neo4j..."
exec neo4j console
