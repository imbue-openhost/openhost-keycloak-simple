#!/bin/bash
# OpenHost supervisor for Keycloak + SSO auth proxy.
#
# Boot sequence:
#   1. Generate a per-boot bootstrap admin (password lives only in process
#      env, never on disk — see README).
#   2. Start the auth proxy immediately so OpenHost's readiness probe on
#      port 8080 gets a 200 while the JVM warms up.
#   3. Create the bootstrap admin in the (stopped) server's database.
#   4. Start Keycloak.
set -euo pipefail

KC_DIR=/opt/keycloak
DATA_DIR="${OPENHOST_APP_DATA_DIR:?OPENHOST_APP_DATA_DIR is required}"
APP_NAME="${OPENHOST_APP_NAME:-keycloak}"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:?OPENHOST_ZONE_DOMAIN is required}"

H2_DIR="$DATA_DIR/h2"
mkdir -p "$H2_DIR"
chown -R keycloak:keycloak "$DATA_DIR"

export KC_DB=dev-file
export KC_DB_URL="jdbc:h2:file:$H2_DIR/keycloakdb;AUTO_SERVER=TRUE;NON_KEYWORDS=VALUE"
export KC_HOSTNAME="https://$APP_NAME.$ZONE_DOMAIN"
export KC_HTTP_ENABLED=true
export KC_HTTP_HOST=127.0.0.1
export KC_HTTP_PORT=8081
export KC_PROXY_HEADERS=xforwarded
export KC_HEALTH_ENABLED=true
export KC_HTTP_MANAGEMENT_HOST=127.0.0.1
export KC_HTTP_MANAGEMENT_PORT=9001

# Per-boot SSO bootstrap admin. A fresh admin user with a random password is
# created on every container start; the auth proxy deletes stale ones from
# previous boots once the server is up. Neither value is written to disk.
SSO_USER="openhost-sso-$(head -c 4 /dev/urandom | od -An -tx1 | tr -d ' \n')"
SSO_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
export SSO_USER SSO_PASSWORD

# runuser without --login preserves the environment, so the KC_*/SSO_*
# exports above reach the child processes.
runuser -u keycloak -- python3 /opt/openhost/auth_proxy.py &
PROXY_PID=$!

runuser -u keycloak -- "$KC_DIR/bin/kc.sh" bootstrap-admin user \
    --username:env SSO_USER --password:env SSO_PASSWORD --no-prompt --optimized

runuser -u keycloak -- "$KC_DIR/bin/kc.sh" start --optimized &
KC_PID=$!

term() { kill "$KC_PID" "$PROXY_PID" 2>/dev/null || true; }
trap term SIGTERM SIGINT

set +e
wait -n "$KC_PID" "$PROXY_PID"
rc=$?
term
wait
exit "$rc"
