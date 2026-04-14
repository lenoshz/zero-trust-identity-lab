#!/bin/sh
set -eu

OPENBAO_ADDR="${OPENBAO_ADDR:-http://openbao:8200}"
OPENBAO_TOKEN="${OPENBAO_DEV_ROOT_TOKEN_ID:-root-dev-token-zerotrust}"
APP_POLICY_NAME="${OPENBAO_APP_POLICY_NAME:-flask-app-policy}"
APP_TOKEN_FILE="${OPENBAO_APP_TOKEN_FILE:-/run/secrets/openbao/flask-app-token}"

export BAO_ADDR="${OPENBAO_ADDR}"
export BAO_TOKEN="${OPENBAO_TOKEN}"

echo "=============================================="
echo "  OpenBao Secrets Initialization"
echo "=============================================="

echo "[*] Waiting for OpenBao to be ready..."
RETRIES=30
until bao status >/dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -le 0 ]; then
        echo "[x] OpenBao did not become ready in time"
        exit 1
    fi
    sleep 2
done
echo "[ok] OpenBao is ready"

echo "[*] Enabling KV v2 secrets engine at secret/..."
bao secrets enable -path=secret -version=2 kv >/dev/null 2>&1 || echo "    (secret/ engine may already exist)"
echo "[ok] KV secrets engine enabled"

echo "[*] Seeding secrets at secret/flask-app/... if missing"
seed_secret_if_missing() {
    SECRET_PATH="$1"
    shift
    if bao kv get -mount=secret "$SECRET_PATH" >/dev/null 2>&1; then
        echo "    [=] secret/${SECRET_PATH} (already exists)"
    else
        # shellcheck disable=SC2086
        bao kv put -mount=secret "$SECRET_PATH" $@ >/dev/null
        echo "    [ok] secret/${SECRET_PATH}"
    fi
}

seed_secret_if_missing "flask-app/db" "username=appuser" "password=AppDB@Secure1"
seed_secret_if_missing "flask-app/api" "api_key=zt-api-key-8f3k2m9x" "endpoint=https://internal-api.zerotrust.local"
seed_secret_if_missing "flask-app/config" "environment=production" "debug=false" "log_level=INFO"

echo "[*] Creating ${APP_POLICY_NAME}..."
cat <<EOF | bao policy write "${APP_POLICY_NAME}" - >/dev/null
path "secret/data/flask-app/*" {
  capabilities = ["read"]
}

path "secret/metadata/flask-app/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/flask-app" {
  capabilities = ["list"]
}
EOF
echo "[ok] ${APP_POLICY_NAME} created"

echo "[*] Ensuring scoped token exists..."
validate_token() {
    CANDIDATE_TOKEN="$1"
    if [ -z "$CANDIDATE_TOKEN" ]; then
        return 1
    fi
    BAO_TOKEN="$CANDIDATE_TOKEN" bao kv get -mount=secret flask-app/config >/dev/null 2>&1
}

APP_TOKEN=""
if [ -f "${APP_TOKEN_FILE}" ]; then
    APP_TOKEN="$(tr -d '\r\n' < "${APP_TOKEN_FILE}")"
fi

if validate_token "$APP_TOKEN"; then
    echo "    [=] Reusing existing app token from ${APP_TOKEN_FILE}"
else
    APP_TOKEN="$(bao token create -policy="${APP_POLICY_NAME}" -display-name="flask-app-dev" -orphan -ttl=720h -renewable=true -field=token)"
    mkdir -p "$(dirname "${APP_TOKEN_FILE}")"
    printf "%s" "$APP_TOKEN" > "${APP_TOKEN_FILE}"
    chmod 644 "${APP_TOKEN_FILE}" || true
    echo "    [ok] Created new app token at ${APP_TOKEN_FILE}"
fi

if [ -f "${APP_TOKEN_FILE}" ]; then
    chmod 644 "${APP_TOKEN_FILE}" || true
fi

echo "=============================================="
echo "  OpenBao initialization complete"
echo ""
echo "  Policy: ${APP_POLICY_NAME}"
echo "  App Token File: ${APP_TOKEN_FILE}"
echo "=============================================="
