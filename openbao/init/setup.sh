#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# OpenBao Initialization — Seed secrets, policies, and tokens
# ═══════════════════════════════════════════════════════════════
set -e

OPENBAO_ADDR="${OPENBAO_ADDR:-http://openbao:8200}"
OPENBAO_TOKEN="${OPENBAO_DEV_ROOT_TOKEN_ID:-root-dev-token-zerotrust}"

export BAO_ADDR="${OPENBAO_ADDR}"
export BAO_TOKEN="${OPENBAO_TOKEN}"

echo "══════════════════════════════════════════════"
echo "  OpenBao Secrets Initialization"
echo "══════════════════════════════════════════════"

# Wait for OpenBao to be ready
echo "[*] Waiting for OpenBao to be ready..."
RETRIES=30
until curl -sf "${OPENBAO_ADDR}/v1/sys/health" > /dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    if [ "$RETRIES" -le 0 ]; then
        echo "[✗] OpenBao did not become ready in time"
        exit 1
    fi
    sleep 2
done
echo "[✓] OpenBao is ready"

# ── Step 1: Enable KV v2 secrets engine ──
echo "[*] Enabling KV v2 secrets engine at secret/..."
curl -sf -X POST \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"type":"kv","options":{"version":"2"}}' \
    "${OPENBAO_ADDR}/v1/sys/mounts/secret" 2>/dev/null || echo "    (secret/ engine may already exist)"
echo "[✓] KV secrets engine enabled"

# ── Step 2: Write application secrets ──
echo "[*] Writing secrets to secret/flask-app/..."

# Database credentials
curl -sf -X POST \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"data":{"username":"appuser","password":"AppDB@Secure1"}}' \
    "${OPENBAO_ADDR}/v1/secret/data/flask-app/db"
echo "    [✓] secret/flask-app/db"

# API credentials
curl -sf -X POST \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"data":{"api_key":"zt-api-key-8f3k2m9x","endpoint":"https://internal-api.zerotrust.local"}}' \
    "${OPENBAO_ADDR}/v1/secret/data/flask-app/api"
echo "    [✓] secret/flask-app/api"

# Application configuration
curl -sf -X POST \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"data":{"environment":"production","debug":"false","log_level":"INFO"}}' \
    "${OPENBAO_ADDR}/v1/secret/data/flask-app/config"
echo "    [✓] secret/flask-app/config"

# ── Step 3: Create flask-app-policy ──
echo "[*] Creating flask-app-policy..."
POLICY='path "secret/data/flask-app/*" { capabilities = ["read"] }'
curl -sf -X PUT \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"policy\": \"${POLICY}\"}" \
    "${OPENBAO_ADDR}/v1/sys/policies/acl/flask-app-policy"
echo "[✓] flask-app-policy created"

# ── Step 4: Create a policy-scoped token ──
echo "[*] Creating token with flask-app-policy..."
TOKEN_RESPONSE=$(curl -sf -X POST \
    -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"policies":["flask-app-policy"],"ttl":"24h","renewable":true}' \
    "${OPENBAO_ADDR}/v1/auth/token/create")

APP_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])" 2>/dev/null || echo "could-not-extract")

echo "══════════════════════════════════════════════"
echo "  ✅  OpenBao initialization complete!"
echo ""
echo "  Secrets written:"
echo "    • secret/flask-app/db"
echo "    • secret/flask-app/api"  
echo "    • secret/flask-app/config"
echo ""
echo "  Policy: flask-app-policy"
echo "  App Token: ${APP_TOKEN}"
echo ""
echo "  ⚠️  In production, use this app token"
echo "     instead of the root token."
echo "══════════════════════════════════════════════"
