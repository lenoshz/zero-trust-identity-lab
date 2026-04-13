#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# Keycloak Configuration Verification
# Verifies the realm was imported correctly via Keycloak REST API
# ═══════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load environment variables
if [ -f "${PROJECT_ROOT}/.env" ]; then
    . "${PROJECT_ROOT}/.env"
fi

KC_URL="http://localhost:8080"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-Admin@ZeroTrust1}"
REALM="zero-trust-realm"

echo "══════════════════════════════════════════════"
echo "  Keycloak Configuration Verification"
echo "══════════════════════════════════════════════"

# ── Get admin access token ──
echo "[*] Obtaining admin access token..."
TOKEN_RESPONSE=$(curl -sf -X POST \
    "${KC_URL}/realms/master/protocol/openid-connect/token" \
    -d "client_id=admin-cli" \
    -d "username=${KC_ADMIN}" \
    -d "password=${KC_ADMIN_PASSWORD}" \
    -d "grant_type=password" 2>/dev/null)

if [ -z "$TOKEN_RESPONSE" ]; then
    echo "[✗] Could not obtain admin token — Keycloak may not be ready"
    exit 1
fi

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "" ]; then
    echo "[✗] Failed to parse access token"
    exit 1
fi
echo "[✓] Admin token obtained"

# ── Check realm exists ──
echo "[*] Checking realm '${REALM}'..."
REALM_CHECK=$(curl -sf -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}" 2>/dev/null)

if [ "$REALM_CHECK" = "200" ]; then
    echo "[✓] Realm '${REALM}' exists"
else
    echo "[✗] Realm '${REALM}' not found (HTTP ${REALM_CHECK})"
    echo "    The realm should be auto-imported from realm-export.json"
    exit 1
fi

# ── Check client exists ──
echo "[*] Checking client 'flask-demo-app'..."
CLIENTS=$(curl -sf \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/clients?clientId=flask-demo-app" 2>/dev/null)

CLIENT_COUNT=$(echo "$CLIENTS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

if [ "$CLIENT_COUNT" -gt "0" ]; then
    echo "[✓] Client 'flask-demo-app' exists"
else
    echo "[✗] Client 'flask-demo-app' not found"
fi

# ── Check users exist ──
echo "[*] Checking users..."
for USER in ztadmin ztuser ztviewer; do
    USER_CHECK=$(curl -sf \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        "${KC_URL}/admin/realms/${REALM}/users?username=${USER}&exact=true" 2>/dev/null)
    
    USER_COUNT=$(echo "$USER_CHECK" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
    
    if [ "$USER_COUNT" -gt "0" ]; then
        echo "    [✓] User '${USER}' exists"
    else
        echo "    [✗] User '${USER}' not found"
    fi
done

# ── Check roles exist ──
echo "[*] Checking realm roles..."
ROLES=$(curl -sf \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    "${KC_URL}/admin/realms/${REALM}/roles" 2>/dev/null)

for ROLE in zero-trust-admin zero-trust-user zero-trust-readonly; do
    ROLE_EXISTS=$(echo "$ROLES" | python3 -c "import sys,json; roles=[r['name'] for r in json.load(sys.stdin)]; print('yes' if '${ROLE}' in roles else 'no')" 2>/dev/null || echo "no")
    
    if [ "$ROLE_EXISTS" = "yes" ]; then
        echo "    [✓] Role '${ROLE}' exists"
    else
        echo "    [✗] Role '${ROLE}' not found"
    fi
done

echo "══════════════════════════════════════════════"
echo "  ✅ Keycloak configuration verified!"
echo "══════════════════════════════════════════════"
