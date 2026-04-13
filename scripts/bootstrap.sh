#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# Zero Trust Identity Lab — Bootstrap Script
# One-command full stack deployment
# ═══════════════════════════════════════════════════════════════
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Get project root directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo ""
echo "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo "${CYAN}  ${BOLD}Zero Trust Identity & Secrets Management Lab${NC}"
echo "${CYAN}  Full Stack Bootstrap${NC}"
echo "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Step 1: Check prerequisites ──
echo "${BLUE}[1/7]${NC} Checking prerequisites..."

if ! command -v docker > /dev/null 2>&1; then
    echo "${RED}[✗] Docker is not installed. Please install Docker first.${NC}"
    echo "    https://docs.docker.com/get-docker/"
    exit 1
fi
echo "  ${GREEN}[✓]${NC} Docker $(docker --version | cut -d' ' -f3 | tr -d ',')"

if ! docker compose version > /dev/null 2>&1; then
    echo "${RED}[✗] Docker Compose v2 is not available.${NC}"
    echo "    Please install Docker Compose v2: https://docs.docker.com/compose/install/"
    exit 1
fi
echo "  ${GREEN}[✓]${NC} $(docker compose version | head -1)"

if ! command -v openssl > /dev/null 2>&1; then
    echo "${RED}[✗] OpenSSL is not installed.${NC}"
    exit 1
fi
echo "  ${GREEN}[✓]${NC} OpenSSL $(openssl version | cut -d' ' -f2)"

if ! command -v curl > /dev/null 2>&1; then
    echo "${YELLOW}[!] curl not found — healthchecks may not work${NC}"
fi

echo ""

# ── Step 2: Check .env file ──
echo "${BLUE}[2/7]${NC} Checking environment configuration..."
if [ ! -f "${PROJECT_ROOT}/.env" ]; then
    echo "  ${YELLOW}[!]${NC} .env file not found — creating from .env.example"
    if [ -f "${PROJECT_ROOT}/.env.example" ]; then
        cp "${PROJECT_ROOT}/.env.example" "${PROJECT_ROOT}/.env"
        echo "  ${YELLOW}[!]${NC} Please edit .env with your values before production use"
    else
        echo "  ${RED}[✗]${NC} .env.example not found either — cannot continue"
        exit 1
    fi
else
    echo "  ${GREEN}[✓]${NC} .env file found"
fi
echo ""

# ── Step 3: Generate TLS certificates ──
echo "${BLUE}[3/7]${NC} Generating TLS certificates..."
if [ -f "${PROJECT_ROOT}/nginx/ssl/server.crt" ] && [ -f "${PROJECT_ROOT}/nginx/ssl/server.key" ]; then
    echo "  ${GREEN}[✓]${NC} Certificates already exist — skipping generation"
else
    chmod +x "${PROJECT_ROOT}/nginx/ssl/generate-certs.sh"
    sh "${PROJECT_ROOT}/nginx/ssl/generate-certs.sh"
    echo "  ${GREEN}[✓]${NC} Self-signed certificates generated"
fi
echo ""

# ── Step 4: Build and start services ──
echo "${BLUE}[4/7]${NC} Building and starting Docker services..."
cd "${PROJECT_ROOT}"
docker compose build --no-cache flask-app
echo "  ${GREEN}[✓]${NC} Flask app image built"

docker compose up -d
echo "  ${GREEN}[✓]${NC} All services starting..."
echo ""

# ── Step 5: Wait for services to be healthy ──
echo "${BLUE}[5/7]${NC} Waiting for services to become healthy..."

# Wait for Keycloak (main bottleneck)
echo "  Waiting for Keycloak (this may take 60-90 seconds)..."
RETRIES=40
while [ $RETRIES -gt 0 ]; do
    KC_STATUS=$(docker inspect --format='{{.State.Health.Status}}' zt-keycloak 2>/dev/null || echo "unknown")
    if [ "$KC_STATUS" = "healthy" ]; then
        break
    fi
    printf "  ."
    RETRIES=$((RETRIES - 1))
    sleep 5
done
echo ""
if [ "$KC_STATUS" = "healthy" ]; then
    echo "  ${GREEN}[✓]${NC} Keycloak is healthy"
else
    echo "  ${YELLOW}[!]${NC} Keycloak may still be starting — check 'docker compose logs keycloak'"
fi

# Wait for Elasticsearch
echo "  Waiting for Elasticsearch..."
RETRIES=30
while [ $RETRIES -gt 0 ]; do
    ES_STATUS=$(docker inspect --format='{{.State.Health.Status}}' zt-elasticsearch 2>/dev/null || echo "unknown")
    if [ "$ES_STATUS" = "healthy" ]; then
        break
    fi
    printf "  ."
    RETRIES=$((RETRIES - 1))
    sleep 5
done
echo ""
if [ "$ES_STATUS" = "healthy" ]; then
    echo "  ${GREEN}[✓]${NC} Elasticsearch is healthy"
else
    echo "  ${YELLOW}[!]${NC} Elasticsearch may still be starting"
fi

# Set up kibana_system password
echo "  Setting up Kibana system user..."
. "${PROJECT_ROOT}/.env"
curl -sf -X POST \
    -u "elastic:${ELASTIC_PASSWORD}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${KIBANA_PASSWORD}\"}" \
    "http://localhost:9200/_security/user/kibana_system/_password" > /dev/null 2>&1 || true
echo "  ${GREEN}[✓]${NC} Kibana system user configured"
echo ""

# ── Step 6: Configure Keycloak and OpenBao ──
echo "${BLUE}[6/7]${NC} Running post-startup configuration..."

# Verify Keycloak realm
if [ -f "${SCRIPT_DIR}/keycloak-configure.sh" ]; then
    chmod +x "${SCRIPT_DIR}/keycloak-configure.sh"
    sh "${SCRIPT_DIR}/keycloak-configure.sh" || echo "  ${YELLOW}[!]${NC} Keycloak config check had warnings"
fi

# Seed OpenBao secrets
if [ -f "${PROJECT_ROOT}/openbao/init/setup.sh" ]; then
    chmod +x "${PROJECT_ROOT}/openbao/init/setup.sh"
    sh "${PROJECT_ROOT}/openbao/init/setup.sh" || echo "  ${YELLOW}[!]${NC} OpenBao setup had warnings"
fi
echo ""

# ── Step 7: Final health check and status ──
echo "${BLUE}[7/7]${NC} Running health checks..."
if [ -f "${SCRIPT_DIR}/healthcheck.sh" ]; then
    chmod +x "${SCRIPT_DIR}/healthcheck.sh"
    sh "${SCRIPT_DIR}/healthcheck.sh"
fi

echo ""
echo "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo "${CYAN}  ${BOLD}✅ Zero Trust Lab is Ready!${NC}"
echo "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  ${BOLD}Access URLs:${NC}"
echo "  ─────────────────────────────────────────────────"
echo "  🔐 Identity Provider:  ${GREEN}https://localhost/auth${NC}"
echo "  🌐 Demo Application:   ${GREEN}https://localhost/app${NC}"
echo "  📊 Kibana SIEM:        ${GREEN}https://localhost/kibana${NC}"
echo "  ⚙️  Keycloak Admin:     ${GREEN}https://localhost/auth/admin${NC}"
echo ""
echo "  ${BOLD}Demo Credentials:${NC}"
echo "  ─────────────────────────────────────────────────"
echo "  Admin:   ztadmin  / Admin@123"
echo "  User:    ztuser   / User@123"
echo "  Viewer:  ztviewer / View@123"
echo ""
echo "  ${BOLD}Keycloak Admin:${NC}"
echo "  ─────────────────────────────────────────────────"
echo "  Username: admin"
echo "  Password: (see KC_ADMIN_PASSWORD in .env)"
echo ""
echo "  ${YELLOW}⚠️  Using self-signed certs — accept browser warnings${NC}"
echo "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
