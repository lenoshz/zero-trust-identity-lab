#!/bin/sh
# ═══════════════════════════════════════════════════════════════
# Zero Trust Lab — Health Check Script
# Checks all services and prints a status table
# ═══════════════════════════════════════════════════════════════

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Load environment
if [ -f "${PROJECT_ROOT}/.env" ]; then
    . "${PROJECT_ROOT}/.env"
fi

echo ""
echo "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo "${BOLD}  Zero Trust Lab — Service Health Check${NC}"
echo "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""

check_service() {
    SERVICE_NAME="$1"
    CHECK_URL="$2"
    DISPLAY_URL="$3"
    EXTRA_OPTS="$4"

    STATUS_CODE=$(curl -sf -o /dev/null -w "%{http_code}" -k ${EXTRA_OPTS} "${CHECK_URL}" 2>/dev/null || echo "000")
    
    if [ "$STATUS_CODE" -ge 200 ] && [ "$STATUS_CODE" -lt 400 ]; then
        STATUS="${GREEN}● HEALTHY${NC}"
    elif [ "$STATUS_CODE" = "000" ]; then
        STATUS="${RED}● DOWN${NC}"
    else
        STATUS="${YELLOW}● DEGRADED (${STATUS_CODE})${NC}"
    fi

    printf "  %-20s %b    %s\n" "$SERVICE_NAME" "$STATUS" "$DISPLAY_URL"
}

echo "  ${BOLD}SERVICE              STATUS              URL${NC}"
echo "  ─────────────────────────────────────────────────────────────"

check_service "Keycloak" \
    "http://localhost:8080/health/ready" \
    "https://localhost/auth"

check_service "OpenBao" \
    "http://localhost:8200/v1/sys/health" \
    "http://localhost:8200"

check_service "Flask App" \
    "http://localhost:5000/health" \
    "https://localhost/app"

check_service "Nginx (HTTPS)" \
    "https://localhost/" \
    "https://localhost"

check_service "Elasticsearch" \
    "http://localhost:9200/_cluster/health" \
    "http://localhost:9200" \
    "-u elastic:${ELASTIC_PASSWORD}"

check_service "Kibana" \
    "http://localhost:5601/kibana/api/status" \
    "https://localhost/kibana"

echo ""
echo "  ${BOLD}Docker Container Status:${NC}"
echo "  ─────────────────────────────────────────────────────────────"
docker compose -f "${PROJECT_ROOT}/docker-compose.yml" ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || \
    docker compose -f "${PROJECT_ROOT}/docker-compose.yml" ps 2>/dev/null || \
    echo "  Could not fetch container status"

echo ""
echo "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
