# Zero Trust Identity Lab — Setup Guide

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Manual Setup](#manual-setup)
4. [Kibana Dashboard Setup](#kibana-dashboard-setup)
5. [Generating Test Events](#generating-test-events)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Software

| Software | Minimum Version | Check Command |
|----------|----------------|---------------|
| Docker | 20.10+ | `docker --version` |
| Docker Compose | v2.0+ | `docker compose version` |
| OpenSSL | 1.1+ | `openssl version` |
| curl | 7.0+ | `curl --version` |

### System Requirements

- **RAM**: 8GB minimum (Elasticsearch alone uses ~512MB)
- **Disk**: 5GB free space for images and volumes
- **Ports**: 80, 443, 5000, 5601, 8080, 8200, 9200 must be available

### Check Port Availability

```bash
# Linux/macOS
for port in 80 443 5000 5601 8080 8200 9200; do
    lsof -i :$port > /dev/null 2>&1 && echo "Port $port is IN USE" || echo "Port $port is available"
done

# Windows (PowerShell)
@(80, 443, 5000, 5601, 8080, 8200, 9200) | ForEach-Object {
    $result = netstat -an | findstr ":$_ "
    if ($result) { "Port $_ is IN USE" } else { "Port $_ is available" }
}
```

---

## Quick Start

```bash
git clone https://github.com/lenoshz/zero-trust-identity-lab.git
cd zero-trust-identity-lab
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

The bootstrap script will:
1. ✅ Verify Docker and Docker Compose are installed
2. ✅ Generate self-signed TLS certificates
3. ✅ Build the Flask app Docker image
4. ✅ Start all 8 services in dependency order
5. ✅ Wait for health checks to pass
6. ✅ Set up Kibana system user credentials
7. ✅ Verify Keycloak realm configuration
8. ✅ Seed OpenBao with application secrets
9. ✅ Print access URLs and credentials

---

## Manual Setup

### Step 1: Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your preferred values (defaults work for local dev)
# All passwords and tokens are configured here
```

### Step 2: Generate TLS Certificates

```bash
chmod +x nginx/ssl/generate-certs.sh
./nginx/ssl/generate-certs.sh
```

This creates `nginx/ssl/server.crt` and `nginx/ssl/server.key` (self-signed, valid for 365 days).

### Step 3: Start Services

```bash
# Build and start all services
docker compose up -d

# Monitor startup (Keycloak takes 60-90 seconds)
docker compose logs -f keycloak
```

### Step 4: Configure Elasticsearch Users

After Elasticsearch is healthy, set the `kibana_system` user password:

```bash
source .env
curl -X POST -u "elastic:${ELASTIC_PASSWORD}" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${KIBANA_PASSWORD}\"}" \
    "http://localhost:9200/_security/user/kibana_system/_password"
```

### Step 5: Seed OpenBao Secrets

```bash
chmod +x openbao/init/setup.sh
./openbao/init/setup.sh
```

### Step 6: Verify Services

```bash
chmod +x scripts/healthcheck.sh
./scripts/healthcheck.sh
```

---

## Kibana Dashboard Setup

Kibana dashboards require manual setup through the UI. Follow these steps to create the **"Zero Trust Identity Threats"** dashboard.

### Step 1: Access Kibana

1. Navigate to `https://localhost/kibana`
2. Log in with `elastic` / `Elastic@ZeroTrust1`

### Step 2: Create Index Pattern

1. Go to **Stack Management** → **Index Patterns**
2. Click **Create index pattern**
3. Pattern: `zerotrust-logs-*`
4. Time field: `@timestamp`
5. Click **Create**

### Step 3: Create Dashboard

Go to **Dashboard** → **Create dashboard**. Name it: **"Zero Trust Identity Threats"**

### Panel 1: Failed Login Attempts Over Time

- Click **Create visualization** → **Lens**
- Index pattern: `zerotrust-logs-*`
- Visualization type: **Line**
- X-axis: `@timestamp`
- Y-axis: Count
- Filter: `message : "*LOGIN_ERROR*"` or `keycloak.type : "LOGIN_ERROR"`
- Title: "Failed Login Attempts"

### Panel 2: Successful Logins by User

- Visualization type: **Bar (vertical)**
- X-axis: `keycloak.userId` or `preferred_username` (Terms)
- Y-axis: Count
- Filter: `message : "*LOGIN*" AND NOT message : "*ERROR*"`
- Title: "Successful Logins by User"

### Panel 3: Admin Actions Log

- Visualization type: **Data table**
- Columns: `@timestamp`, `message`, `keycloak.type`
- Filter: `source : "keycloak" AND message : "*ADMIN*"`
- Title: "Admin Actions Log"

### Panel 4: Nginx HTTP Errors

- Visualization type: **Metric**
- Metric: Count
- Filter: `source : "nginx" AND status >= 400`
- Title: "Nginx 4xx/5xx Errors"

### Panel 5: Request Map (if applicable)

- Visualization type: **Maps** (if GeoIP data available)
- Use `remote_addr` field with GeoIP lookup
- Title: "Geographic Login Distribution"

### Step 4: Save Dashboard

Click **Save** and name it: **"Zero Trust Identity Threats"**

---

## Generating Test Events

### Failed Login Attempts (for SIEM testing)

```bash
# Generate 5 failed login attempts via Keycloak API
for i in $(seq 1 5); do
    curl -sf -X POST \
        "http://localhost:8080/realms/zero-trust-realm/protocol/openid-connect/token" \
        -d "client_id=flask-demo-app" \
        -d "client_secret=flask-demo-secret-2024" \
        -d "username=ztuser" \
        -d "password=WRONG_PASSWORD" \
        -d "grant_type=password" 2>/dev/null
    echo "  Attempt $i sent"
    sleep 1
done
echo "Check Kibana for LOGIN_ERROR events"
```

### Successful Login

```bash
# Direct grant login (generates LOGIN event)
curl -sf -X POST \
    "http://localhost:8080/realms/zero-trust-realm/protocol/openid-connect/token" \
    -d "client_id=flask-demo-app" \
    -d "client_secret=flask-demo-secret-2024" \
    -d "username=ztuser" \
    -d "password=User@123" \
    -d "grant_type=password" | python3 -m json.tool
```

### Nginx 404 Events

```bash
# Generate Nginx 404 errors
for path in /nonexistent /admin/hack /../../etc/passwd; do
    curl -sf -k "https://localhost${path}" > /dev/null 2>&1
done
```

---

## Troubleshooting

### 1. Keycloak Fails to Start / "Connection refused" to PostgreSQL

**Symptoms**: Keycloak container repeatedly restarts; logs show `Connection refused` or `FATAL: role "keycloak" does not exist`.

**Cause**: PostgreSQL hasn't finished initializing before Keycloak tries to connect, or the PostgreSQL credentials in `.env` don't match.

**Fix**:
```bash
# Check PostgreSQL is running and healthy
docker compose ps postgres
docker compose logs postgres

# Verify credentials match
grep POSTGRES_ .env

# Restart Keycloak after PostgreSQL is healthy
docker compose restart keycloak

# Nuclear option: reset everything
docker compose down -v
docker compose up -d
```

### 2. "Bad Gateway" (502) for Flask App or Keycloak

**Symptoms**: Nginx returns 502 when accessing `/app/` or `/auth/`.

**Cause**: The upstream service (Flask or Keycloak) isn't running or isn't on the same Docker network.

**Fix**:
```bash
# Check all services are on identity-net
docker network inspect identity-net

# Verify Flask app is running
docker compose logs flask-app

# Check Keycloak health
docker compose exec keycloak curl -s http://localhost:8080/health/ready

# Rebuild Flask image if needed
docker compose build flask-app
docker compose up -d flask-app
```

### 3. Elasticsearch Exits with "Out of Memory" / Killed by OOM

**Symptoms**: Elasticsearch container exits immediately; `docker compose logs elasticsearch` shows Java heap errors or the container is OOM killed.

**Cause**: The host system doesn't have enough RAM for the 512MB heap allocation.

**Fix**:
```bash
# Check available memory
free -h  # Linux
# or: systeminfo | findstr Memory  (Windows)

# Reduce ES heap (edit docker-compose.yml)
# Change: ES_JAVA_OPTS=-Xms512m -Xmx512m
# To:     ES_JAVA_OPTS=-Xms256m -Xmx256m

# On Linux, increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 4. TLS Certificate Errors / "NET::ERR_CERT_AUTHORITY_INVALID"

**Symptoms**: Browser shows certificate warning when accessing `https://localhost`.

**Cause**: Self-signed certificates are not trusted by the browser (expected behavior).

**Fix**:
- **Chrome/Edge**: Click "Advanced" → "Proceed to localhost (unsafe)"
- **Firefox**: Click "Advanced" → "Accept the Risk and Continue"
- **curl**: Use the `-k` flag to skip certificate verification
- **Programmatic**: This is expected in a lab — production would use Let's Encrypt

To regenerate certificates:
```bash
rm nginx/ssl/server.crt nginx/ssl/server.key
./nginx/ssl/generate-certs.sh
docker compose restart nginx
```

### 5. Containers Can't Resolve Each Other (DNS Issues)

**Symptoms**: Services fail with "Name or service not known" or "could not resolve host" errors when trying to reach other containers by name.

**Cause**: Container is not on the correct Docker network, or Docker's internal DNS is having issues.

**Fix**:
```bash
# Verify networks exist
docker network ls | grep -E "identity|monitoring"

# Check which network each container is on
docker inspect zt-flask-app --format '{{json .NetworkSettings.Networks}}' | python3 -m json.tool

# Verify DNS resolution inside a container
docker compose exec flask-app python3 -c "import socket; print(socket.gethostbyname('keycloak'))"

# Recreate networks (nuclear option)
docker compose down
docker network prune -f
docker compose up -d
```

### General Debug Commands

```bash
# View all container statuses
docker compose ps -a

# Follow logs for all services
docker compose logs -f

# Follow logs for a specific service
docker compose logs -f keycloak

# Enter a container for debugging
docker compose exec flask-app /bin/sh
docker compose exec keycloak /bin/bash

# Check resource usage
docker stats --no-stream

# Full reset (WARNING: destroys all data)
docker compose down -v --remove-orphans
docker system prune -f
docker compose up -d
```
