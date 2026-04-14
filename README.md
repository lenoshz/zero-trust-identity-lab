# 🔐 Zero Trust Identity & Secrets Management Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-v2-blue)](https://docs.docker.com/compose/)
[![Keycloak](https://img.shields.io/badge/Keycloak-24.0.4-orange)](https://www.keycloak.org/)
[![OpenBao](https://img.shields.io/badge/OpenBao-2.0.0-yellow)](https://openbao.org/)

## Overview

A production-like **Zero Trust Identity & Access Management (IAM)** platform demonstrating enterprise security architecture using **Keycloak SSO** (OpenID Connect), **OpenBao** secrets management, **Nginx** reverse proxy with TLS, and **ELK Stack** SIEM integration with real-time identity threat dashboards. Every design decision follows Zero Trust principles: **never trust, always verify**.

This project is a fully containerized, single-command deployment that mirrors the identity security stack used in enterprise environments — built as a portfolio piece demonstrating hands-on IAM engineering skills.

---

## Architecture

```
                           ┌──────────────────────────────────────────────┐
                           │           ZERO TRUST BOUNDARY                │
   ┌──────────┐            │                                              │
   │          │   HTTPS    │  ┌──────────────────────────────────────┐    │
   │ Browser  │ ─────────► │  │         Nginx (TLS Gateway)         │    │
   │ (User)   │  :443      │  │   Security Headers · JSON Logs      │    │
   │          │ ◄───────── │  └──────┬──────────┬──────────┬────────┘    │
   └──────────┘            │         │          │          │             │
                           │         ▼          ▼          ▼             │
                           │  ┌──────────┐ ┌─────────┐ ┌────────┐      │
                           │  │ Keycloak │ │  Flask   │ │ Kibana │      │
                           │  │  (IdP)   │ │  App    │ │ (SIEM) │      │
                           │  │ OIDC/SSO │ │ :5000   │ │ :5601  │      │
                           │  │ :8080    │ │         │ │        │      │
                           │  └────┬─────┘ └───┬─────┘ └───┬────┘      │
                           │       │           │           │            │
                           │       ▼           ▼           │            │
                           │  ┌──────────┐ ┌─────────┐    │            │
                           │  │PostgreSQL│ │ OpenBao │    │            │
                           │  │  (DB)    │ │(Secrets)│    │            │
                           │  │ :5432    │ │ :8200   │    │            │
                           │  └──────────┘ └─────────┘    │            │
                           │                               │            │
                           │  ┌────────────────────────────┴──────┐    │
                           │  │  Filebeat → Elasticsearch :9200   │    │
                           │  │  (Log Pipeline)                    │    │
                           │  └───────────────────────────────────┘    │
                           └──────────────────────────────────────────────┘

Network Isolation:
  identity-net     ──── Keycloak, Flask, Nginx, PostgreSQL, OpenBao
  monitoring-net   ──── Elasticsearch, Kibana, Filebeat, Nginx
```

> 📘 See [ARCHITECTURE.md](ARCHITECTURE.md) for a detailed technical breakdown of each component and data flow.

---

## Zero Trust Principles Implemented

| Principle | Implementation |
|-----------|---------------|
| 🔍 **Never Trust, Always Verify** | Every request authenticated via Keycloak OIDC tokens |
| 🔒 **Least Privilege** | RBAC roles with scoped OpenBao policies (`flask-app-policy`) |
| ⏱️ **Short-Lived Tokens** | Access tokens: 5 minutes · Sessions: 1 hour max |
| 🔑 **Secrets Never Hardcoded** | All secrets fetched at runtime from OpenBao KV engine |
| 📊 **All Access Logged** | Keycloak events + Nginx logs shipped to ELK for SIEM analysis |
| 🛡️ **TLS Everywhere** | Nginx enforces HTTPS with HSTS, CSP, and security headers |
| 🔐 **MFA Ready** | TOTP/OTP configured as an available action in Keycloak |
| 🌐 **Network Isolation** | Docker networks separate identity and monitoring traffic |

---

## Tech Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| Identity Provider | Keycloak | 24.0.4 | SSO, OIDC, RBAC, MFA |
| Secrets Engine | OpenBao | 2.0.0 | KV secrets management |
| Reverse Proxy | Nginx | 1.25-alpine | TLS termination, security headers |
| Demo Application | Flask (Python) | 3.0.3 | OIDC-protected web app |
| Database | PostgreSQL | 16-alpine | Keycloak persistent store |
| Search Engine | Elasticsearch | 8.13.4 | Log storage & analysis |
| Dashboards | Kibana | 8.13.4 | SIEM visualization |
| Log Shipper | Filebeat | 8.13.4 | Log collection & forwarding |
| Orchestration | Docker Compose | v2 | Container orchestration |

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) (20.10+)
- [Docker Compose](https://docs.docker.com/compose/install/) v2
- OpenSSL (for certificate generation)
- 8GB+ RAM recommended (Elasticsearch needs ~512MB)

### Deploy

```bash
# Clone the repository
git clone https://github.com/lenoshz/zero-trust-identity-lab.git
cd zero-trust-identity-lab

# Make scripts executable
chmod +x scripts/bootstrap.sh

# Deploy everything with a single command
./scripts/bootstrap.sh
```

> ⚠️ **Self-signed certificates**: Accept the browser security warning when accessing `https://localhost`.

### Manual Setup (if not using bootstrap.sh)

```bash
# 1. Generate TLS certificates
chmod +x nginx/ssl/generate-certs.sh
./nginx/ssl/generate-certs.sh

# 2. Start all services
docker compose up -d

# 3. Wait for services to be healthy (~90 seconds)
docker compose ps

# 4. Seed OpenBao secrets
chmod +x openbao/init/setup.sh
./openbao/init/setup.sh

# 5. Check health
chmod +x scripts/healthcheck.sh
./scripts/healthcheck.sh
```

---

## Service URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| 🌐 Demo Application | `https://localhost/app` | See demo users below |
| 🔐 Keycloak Login | `https://localhost/auth` | Demo users below |
| ⚙️ Keycloak Admin Console | `https://localhost/auth/admin` | `admin` / `Admin@ZeroTrust1` |
| 📊 Kibana SIEM | `https://localhost/kibana` | `elastic` / `Elastic@ZeroTrust1` |
| 🔑 OpenBao UI | `http://localhost:8200` | Token: `root-dev-token-zerotrust` |

### Demo Users

| Username | Password | Role | Access Level |
|----------|----------|------|-------------|
| `ztadmin` | `Admin@123` | `zero-trust-admin` | Full administrative access |
| `ztuser` | `User@123` | `zero-trust-user` | Standard read/write access |
| `ztviewer` | `View@123` | `zero-trust-readonly` | Read-only access |

---

## Demo Walkthrough

### 1. Authenticate via Keycloak OIDC

Navigate to `https://localhost/app` and click **"Authenticate with Keycloak"**. You'll be redirected to the Keycloak login page.

### 2. Log in as a Demo User

Sign in as `ztuser` with password `User@123`. Keycloak issues a short-lived JWT access token (5-minute TTL) and redirects you back to the Flask app.

### 3. View the Identity Dashboard

The dashboard displays:
- Your authenticated username and email
- Assigned Zero Trust roles (from Keycloak token claims)
- Token expiry countdown
- OpenBao connection status

### 4. View Secrets from OpenBao

Navigate to `/secrets` to see application secrets fetched in real-time from OpenBao's KV v2 engine. All values are masked — they're never exposed in source code or environment variables.

### 5. Generate SIEM Events

- **Failed login**: Try logging in with the wrong password — Keycloak logs a `LOGIN_ERROR` event
- **Admin action**: Access the Keycloak admin console — logs `ADMIN_EVENT`
- **404 errors**: Access a non-existent URL — Nginx logs generate 4xx entries

All events flow through: **Keycloak/Nginx → Filebeat → Elasticsearch → Kibana**

### 6. View Kibana Dashboards

Navigate to `https://localhost/kibana` and explore the `zerotrust-logs-*` index pattern to see real-time identity events.

---

## Screenshots

> 📸 After deploying the lab, take screenshots of the following and add them to `docs/screenshots/`:
> 
> 1. Flask app landing page showing system status
> 2. Keycloak OIDC login page
> 3. Identity dashboard showing token issued/expires/remaining + status chip
> 4. Secrets page with masked OpenBao values
> 5. Admin page RBAC guard (`/app/admin`) for admin role
> 6. Audit log panel with login/logout/secrets/admin events
> 7. Live health panel showing response code, latency, and checked timestamp
> 8. Kibana dashboard showing identity events

---

## Security Architecture Deep Dive

### How Keycloak Enforces Zero Trust

Keycloak serves as the centralized Identity Provider (IdP) using OpenID Connect:
- **Short-lived JWT tokens** (5-minute access token lifespan) minimize the window of compromise
- **Role-Based Access Control (RBAC)** with three granular roles: admin, user, readonly
- **Brute force protection** locks accounts after 5 failed attempts
- **Password policy** enforces complexity (8+ chars, uppercase, digit, special char)
- **TOTP/MFA** is configured and available for all users
- **Event logging** captures all login attempts, admin actions, and token exchanges

### How OpenBao Manages Secrets

OpenBao (open-source Vault fork) provides runtime secret management:
- Secrets are stored in a **KV v2 secrets engine** — versioned and auditable
- The Flask app fetches secrets via **HTTP API** at startup and on demand
- A scoped **flask-app-policy** restricts access to only `secret/data/flask-app/*`
- **No secrets exist in source code, Dockerfiles, or environment variables**
- In production, AppRole or Kubernetes auth would replace the dev token

### How Nginx Acts as Zero Trust Enforcement Layer

Nginx serves as the TLS gateway and security boundary:
- **TLS termination** — all external traffic is HTTPS-only (HTTP 301 → HTTPS)
- **Security headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- **Proxy headers**: X-Forwarded-For, X-Real-IP for audit trails
- **JSON access logs** enable structured parsing by Filebeat
- **Custom error pages** (403, 502) with branded Zero Trust messaging

### How ELK Provides Real-Time Threat Visibility

The ELK Stack creates a SIEM pipeline for identity threat monitoring:
- **Filebeat** ships Keycloak and Nginx logs to Elasticsearch
- **Elasticsearch** indexes events with the `zerotrust-logs-*` pattern
- **Kibana** provides dashboards for:
  - Failed login attempts over time (detect brute force)
  - Successful logins by user (detect anomalous access)
  - Admin actions log (detect privilege escalation)
  - Nginx 4xx/5xx errors (detect scanning/attacks)

> See [docs/setup-guide.md](docs/setup-guide.md) for Kibana dashboard creation steps.

---

## Project Structure

```
zero-trust-identity-lab/
├── docker-compose.yml          # Full stack orchestration
├── .env                        # Environment secrets (gitignored)
├── .env.example                # Template with placeholder values
├── README.md                   # This file
├── ARCHITECTURE.md             # Detailed architecture documentation
├── nginx/
│   ├── nginx.conf              # TLS reverse proxy configuration
│   └── ssl/
│       └── generate-certs.sh   # Self-signed certificate generator
├── keycloak/
│   ├── realm-export.json       # Pre-configured realm with users/roles
│   └── themes/                 # Custom theme placeholder
├── openbao/
│   ├── config/openbao.hcl      # Server configuration
│   └── init/setup.sh           # Secret seeding script
├── flask-app/
│   ├── Dockerfile              # Python 3.12 container image
│   ├── requirements.txt        # Pinned Python dependencies
│   ├── app.py                  # OIDC + OpenBao integration
│   └── templates/              # Bootstrap 5 HTML templates
├── elk/
│   ├── elasticsearch/          # ES single-node config
│   ├── kibana/                 # Kibana config with base path
│   └── filebeat/               # Log shipping configuration
├── scripts/
│   ├── bootstrap.sh            # One-command deployment
│   ├── keycloak-configure.sh   # Realm verification
│   └── healthcheck.sh          # Service status checker
└── docs/
    ├── screenshots/            # UI screenshots (post-deployment)
    ├── zero-trust-flow.md      # Authentication flow diagram
    └── setup-guide.md          # Detailed setup & Kibana guide
```

---

## Troubleshooting

See [docs/setup-guide.md](docs/setup-guide.md) for detailed troubleshooting, including:
- Docker networking issues
- Keycloak startup failures
- Certificate problems
- Elasticsearch heap issues
- OpenBao connection errors

### Keycloak Client Settings (flask-demo-app)

If OIDC login loops, callback fails, or shows invalid redirect errors, verify the `flask-demo-app` client in Keycloak:

- Client type / access type: **Confidential**
- Client authentication: **Enabled**
- Valid redirect URIs:
  - `https://localhost/app/callback`
  - `https://localhost/app/*`
  - `http://localhost:5000/callback` (optional direct fallback)
- Web origins:
  - `https://localhost`
  - `http://localhost:5000` (optional)

These values must match the Flask app OIDC environment values from `docker-compose.yml`.

### OIDC Diagnostics Commands

```bash
docker compose logs --tail=200 flask-app
docker compose logs --tail=200 nginx
curl -kI https://localhost/auth/realms/zero-trust-realm/.well-known/openid-configuration
curl -kI https://localhost/app/
```

Expected quick checks:
- Discovery endpoint returns `HTTP/1.1 200 OK`
- App endpoint returns `HTTP/1.1 200 OK`
- Flask logs show resolved OIDC settings and login redirect URI
- Nginx logs show `/auth/` and `/app/` requests without upstream resolution crashes

### Token Timing, RBAC, and Audit Verification

```bash
# 1) Verify session token timing fields are populated after login callback
docker compose logs --tail=200 flask-app

# 2) Verify app health endpoint includes live check metadata
curl -k https://localhost/app/health

# 3) Verify RBAC guards
#   - /app/secrets allows zero-trust-admin and zero-trust-user
#   - /app/admin allows zero-trust-admin only
curl -kI https://localhost/app/secrets
curl -kI https://localhost/app/admin

# 4) Verify OpenBao access with app-scoped token from Flask container
docker compose exec -T flask-app python -c "import requests; tok=open('/run/secrets/openbao/flask-app-token','r',encoding='utf-8').read().strip(); base='http://openbao:8200/v1'; hdr={'X-Vault-Token':tok}; print('db',requests.get(f'{base}/secret/data/flask-app/db',headers=hdr,timeout=5).status_code); print('api',requests.get(f'{base}/secret/data/flask-app/api',headers=hdr,timeout=5).status_code); print('config',requests.get(f'{base}/secret/data/flask-app/config',headers=hdr,timeout=5).status_code)"
```

Expected:
- Dashboard shows issued time, expiry time, remaining countdown, and token status chip (`VALID`, `EXPIRING SOON`, or `EXPIRED`)
- Expired sessions redirect to sign-in-required page with a clear message
- `/app/admin` redirects to auth-required page when role policy fails
- Audit panel records login, secrets access, admin access, logout, and expiry/denied events
- Health panel displays per-service response code, latency (ms), and checked timestamp

### Quick Fixes

```bash
# View all container logs
docker compose logs -f

# Restart a specific service
docker compose restart keycloak

# Full reset (WARNING: destroys all data)
docker compose down -v && docker compose up -d

# Check container health
docker compose ps
```

---

## CV-Ready Description

> **Project:** Zero Trust Identity & Secrets Management Lab  
> Designed and deployed a Zero Trust identity platform using Keycloak 24 (IAM/SSO/OIDC), OpenBao (secrets management), and Nginx (TLS reverse proxy) orchestrated via Docker Compose. Implemented RBAC, MFA, and short-lived JWT access tokens. Built a Python/Flask demo application that fetches secrets dynamically from OpenBao at runtime — no credentials in code or environment variables. Forwarded Keycloak audit logs and Nginx access logs to Elasticsearch via Filebeat and built Kibana dashboards for real-time identity threat monitoring. Stack mirrors enterprise Zero Trust deployments used in Identity Security Engineering roles.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>🔐 Never Trust. Always Verify. 🔐</strong>
</p>
