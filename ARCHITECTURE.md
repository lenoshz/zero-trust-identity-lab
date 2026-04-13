# Zero Trust Architecture — Technical Deep Dive

## Table of Contents

1. [What is Zero Trust?](#what-is-zero-trust)
2. [Service-by-Service Breakdown](#service-by-service-breakdown)
3. [Authentication Flow (OIDC)](#authentication-flow-oidc)
4. [Secrets Management Flow](#secrets-management-flow)
5. [Log Pipeline Flow](#log-pipeline-flow)
6. [Network Isolation](#network-isolation)

---

## What is Zero Trust?

Zero Trust is a security framework that eliminates implicit trust from network architecture. Instead of the traditional "castle and moat" model where everything inside the network is trusted, Zero Trust operates on three core principles:

1. **Never trust, always verify** — Every request must be authenticated and authorized, regardless of source
2. **Assume breach** — Design systems as if an attacker is already inside
3. **Least privilege access** — Grant only the minimum permissions required

### Why It Matters

Traditional perimeter-based security fails because:
- Attackers breach perimeters regularly (phishing, supply chain attacks)
- Internal lateral movement goes undetected
- Over-privileged accounts create blast radius for compromise
- Credentials embedded in code or config files become attack vectors

Zero Trust addresses these by making identity the new perimeter, encrypting all traffic, validating every access request, and continuously monitoring for threats.

### This Lab Demonstrates

| Zero Trust Control | Implementation |
|---|---|
| Identity verification | Keycloak OIDC with short-lived JWTs |
| Least privilege | RBAC roles + OpenBao scoped policies |
| Encryption in transit | Nginx TLS with HSTS |
| Secrets management | OpenBao runtime secret injection |
| Continuous monitoring | ELK Stack SIEM with identity event logging |
| MFA readiness | TOTP configured in Keycloak |
| Session controls | 5-minute tokens, 1-hour sessions |

---

## Service-by-Service Breakdown

### 1. Nginx (TLS Reverse Proxy)

**Role**: Zero Trust gateway and enforcement layer

Nginx serves as the single entry point for all external traffic:

- **TLS Termination**: All external connections are HTTPS (port 443). HTTP (port 80) is 301-redirected to HTTPS.
- **Security Headers**: HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
- **Proxy Routing**: Routes traffic to Keycloak (`/auth/`), Flask (`/app/`), and Kibana (`/kibana/`)
- **Audit Logging**: JSON-formatted access logs enable structured parsing by Filebeat
- **Proxy Headers**: X-Forwarded-For, X-Real-IP propagate client identity for auditability

### 2. Keycloak (Identity Provider)

**Role**: Centralized Identity and Access Management

Keycloak handles all authentication and authorization:

- **OIDC/SSO**: OpenID Connect protocol for single sign-on across services
- **Realm**: `zero-trust-realm` — isolated tenant with its own users, roles, and policies
- **RBAC Roles**: `zero-trust-admin`, `zero-trust-user`, `zero-trust-readonly`
- **Short-Lived Tokens**: Access tokens expire in 5 minutes (Zero Trust principle)
- **Session Control**: Maximum session lifespan of 1 hour
- **Password Policy**: Minimum 8 characters, 1 uppercase, 1 digit, 1 special character
- **Brute Force Protection**: Account lockout after 5 failed login attempts
- **MFA**: TOTP (Time-based One-Time Password) configured as an optional action
- **Event Logging**: Login events, admin events, and errors logged for SIEM analysis
- **Persistence**: User data stored in PostgreSQL (survives container restarts)

### 3. PostgreSQL (Database)

**Role**: Persistent storage for Keycloak

- Stores user credentials, realm configuration, sessions, and audit logs
- Alpine-based image for minimal footprint
- Data persisted via Docker volume (`postgres_data`)
- Only accessible on the `identity-net` network (not exposed externally in production)

### 4. OpenBao (Secrets Management)

**Role**: Runtime secrets engine

OpenBao (open-source fork of HashiCorp Vault) provides dynamic secrets management:

- **KV v2 Engine**: Versioned key-value store at `secret/flask-app/*`
- **Scoped Policies**: `flask-app-policy` restricts access to only the app's secrets
- **HTTP API**: Flask fetches secrets via REST API at startup and on demand
- **No Hardcoded Secrets**: Application credentials are never in source code or environment variables
- **Dev Mode**: Uses an in-memory backend with a known root token (dev/lab only)
- **Stored Secrets**:
  - `secret/flask-app/db` — Database credentials
  - `secret/flask-app/api` — API keys and endpoints
  - `secret/flask-app/config` — Application configuration

### 5. Flask Application (Demo App)

**Role**: Zero Trust-protected web application

The Flask app demonstrates the complete authentication and secrets flow:

- **OIDC Integration**: Uses Authlib to integrate with Keycloak for authentication
- **Protected Routes**: Dashboard and secrets pages require valid Keycloak tokens
- **Runtime Secrets**: Fetches configuration from OpenBao at startup
- **Graceful Degradation**: Shows error cards (not crashes) if Keycloak or OpenBao is unreachable
- **Session Management**: Stores JWT tokens in server-side sessions
- **Value Masking**: Secrets displayed on the dashboard are masked (`****`)

### 6. Elasticsearch (Search & Analytics)

**Role**: Log storage and search engine for SIEM

- **Single Node**: Development-appropriate deployment
- **Security**: Basic authentication enabled (elastic/password)
- **Heap**: Capped at 512MB for laptop-friendly operation
- **Index Pattern**: `zerotrust-logs-YYYY.MM.DD`

### 7. Kibana (Visualization)

**Role**: SIEM dashboard and threat visualization

- **Base Path**: Accessible via `/kibana/` through Nginx
- **Dashboards**: Identity threat monitoring panels
- **Security**: Authenticated via `kibana_system` user

### 8. Filebeat (Log Shipper)

**Role**: Ship logs from Keycloak and Nginx to Elasticsearch

- **Inputs**: Keycloak logs, Nginx access/error logs
- **JSON Parsing**: Parses structured JSON logs from Nginx
- **Docker Autodiscovery**: Also collects container stdout/stderr
- **Field Tagging**: Adds `source=keycloak` or `source=nginx` for filtering

---

## Authentication Flow (OIDC)

The following sequence describes the OpenID Connect authorization code flow used in this lab:

```
┌──────┐     ┌───────┐      ┌──────────┐      ┌──────────┐
│Browser│     │ Nginx │      │  Flask   │      │ Keycloak │
└──┬───┘     └──┬────┘      └───┬──────┘      └───┬──────┘
   │            │               │                  │
   │ 1. GET /app/dashboard     │                  │
   │ ──────────►│               │                  │
   │            │ 2. Proxy      │                  │
   │            │──────────────►│                  │
   │            │               │                  │
   │            │  3. No token → 302 Redirect     │
   │ ◄──────────┼───────────────┤                  │
   │            │               │                  │
   │ 4. GET /auth/realms/.../auth?client_id=...   │
   │ ─────────────────────────────────────────────►│
   │            │               │                  │
   │            │     5. Keycloak Login Page       │
   │ ◄─────────────────────────────────────────────┤
   │            │               │                  │
   │ 6. POST credentials (username/password)      │
   │ ─────────────────────────────────────────────►│
   │            │               │                  │
   │            │     7. Validate + Issue Code     │
   │ ◄──────────┼───────────────┼──────────────────┤
   │            │               │     (302 + auth code)
   │ 8. GET /app/callback?code=...                │
   │ ──────────►│               │                  │
   │            │──────────────►│                  │
   │            │               │                  │
   │            │               │ 9. Exchange code │
   │            │               │    for tokens    │
   │            │               │─────────────────►│
   │            │               │                  │
   │            │               │ 10. JWT tokens   │
   │            │               │◄─────────────────┤
   │            │               │  (access_token,  │
   │            │               │   id_token,      │
   │            │               │   refresh_token) │
   │            │               │                  │
   │            │ 11. Store in  │                  │
   │            │     session   │                  │
   │            │               │                  │
   │  12. 302 → /app/dashboard │                  │
   │ ◄──────────┼───────────────┤                  │
   │            │               │                  │
   │ 13. GET /app/dashboard (with session)        │
   │ ──────────►│──────────────►│                  │
   │            │               │                  │
   │  14. Dashboard HTML with user info           │
   │ ◄──────────┼───────────────┤                  │
```

### Key Security Properties

1. **Authorization Code Flow**: The browser never sees the access token directly during the initial exchange
2. **Server-Side Token Storage**: Tokens are stored in Flask's server-side session, not in browser cookies or localStorage
3. **Short Token Lifespan**: 5-minute access tokens minimize the impact of token theft
4. **Token Validation**: Keycloak validates credentials and issues cryptographically signed JWTs
5. **HTTPS Only**: All browser communication is encrypted via Nginx TLS

---

## Secrets Management Flow

```
┌──────────┐      ┌───────────┐
│  Flask   │      │  OpenBao  │
│   App    │      │  (Vault)  │
└───┬──────┘      └───┬───────┘
    │                 │
    │ 1. GET /v1/secret/data/flask-app/config
    │    Header: X-Vault-Token: <token>
    │────────────────►│
    │                 │
    │                 │ 2. Validate token
    │                 │    Check policy
    │                 │    (flask-app-policy allows read)
    │                 │
    │ 3. 200 OK      │
    │  { "data": {   │
    │    "environment": "production",
    │    "debug": "false",
    │    "log_level": "INFO"
    │  }}             │
    │◄────────────────┤
    │                 │
    │ 4. Store in memory
    │    Display masked on dashboard
    │    (pr****ion, fa**e, IN**)
```

### Security Properties

1. **Runtime Fetching**: Secrets are fetched via HTTP at startup, never baked into images or configs
2. **Policy Scoping**: The `flask-app-policy` only allows `read` on `secret/data/flask-app/*`
3. **Value Masking**: Secrets displayed on the UI are masked — only first 2 characters shown
4. **No Env Var Leaking**: While the OpenBao token is in an env var for this demo, production would use AppRole auth
5. **KV v2 Versioning**: Secret changes are versioned, enabling audit trails

---

## Log Pipeline Flow

```
┌──────────┐    ┌──────────┐    ┌───────────────┐    ┌──────────┐
│ Keycloak │    │  Nginx   │    │   Filebeat    │    │  Elastic │
│  Events  │    │   Logs   │    │  (Shipper)    │    │  Search  │
└───┬──────┘    └───┬──────┘    └──────┬────────┘    └───┬──────┘
    │               │                  │                 │
    │ 1. Login      │                  │                 │
    │    event      │ 2. Access        │                 │
    │    written    │    log (JSON)    │                 │
    │    to file    │    written       │                 │
    │               │                  │                 │
    ▼               ▼                  │                 │
  /var/log/       /var/log/           │                 │
  keycloak/       nginx/              │                 │
  keycloak.log    access.log          │                 │
    │               │                  │                 │
    └───────────────┘                  │                 │
              │                        │                 │
              │  3. Filebeat tails     │                 │
              │     log files          │                 │
              └───────────────────────►│                 │
                                       │                 │
                                       │ 4. Parse JSON   │
                                       │    Add fields   │
                                       │    (source=...)  │
                                       │                 │
                                       │ 5. Ship to ES   │
                                       │────────────────►│
                                       │                 │
                                       │                 │ 6. Index as
                                       │                 │    zerotrust-
                                       │                 │    logs-*
                                       │                 │
                                       │                 ▼
                                       │            ┌──────────┐
                                       │            │  Kibana  │
                                       │            │  (SIEM)  │
                                       │            └──────────┘
                                       │              7. Visualize
                                       │                 dashboards
```

### Event Types Captured

| Source | Event Type | Zero Trust Relevance |
|--------|-----------|---------------------|
| Keycloak | `LOGIN` | Successful authentication tracking |
| Keycloak | `LOGIN_ERROR` | Failed login / brute force detection |
| Keycloak | `LOGOUT` | Session termination tracking |
| Keycloak | `ADMIN_EVENT` | Privilege escalation monitoring |
| Keycloak | `CODE_TO_TOKEN` | Token exchange audit |
| Keycloak | `UPDATE_PASSWORD` | Credential change tracking |
| Nginx | Access log | All HTTP requests with status codes |
| Nginx | Error log | Gateway errors, upstream failures |

---

## Network Isolation

Docker networks enforce microsegmentation — a key Zero Trust principle:

### identity-net

Services that handle authentication, authorization, and application logic:

| Service | Justification |
|---------|--------------|
| Keycloak | Identity provider — core service for authentication |
| PostgreSQL | Keycloak's database — should only be reachable by Keycloak |
| Flask App | Needs to communicate with Keycloak (token validation) and OpenBao (secrets) |
| OpenBao | Secrets engine — accessed by Flask for runtime secrets |
| Nginx | Gateway — must proxy traffic to Keycloak and Flask |

### monitoring-net

Services that handle log aggregation and SIEM:

| Service | Justification |
|---------|--------------|
| Elasticsearch | Log storage — only Filebeat and Kibana need access |
| Kibana | Visualization — queries Elasticsearch |
| Filebeat | Log shipper — sends to Elasticsearch |
| Nginx | Gateway — proxies traffic to Kibana + provides access logs to Filebeat |

### Why Separate Networks?

1. **Blast Radius Reduction**: If Elasticsearch is compromised, the attacker cannot reach Keycloak or PostgreSQL
2. **Principle of Least Communication**: Services only communicate with the services they actually need
3. **Nginx as Bridge**: The only service on both networks, acting as a controlled gateway
4. **Defense in Depth**: Even if an attacker escapes a container, network isolation limits movement

---

## Production Considerations

This lab is designed for learning and demonstration. In a production environment, you would also implement:

1. **Hardware Security Modules (HSMs)** for storing Keycloak and OpenBao master keys
2. **Mutual TLS (mTLS)** between all services, not just external-facing
3. **OpenBao Auto-Unseal** via cloud KMS (AWS KMS, Azure Key Vault, GCP KMS)
4. **Certificate Authority** (e.g., Let's Encrypt, internal CA) instead of self-signed certs
5. **High Availability** — clustered Keycloak, multi-node Elasticsearch
6. **AppRole Authentication** in OpenBao instead of root token
7. **Secret Rotation** policies with dynamic database credentials
8. **WAF/API Gateway** (e.g., Kong, AWS API Gateway) in front of Nginx
9. **SIEM Alerting** rules in Elasticsearch for automated incident response
10. **Kubernetes** deployment with pod security policies and network policies
