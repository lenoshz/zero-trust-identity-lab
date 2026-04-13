# Zero Trust Authentication Flow

## Overview

This document details the authentication and authorization flows in the Zero Trust Identity Lab, showing how each component enforces the "never trust, always verify" principle.

---

## 1. OIDC Authorization Code Flow

The Flask application uses the **OpenID Connect Authorization Code Flow** — the most secure flow for server-side web applications.

### Why Authorization Code Flow?

| Flow | Security Level | Use Case |
|------|---------------|----------|
| Authorization Code | ✅ Highest | Server-side web apps (this lab) |
| PKCE | ✅ High | SPAs and mobile apps |
| Implicit | ❌ Deprecated | Legacy SPAs (avoid) |
| Client Credentials | ✅ High | Machine-to-machine |

### Step-by-Step Flow

#### Step 1: User Accesses Protected Resource
```
Browser → GET https://localhost/app/dashboard
  ↓
Nginx → Proxy to Flask (http://flask-app:5000/dashboard)
  ↓
Flask → Check session → No token found → Render login_required.html
```

#### Step 2: User Clicks "Sign In"
```
Browser → GET https://localhost/app/login
  ↓
Flask → Generate OIDC authorize URL with:
  - client_id: flask-demo-app
  - redirect_uri: https://localhost/app/callback
  - scope: openid email profile
  - response_type: code
  - state: <random CSRF token>
  ↓
Flask → 302 Redirect to Keycloak
```

#### Step 3: Keycloak Authentication
```
Browser → GET https://localhost/auth/realms/zero-trust-realm/protocol/openid-connect/auth
  ↓
Keycloak → Display login form
  ↓
User → Enter credentials (ztuser / User@123)
  ↓
Keycloak → Validate credentials against PostgreSQL
  ↓
Keycloak → Check brute force protection (< 5 failures?)
  ↓
Keycloak → Check MFA (TOTP optional for demo users)
  ↓
Keycloak → Generate authorization code
  ↓
Keycloak → Log LOGIN event (shipped to ELK)
  ↓
Keycloak → 302 Redirect to redirect_uri with code
```

#### Step 4: Token Exchange (Server-to-Server)
```
Flask → POST to http://keycloak:8080/realms/zero-trust-realm/protocol/openid-connect/token
  Body:
    - grant_type: authorization_code
    - code: <authorization code from step 3>
    - client_id: flask-demo-app
    - client_secret: flask-demo-secret-2024
    - redirect_uri: https://localhost/app/callback
  ↓
Keycloak → Validate code, client credentials, redirect_uri
  ↓
Keycloak → Issue tokens:
  - access_token (JWT, 5-min TTL)
  - id_token (JWT, user identity claims)
  - refresh_token (longer-lived, for token renewal)
  ↓
Flask → Store tokens in server-side session
  ↓
Flask → 302 Redirect to /dashboard
```

#### Step 5: Authenticated Access
```
Browser → GET https://localhost/app/dashboard (with session cookie)
  ↓
Flask → Check session → Token found → Decode JWT claims
  ↓
Flask → Extract: username, email, roles, expiry
  ↓
Flask → Render dashboard.html with user info
```

---

## 2. Token Structure

### Access Token (JWT) Claims

```json
{
  "exp": 1713100800,           // Expires in 5 minutes
  "iat": 1713100500,           // Issued at
  "jti": "uuid",               // Unique token ID
  "iss": "http://keycloak:8080/realms/zero-trust-realm",
  "sub": "user-uuid",          // Subject (user ID)
  "typ": "Bearer",
  "azp": "flask-demo-app",     // Authorized party (client)
  "acr": "1",                  // Authentication context class
  "realm_access": {
    "roles": [
      "zero-trust-user",       // Realm role
      "default-roles-zero-trust-realm"
    ]
  },
  "resource_access": {
    "flask-demo-app": {
      "roles": ["app-user"]    // Client-specific role
    }
  },
  "scope": "openid email profile",
  "preferred_username": "ztuser",
  "email": "ztuser@zerotrust.local"
}
```

### Zero Trust Token Properties

| Property | Value | Security Rationale |
|----------|-------|-------------------|
| Access Token TTL | 5 minutes | Minimize window of compromise |
| Session Max | 1 hour | Force re-authentication |
| Token Type | JWT | Cryptographically signed, self-validating |
| Signing Algorithm | RS256 | Asymmetric — only Keycloak can sign |
| Audience | `flask-demo-app` | Token only valid for intended client |

---

## 3. Logout Flow

```
Browser → GET https://localhost/app/logout
  ↓
Flask → Clear server-side session
  ↓
Flask → 302 Redirect to Keycloak end-session endpoint:
  - id_token_hint: <id_token>
  - post_logout_redirect_uri: https://localhost/app/
  ↓
Keycloak → Invalidate SSO session
  ↓
Keycloak → Log LOGOUT event
  ↓
Keycloak → 302 Redirect back to Flask landing page
```

---

## 4. Failed Login Flow (SIEM Event Generation)

```
Browser → Enter wrong password
  ↓
Keycloak → Validate credentials → FAIL
  ↓
Keycloak → Increment failure counter (brute force protection)
  ↓
Keycloak → Log LOGIN_ERROR event to /var/log/keycloak/keycloak.log
  ↓
Filebeat → Detect new log entry
  ↓
Filebeat → Parse, add source=keycloak field
  ↓
Filebeat → Ship to Elasticsearch (zerotrust-logs-*)
  ↓
Kibana → Display on "Failed Login Attempts" dashboard panel
```

After 5 consecutive failures, Keycloak temporarily locks the account (brute force protection).

---

## 5. Role-Based Access Control (RBAC)

### Role Hierarchy

| Role | Permissions | Users |
|------|------------|-------|
| `zero-trust-admin` | Full access, admin operations | ztadmin |
| `zero-trust-user` | Read/write application access | ztuser |
| `zero-trust-readonly` | Read-only access | ztviewer |

### Role Enforcement Points

1. **Keycloak**: Assigns roles to users, embeds in JWT claims
2. **Flask App**: Reads roles from `realm_access.roles` in the JWT
3. **OpenBao**: Policy-based access (independent of Keycloak roles in this demo)

In production, OpenBao policies would map to Keycloak roles via JWT authentication backend.
