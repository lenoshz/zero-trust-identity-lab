"""
Zero Trust Identity Lab — Flask Demo Application
═══════════════════════════════════════════════════
Demonstrates OIDC authentication via Keycloak and
runtime secret fetching from OpenBao.
"""

import os
import json
import logging
from datetime import datetime, timezone

from flask import (
    Flask, redirect, url_for, session, render_template,
    jsonify, request
)
from authlib.integrations.flask_client import OAuth
import requests as http_requests

# ═══════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-fallback-key")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("zero-trust-app")

# Keycloak / OIDC settings
KC_REALM = os.environ.get("FLASK_KEYCLOAK_REALM", "zero-trust-realm")
KC_CLIENT_ID = os.environ.get("FLASK_KEYCLOAK_CLIENT_ID", "flask-demo-app")
KC_CLIENT_SECRET = os.environ.get("FLASK_KEYCLOAK_CLIENT_SECRET", "flask-demo-secret-2024")
DOMAIN = os.environ.get("DOMAIN", "localhost")

# Internal Keycloak URL (container-to-container)
KC_INTERNAL_URL = f"http://keycloak:8080/realms/{KC_REALM}"
# External Keycloak URL (browser-facing, via Nginx)
KC_EXTERNAL_URL = f"https://{DOMAIN}/auth/realms/{KC_REALM}"

# OpenBao settings
OPENBAO_ADDR = os.environ.get("FLASK_OPENBAO_ADDR", "http://openbao:8200")
OPENBAO_TOKEN = os.environ.get("FLASK_OPENBAO_TOKEN", "root-dev-token-zerotrust")

# ═══════════════════════════════════════════════════
# OAuth2 / OIDC Setup (Authlib)
# ═══════════════════════════════════════════════════

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=KC_CLIENT_ID,
    client_secret=KC_CLIENT_SECRET,
    server_metadata_url=f"{KC_INTERNAL_URL}/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile",
    },
    authorize_url=f"{KC_EXTERNAL_URL}/protocol/openid-connect/auth",
    access_token_url=f"{KC_INTERNAL_URL}/protocol/openid-connect/token",
    jwks_uri=f"{KC_INTERNAL_URL}/protocol/openid-connect/certs",
)


# ═══════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════

def check_keycloak_health():
    """Check if Keycloak is reachable."""
    try:
        r = http_requests.get(
            f"http://keycloak:8080/health/ready", timeout=5
        )
        return r.status_code == 200
    except Exception:
        return False


def check_openbao_health():
    """Check if OpenBao is reachable."""
    try:
        r = http_requests.get(
            f"{OPENBAO_ADDR}/v1/sys/health", timeout=5
        )
        return r.status_code == 200
    except Exception:
        return False


def fetch_openbao_secrets(path):
    """Fetch secrets from OpenBao KV v2 engine."""
    try:
        r = http_requests.get(
            f"{OPENBAO_ADDR}/v1/secret/data/{path}",
            headers={"X-Vault-Token": OPENBAO_TOKEN},
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json()
            return data.get("data", {}).get("data", {})
        logger.warning("OpenBao returned %d for %s", r.status_code, path)
        return None
    except Exception as e:
        logger.error("Failed to fetch secrets from OpenBao: %s", e)
        return None


def mask_value(value):
    """Mask a secret value, showing only first 2 characters."""
    s = str(value)
    if len(s) <= 4:
        return "*" * len(s)
    return s[:2] + "*" * (len(s) - 2)


def get_user_info():
    """Extract user info from the session token."""
    token = session.get("token")
    if not token:
        return None

    userinfo = session.get("userinfo", {})
    id_token = token.get("id_token")
    access_token = token.get("access_token")

    # Decode token claims without verification (already verified by Authlib)
    from jose import jwt as jose_jwt
    try:
        claims = jose_jwt.get_unverified_claims(access_token)
    except Exception:
        claims = {}

    # Extract roles
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    # Filter out internal Keycloak roles
    filtered_roles = [
        r for r in realm_roles
        if r.startswith("zero-trust-")
    ]

    # Token expiry
    exp = claims.get("exp")
    if exp:
        expiry_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        expiry_str = expiry_time.strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        expiry_str = "Unknown"

    return {
        "username": userinfo.get("preferred_username", claims.get("preferred_username", "unknown")),
        "email": userinfo.get("email", claims.get("email", "N/A")),
        "name": userinfo.get("name", claims.get("name", "N/A")),
        "roles": filtered_roles,
        "all_roles": realm_roles,
        "token_expiry": expiry_str,
        "token_issued": claims.get("iat", "N/A"),
    }


# ═══════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════

@app.route("/")
def index():
    """Public landing page — system status overview."""
    kc_healthy = check_keycloak_health()
    bao_healthy = check_openbao_health()
    user = get_user_info() if session.get("token") else None

    return render_template(
        "index.html",
        keycloak_status=kc_healthy,
        openbao_status=bao_healthy,
        user=user,
    )


@app.route("/login")
def login():
    """Redirect to Keycloak OIDC login."""
    # Determine callback URL
    redirect_uri = url_for("callback", _external=True, _scheme="https")
    # If behind proxy, fix the URL
    if DOMAIN != "localhost" or request.headers.get("X-Forwarded-Proto"):
        redirect_uri = f"https://{DOMAIN}/app/callback"
    else:
        redirect_uri = f"https://localhost/app/callback"

    logger.info("Initiating OIDC login, redirect_uri=%s", redirect_uri)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.route("/callback")
def callback():
    """Handle OIDC callback from Keycloak."""
    try:
        token = oauth.keycloak.authorize_access_token()
        userinfo = token.get("userinfo", {})

        session["token"] = {
            "access_token": token.get("access_token"),
            "id_token": token.get("id_token"),
            "refresh_token": token.get("refresh_token"),
            "token_type": token.get("token_type"),
            "expires_at": token.get("expires_at"),
        }
        session["userinfo"] = dict(userinfo) if userinfo else {}

        logger.info(
            "User '%s' authenticated successfully",
            userinfo.get("preferred_username", "unknown"),
        )
        return redirect(url_for("dashboard"))
    except Exception as e:
        logger.error("OIDC callback error: %s", e)
        return render_template(
            "login_required.html",
            error=f"Authentication failed: {str(e)}",
        ), 401


@app.route("/dashboard")
def dashboard():
    """Protected dashboard — requires valid Keycloak token."""
    if not session.get("token"):
        return render_template("login_required.html", error=None)

    user = get_user_info()
    if not user:
        return render_template("login_required.html", error="Session expired")

    bao_healthy = check_openbao_health()

    return render_template(
        "dashboard.html",
        user=user,
        openbao_status=bao_healthy,
        active_page="dashboard",
    )


@app.route("/secrets")
def secrets():
    """Protected page — shows OpenBao-fetched secrets (values masked)."""
    if not session.get("token"):
        return render_template("login_required.html", error=None)

    user = get_user_info()
    if not user:
        return render_template("login_required.html", error="Session expired")

    bao_healthy = check_openbao_health()
    secrets_data = {}
    error_msg = None

    if bao_healthy:
        for path in ["flask-app/db", "flask-app/api", "flask-app/config"]:
            fetched = fetch_openbao_secrets(path)
            if fetched:
                secrets_data[path] = {k: mask_value(v) for k, v in fetched.items()}
            else:
                secrets_data[path] = {"error": "Could not fetch"}
    else:
        error_msg = "OpenBao is unreachable. Secrets cannot be displayed."

    return render_template(
        "dashboard.html",
        user=user,
        openbao_status=bao_healthy,
        secrets_data=secrets_data,
        secrets_error=error_msg,
        active_page="secrets",
    )


@app.route("/logout")
def logout():
    """Clear session and redirect to Keycloak logout."""
    id_token = session.get("token", {}).get("id_token")
    session.clear()

    # Redirect to Keycloak end-session endpoint
    if id_token:
        logout_url = (
            f"{KC_EXTERNAL_URL}/protocol/openid-connect/logout"
            f"?id_token_hint={id_token}"
            f"&post_logout_redirect_uri=https://{DOMAIN}/app/"
        )
        return redirect(logout_url)

    return redirect(url_for("index"))


@app.route("/health")
def health():
    """Health check endpoint — returns JSON status."""
    kc_healthy = check_keycloak_health()
    bao_healthy = check_openbao_health()

    return jsonify({
        "status": "ok",
        "keycloak": kc_healthy,
        "openbao": bao_healthy,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ═══════════════════════════════════════════════════
# Startup — Fetch initial config from OpenBao
# ═══════════════════════════════════════════════════

def startup_config():
    """Fetch config from OpenBao at startup and log it."""
    logger.info("Fetching startup configuration from OpenBao...")
    config = fetch_openbao_secrets("flask-app/config")
    if config:
        logger.info(
            "OpenBao config loaded: environment=%s, debug=%s, log_level=%s",
            mask_value(config.get("environment", "?")),
            mask_value(config.get("debug", "?")),
            mask_value(config.get("log_level", "?")),
        )
    else:
        logger.warning("Could not fetch config from OpenBao — will retry on access")


if __name__ == "__main__":
    startup_config()
    app.run(host="0.0.0.0", port=5000, debug=False)
