"""
Zero Trust Identity Lab — Flask Demo Application
═══════════════════════════════════════════════════
Demonstrates OIDC authentication via Keycloak and
runtime secret fetching from OpenBao.
"""

import os
import json
import base64
import logging
from datetime import datetime, timezone
import urllib3

from flask import (
    Flask, redirect, session, render_template, request,
    jsonify
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
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Keycloak / OIDC settings
REALM = os.environ.get("FLASK_KEYCLOAK_REALM", "zero-trust-realm")
KC_CLIENT_ID = os.environ.get("FLASK_KEYCLOAK_CLIENT_ID", "flask-demo-app")
KC_CLIENT_SECRET = os.environ.get("FLASK_KEYCLOAK_CLIENT_SECRET", "flask-demo-secret-2024")
DOMAIN = os.environ.get("DOMAIN", "localhost")
KEYCLOAK_BASE_URL = (os.environ.get("FLASK_KEYCLOAK_BASE_URL") or "http://keycloak:8080/auth").rstrip("/")
REDIRECT_URI = os.environ.get("FLASK_OIDC_REDIRECT_URI") or "https://localhost/app/callback"

# Internal Keycloak URL (container-to-container)
KC_INTERNAL_URL = f"{KEYCLOAK_BASE_URL}/realms/{REALM}"
OIDC_DISCOVERY_URL = f"{KC_INTERNAL_URL}/.well-known/openid-configuration"
# External Keycloak URL (browser-facing, via Nginx)
KC_EXTERNAL_URL = f"https://{DOMAIN}/auth/realms/{REALM}"

logger.info("Resolved OIDC KEYCLOAK_BASE_URL=%s", KEYCLOAK_BASE_URL)
logger.info("Resolved OIDC REALM=%s", REALM)
logger.info("Resolved OIDC discovery URL=%s", OIDC_DISCOVERY_URL)
logger.info("Resolved OIDC REDIRECT_URI=%s", REDIRECT_URI)

# OpenBao settings
OPENBAO_ADDR = os.environ.get("FLASK_OPENBAO_ADDR", "http://openbao:8200")
OPENBAO_TOKEN = os.environ.get("FLASK_OPENBAO_TOKEN", "root-dev-token-zerotrust")
OPENBAO_TOKEN_FILE = os.environ.get("FLASK_OPENBAO_TOKEN_FILE", "/run/secrets/openbao/flask-app-token")
ENABLE_SILENT_REFRESH = os.environ.get("FLASK_ENABLE_SILENT_REFRESH", "false").lower() == "true"
SHOW_HEALTH_DEBUG = os.environ.get("FLASK_SHOW_HEALTH_DEBUG", "false").lower() == "true"
EXPIRING_SOON_SECONDS = int(os.environ.get("FLASK_EXPIRING_SOON_SECONDS", "120"))
AUDIT_LOG_LIMIT = int(os.environ.get("FLASK_AUDIT_LOG_LIMIT", "25"))

# ═══════════════════════════════════════════════════
# OAuth2 / OIDC Setup (Authlib)
# ═══════════════════════════════════════════════════

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=KC_CLIENT_ID,
    client_secret=KC_CLIENT_SECRET,
    server_metadata_url=OIDC_DISCOVERY_URL,
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

def now_unix():
    return int(datetime.now(timezone.utc).timestamp())


def format_unix(ts):
    if not ts:
        return "N/A"
    try:
        return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except Exception:
        return "N/A"


def format_remaining(seconds):
    if seconds is None:
        return "N/A"
    if seconds <= 0:
        return "Expired"
    mins, sec = divmod(int(seconds), 60)
    hours, mins = divmod(mins, 60)
    if hours:
        return f"{hours}h {mins}m {sec}s"
    return f"{mins}m {sec}s"


def decode_jwt_claims(jwt_token):
    """Decode JWT payload without signature validation for UI metadata only."""
    if not jwt_token or jwt_token.count(".") < 2:
        return {}
    try:
        payload = jwt_token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def extract_claims(token):
    claims = {}
    if token.get("id_token"):
        claims.update(decode_jwt_claims(token.get("id_token")))
    if token.get("access_token"):
        claims.update(decode_jwt_claims(token.get("access_token")))

    userinfo = token.get("userinfo", {}) or {}
    for key in ["sub", "preferred_username", "email", "auth_time", "iat", "exp"]:
        if key not in claims and key in userinfo:
            claims[key] = userinfo[key]
    return claims


def extract_roles(claims, client_id):
    realm_roles = claims.get("realm_access", {}).get("roles", [])
    client_roles = claims.get("resource_access", {}).get(client_id, {}).get("roles", [])

    merged = []
    for role in (realm_roles or []) + (client_roles or []):
        if isinstance(role, str):
            normalized = role.strip().lower()
            if normalized:
                merged.append(normalized)

    return sorted(set(merged))


def append_audit_event(action, status="ok", detail=""):
    logs = session.get("audit_logs", [])
    logs.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "status": status,
        "detail": detail,
    })
    session["audit_logs"] = logs[-AUDIT_LOG_LIMIT:]


def clear_auth_session(preserve_audit=True):
    audit_logs = session.get("audit_logs", []) if preserve_audit else []
    session.clear()
    if preserve_audit and audit_logs:
        session["audit_logs"] = audit_logs[-AUDIT_LOG_LIMIT:]


def compute_token_times(token, id_claims):
    current = now_unix()
    source = "fallback"

    iat_raw = id_claims.get("iat")
    exp_raw = id_claims.get("exp")
    auth_time_raw = id_claims.get("auth_time")

    if exp_raw is not None and iat_raw is not None:
        source = "id_token"
    else:
        source = "token_fields"
        exp_raw = token.get("expires_at")
        if not exp_raw and token.get("expires_in"):
            exp_raw = current + int(token.get("expires_in"))
        if iat_raw is None:
            iat_raw = current

    try:
        issued = int(iat_raw) if iat_raw is not None else current
    except Exception:
        issued = current

    try:
        expiry = int(exp_raw) if exp_raw is not None else current + 300
    except Exception:
        expiry = current + 300

    auth_time = None
    if auth_time_raw is not None:
        try:
            auth_time = int(auth_time_raw)
        except Exception:
            auth_time = None

    if expiry <= issued:
        expiry = current + 300

    return issued, expiry, auth_time, source


def probe_endpoint(url, fallback_url=None, timeout=3):
    details = {
        "probe_url": url,
        "fallback_url": None,
        "response_code": None,
        "latency_ms": None,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "healthy": False,
        "exception": None,
    }

    start = datetime.now(timezone.utc)
    try:
        r = http_requests.get(url, timeout=timeout, verify=False)
        elapsed = datetime.now(timezone.utc) - start
        details["response_code"] = r.status_code
        details["latency_ms"] = int(elapsed.total_seconds() * 1000)
        details["healthy"] = 200 <= r.status_code < 400
        return details
    except Exception as e:
        details["exception"] = str(e)
        logger.warning("Health probe exception on primary URL %s: %s", url, e)

    if not fallback_url:
        return details

    details["fallback_url"] = fallback_url
    start = datetime.now(timezone.utc)
    try:
        r = http_requests.get(fallback_url, timeout=timeout, verify=False)
        elapsed = datetime.now(timezone.utc) - start
        details["response_code"] = r.status_code
        details["latency_ms"] = int(elapsed.total_seconds() * 1000)
        details["healthy"] = 200 <= r.status_code < 400
        details["exception"] = None
        return details
    except Exception as e:
        details["exception"] = str(e)
        logger.warning("Health probe exception on fallback URL %s: %s", fallback_url, e)
        return details


def check_keycloak_health(with_details=False):
    """Check if Keycloak is reachable via browser-facing discovery endpoint."""
    probe_url = f"https://{DOMAIN}/auth/realms/{REALM}/.well-known/openid-configuration"
    fallback_url = f"https://nginx/auth/realms/{REALM}/.well-known/openid-configuration"
    details = probe_endpoint(probe_url, fallback_url=fallback_url, timeout=3)
    return (details["healthy"], details) if with_details else details["healthy"]


def check_openbao_health(with_details=False):
    """Check if OpenBao is reachable."""
    details = probe_endpoint(f"{OPENBAO_ADDR}/v1/sys/health", timeout=5)
    return (details["healthy"], details) if with_details else details["healthy"]


def check_nginx_health():
    return probe_endpoint("https://nginx/", timeout=3)


def collect_live_health():
    kc_ok, kc = check_keycloak_health(with_details=True)
    bao_ok, bao = check_openbao_health(with_details=True)
    ng = check_nginx_health()
    ng["healthy"] = ng.get("healthy", False)
    return {
        "keycloak": kc,
        "openbao": bao,
        "nginx": ng,
        "summary": {
            "keycloak": kc_ok,
            "openbao": bao_ok,
            "nginx": ng.get("healthy", False),
        },
    }


def fetch_openbao_secrets(path):
    """Fetch secrets from OpenBao KV v2 engine."""
    try:
        token = OPENBAO_TOKEN
        if OPENBAO_TOKEN_FILE and os.path.exists(OPENBAO_TOKEN_FILE):
            with open(OPENBAO_TOKEN_FILE, "r", encoding="utf-8") as f:
                file_token = f.read().strip()
            if file_token:
                token = file_token

        r = http_requests.get(
            f"{OPENBAO_ADDR}/v1/secret/data/{path}",
            headers={"X-Vault-Token": token},
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
    """Extract minimal user identity from the session."""
    if not session.get("authenticated"):
        return None

    user = session.get("user", {})
    issued_unix = session.get("token_issued_unix")
    expiry_unix = session.get("token_expiry_unix")
    auth_time_unix = session.get("auth_time_unix")

    remaining_seconds = None
    token_status = "unknown"
    if expiry_unix is not None:
        remaining_seconds = int(expiry_unix) - now_unix()
        if remaining_seconds <= 0:
            token_status = "expired"
        elif remaining_seconds <= EXPIRING_SOON_SECONDS:
            token_status = "expiring_soon"
        else:
            token_status = "valid"

    roles = session.get("roles", [])

    return {
        "sub": user.get("sub", "unknown"),
        "username": user.get("preferred_username", "unknown"),
        "email": user.get("email", "N/A"),
        "authenticated": bool(session.get("authenticated")),
        "roles": roles,
        "all_roles": roles,
        "is_admin": "zero-trust-admin" in roles,
        "token_issued_unix": issued_unix,
        "token_expiry_unix": expiry_unix,
        "auth_time_unix": auth_time_unix,
        "token_issued": format_unix(issued_unix),
        "token_expiry": format_unix(expiry_unix),
        "auth_time": format_unix(auth_time_unix),
        "remaining_seconds": remaining_seconds,
        "remaining_time": format_remaining(remaining_seconds),
        "token_status": token_status,
    }


def try_silent_refresh():
    """Try refresh-token flow when enabled and token is available."""
    if not ENABLE_SILENT_REFRESH:
        return False

    refresh_token = session.get("refresh_token")
    if not refresh_token:
        return False

    token_endpoint = f"{KC_INTERNAL_URL}/protocol/openid-connect/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": KC_CLIENT_ID,
        "client_secret": KC_CLIENT_SECRET,
        "refresh_token": refresh_token,
    }

    try:
        resp = http_requests.post(token_endpoint, data=payload, timeout=5)
        if resp.status_code != 200:
            logger.warning("Silent refresh failed with HTTP %s", resp.status_code)
            return False

        refreshed = resp.json()
        claims = extract_claims(refreshed)
        id_claims = decode_jwt_claims(refreshed.get("id_token")) if refreshed.get("id_token") else {}
        issued, expiry, auth_time, _ = compute_token_times(refreshed, id_claims)

        session["token_issued_unix"] = issued
        session["token_expiry_unix"] = expiry
        if auth_time is not None:
            session["auth_time_unix"] = auth_time

        roles = extract_roles(claims, KC_CLIENT_ID)
        if roles:
            session["roles"] = roles

        if refreshed.get("refresh_token"):
            session["refresh_token"] = refreshed.get("refresh_token")

        append_audit_event("token_refresh", "ok", "Session silently refreshed")
        return True
    except Exception as e:
        logger.warning("Silent refresh failed: %s", e)
        return False


def require_session(required_roles=None):
    """Auth/session guard with expiry handling and optional RBAC."""
    if not session.get("authenticated"):
        return redirect("/app/login-required?error=Authentication required.")

    expiry = session.get("token_expiry_unix")
    if expiry is not None and int(expiry) <= now_unix():
        should_try_refresh = ENABLE_SILENT_REFRESH and bool(session.get("refresh_token"))
        if should_try_refresh:
            refreshed = try_silent_refresh()
            if not refreshed:
                append_audit_event("token_refresh_failed", "warning", "Silent refresh failed")
                append_audit_event("session_expired", "warning", "Session expired; re-login required")
                clear_auth_session(preserve_audit=True)
                return redirect("/app/login-required?error=Session expired. Please sign in again.")
        else:
            append_audit_event("session_expired", "warning", "Session expired; re-login required")
            clear_auth_session(preserve_audit=True)
            return redirect("/app/login-required?error=Session expired. Please sign in again.")

    user = get_user_info()
    if not user:
        return redirect("/app/login-required?error=Session invalid. Please sign in again.")

    if required_roles:
        user_roles = set([r.lower() for r in user.get("all_roles", []) if isinstance(r, str)])
        expected_roles = set([r.lower() for r in required_roles])
        if not user_roles.intersection(expected_roles):
            append_audit_event("rbac_denied", "warning", f"Required roles: {', '.join(required_roles)}")
            return redirect("/app/login-required?error=Access denied by role policy.")

    return None


# ═══════════════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════════════

@app.route("/")
def index():
    """Public landing page — system status overview."""
    kc_healthy, kc_details = check_keycloak_health(with_details=True)
    bao_healthy = check_openbao_health()
    user = get_user_info() if session.get("authenticated") else None
    debug_health = None
    if SHOW_HEALTH_DEBUG:
        debug_health = kc_details

    logger.info(
        "Homepage status keycloak_status=%s probe_url=%s response_code=%s exception=%s",
        kc_healthy,
        kc_details.get("probe_url"),
        kc_details.get("response_code"),
        kc_details.get("exception"),
    )

    return render_template(
        "index.html",
        keycloak_status=kc_healthy,
        openbao_status=bao_healthy,
        user=user,
        debug_health=debug_health,
    )


@app.route("/login")
def login():
    """Redirect to Keycloak OIDC login."""
    logger.info("Initiating OIDC login, redirect_uri=%s", REDIRECT_URI)
    return oauth.keycloak.authorize_redirect(REDIRECT_URI)


@app.route("/callback")
def callback():
    """Handle OIDC callback from Keycloak."""
    try:
        token = oauth.keycloak.authorize_access_token()
        id_claims = decode_jwt_claims(token.get("id_token")) if token.get("id_token") else {}
        claims = extract_claims(token)
        roles = extract_roles(claims, KC_CLIENT_ID)
        issued_unix, expiry_unix, auth_time_unix, timing_source = compute_token_times(token, id_claims)

        preferred_username = claims.get("preferred_username", "unknown")
        email = claims.get("email", "N/A")
        sub = claims.get("sub", "unknown")

        # Keep session payload small to avoid oversized cookies behind nginx.
        session["user"] = {
            "sub": sub,
            "preferred_username": preferred_username,
            "email": email,
        }
        session["roles"] = roles
        session["token_issued_unix"] = issued_unix
        session["token_expiry_unix"] = expiry_unix
        if auth_time_unix is not None:
            session["auth_time_unix"] = auth_time_unix
        else:
            session.pop("auth_time_unix", None)

        if ENABLE_SILENT_REFRESH and token.get("refresh_token"):
            session["refresh_token"] = token.get("refresh_token")
        else:
            session.pop("refresh_token", None)

        if token.get("id_token"):
            session["id_token_hint"] = token.get("id_token")
        else:
            session.pop("id_token_hint", None)

        session["authenticated"] = True
        append_audit_event("login", "ok", f"user={preferred_username}")

        logger.info(
            "OIDC callback roles extracted user=%s roles=%s",
            preferred_username,
            roles,
        )
        logger.info(
            "OIDC token timing source=%s issued=%s expiry=%s auth_time=%s",
            timing_source,
            issued_unix,
            expiry_unix,
            auth_time_unix,
        )

        logger.info(
            "User '%s' authenticated successfully",
            preferred_username,
        )
        return redirect("/app/dashboard")
    except Exception as e:
        logger.error("OIDC callback error: %s", e)
        return render_template(
            "login_required.html",
            error=f"Authentication failed: {str(e)}",
        ), 401


@app.route("/login-required")
def login_required():
    """Reusable page for auth/authorization/session failures."""
    return render_template("login_required.html", error=request.args.get("error")), 401


@app.route("/dashboard")
def dashboard():
    """Protected dashboard — requires valid Keycloak token."""
    guard = require_session()
    if guard:
        return guard

    user = get_user_info()
    live_health = collect_live_health()
    bao_healthy = live_health["summary"]["openbao"]

    return render_template(
        "dashboard.html",
        user=user,
        openbao_status=bao_healthy,
        live_health=live_health,
        audit_logs=session.get("audit_logs", []),
        active_page="dashboard",
    )


@app.route("/secrets")
def secrets():
    """Protected page — shows OpenBao-fetched secrets (values masked)."""
    guard = require_session(required_roles=["zero-trust-admin", "zero-trust-user"])
    if guard:
        return guard

    user = get_user_info()
    live_health = collect_live_health()
    bao_healthy = live_health["summary"]["openbao"]
    secrets_data = {}
    error_msg = None

    if bao_healthy:
        append_audit_event("secrets_access", "ok", "Viewed secrets data")
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
        live_health=live_health,
        audit_logs=session.get("audit_logs", []),
        secrets_data=secrets_data,
        secrets_error=error_msg,
        active_page="secrets",
    )


@app.route("/admin")
def admin():
    """Admin-only page for privileged operations demo."""
    guard = require_session(required_roles=["zero-trust-admin"])
    if guard:
        return guard

    append_audit_event("admin_access", "ok", "Visited admin panel")
    user = get_user_info()
    live_health = collect_live_health()

    return render_template(
        "dashboard.html",
        user=user,
        openbao_status=live_health["summary"]["openbao"],
        live_health=live_health,
        audit_logs=session.get("audit_logs", []),
        active_page="admin",
    )


@app.route("/debug-auth")
def debug_auth():
    """Development-only auth/session debug endpoint."""
    if os.environ.get("FLASK_ENV") != "development":
        return jsonify({"error": "Not found"}), 404

    guard = require_session()
    if guard:
        return guard

    user = get_user_info() or {}
    return jsonify({
        "username": user.get("username"),
        "extracted_roles": user.get("all_roles", []),
        "token_issued_unix": session.get("token_issued_unix"),
        "token_expiry_unix": session.get("token_expiry_unix"),
        "now_unix": now_unix(),
    })


@app.route("/logout")
def logout():
    """Clear session and redirect to Keycloak logout."""
    id_token_hint = session.get("id_token_hint")
    append_audit_event("logout_initiated", "ok", "User started logout flow")

    if not id_token_hint:
        append_audit_event("logout_completed_local_only", "warning", "id_token_hint missing; Keycloak logout skipped")

    clear_auth_session(preserve_audit=True)

    if not id_token_hint:
        return redirect("/app/")

    logout_url = (
        f"{KC_EXTERNAL_URL}/protocol/openid-connect/logout"
        f"?post_logout_redirect_uri=https://{DOMAIN}/app/"
        f"&id_token_hint={id_token_hint}"
    )
    return redirect(logout_url)


@app.route("/health")
def health():
    """Health check endpoint — returns JSON status."""
    live_health = collect_live_health()

    return jsonify({
        "status": "ok",
        "keycloak": live_health["summary"]["keycloak"],
        "openbao": live_health["summary"]["openbao"],
        "nginx": live_health["summary"]["nginx"],
        "checks": live_health,
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
