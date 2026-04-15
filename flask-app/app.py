"""
Zero Trust Identity Lab — Flask Demo Application
═══════════════════════════════════════════════════
Demonstrates OIDC authentication via Keycloak and
runtime secret fetching from OpenBao.

Extended with:
  - JML (Joiner/Mover/Leaver) lifecycle management
  - Access review workflow with CSV export
  - Privileged access + MFA enforcement
  - In-app SIEM security events
  - Impact metrics KPI dashboard
"""

import os
import json
import base64
import logging
from urllib.parse import quote
from datetime import datetime, timezone
import urllib3

from flask import (
    Flask, redirect, session, render_template, request,
    jsonify, Response
)
from authlib.integrations.flask_client import OAuth
import requests as http_requests

import iam_store

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

# MFA enforcement toggle —
#   false (default) = dev/demo bypass with warning banner
#   true            = strict MFA enforcement for admin actions
ADMIN_MFA_STRICT = os.environ.get("FLASK_ADMIN_MFA_STRICT", "false").lower() == "true"

# Open Discover with a safe default: no strict filter + wider time window.
KIBANA_DISCOVER_URL = (
    "https://localhost/kibana/app/discover"
    "#/?_g=(time:(from:now-24h,to:now))"
    "&_a=(query:(language:kuery,query:''))"
)

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


def _get_client_ip():
    """Get client IP from X-Forwarded-For or remote_addr."""
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _check_mfa_claim():
    """
    Check if the current session has an MFA claim.
    Returns (has_mfa: bool, mfa_bypass: bool).
    """
    claims = session.get("token_claims", {})
    acr = claims.get("acr", "")
    amr = claims.get("amr", [])
    if not isinstance(amr, list):
        amr = []

    has_mfa = (
        acr in ("urn:oasis:names:tc:SAML:2.0:ac:classes:mfa", "2", "silver", "gold")
        or any(m in amr for m in ("otp", "totp", "mfa"))
    )
    return has_mfa


def require_session(required_roles=None, mfa_required=False):
    """Auth/session guard with expiry handling, optional RBAC, and MFA enforcement."""
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
            iam_store.log_security_event(
                "rbac_denied", "warning", user.get("username", "unknown"),
                f"Denied access; required: {', '.join(required_roles)}",
                ip_address=_get_client_ip(),
            )
            return redirect("/app/login-required?error=Access denied by role policy.")

    # MFA enforcement
    if mfa_required:
        has_mfa = _check_mfa_claim()
        if not has_mfa:
            if ADMIN_MFA_STRICT:
                # Strict mode — deny access entirely
                append_audit_event("mfa_denied", "warning", "MFA required but not present (strict mode)")
                iam_store.log_security_event(
                    "mfa_denied", "warning", user.get("username", "unknown"),
                    "Admin action denied — MFA not present (strict enforcement)",
                    ip_address=_get_client_ip(),
                )
                return render_template("mfa_required.html",
                    error="Your session does not include an MFA claim. "
                          "Configure TOTP in Keycloak and re-authenticate."
                ), 403
            else:
                # Dev/demo bypass — allow with warning, log the bypass
                iam_store.log_security_event(
                    "mfa_bypass", "warning", user.get("username", "unknown"),
                    "Admin action permitted without MFA (demo mode)",
                    ip_address=_get_client_ip(),
                )
                session["mfa_bypass"] = True
        else:
            session["mfa_bypass"] = False
            iam_store.log_security_event(
                "mfa_verified", "info", user.get("username", "unknown"),
                "MFA claim verified for admin action",
                ip_address=_get_client_ip(),
            )

    return None


# ═══════════════════════════════════════════════════
# Routes — Core
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
        access_claims = decode_jwt_claims(token.get("access_token")) if token.get("access_token") else {}
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

        # Store MFA-related claims for later enforcement checks
        session["token_claims"] = {
            "acr": access_claims.get("acr", id_claims.get("acr", "")),
            "amr": access_claims.get("amr", id_claims.get("amr", [])),
        }

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

        # Log to persistent security events
        iam_store.log_security_event(
            "login_success", "info", preferred_username,
            f"OIDC login successful, roles={roles}",
            ip_address=_get_client_ip(),
        )

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
        iam_store.log_security_event(
            "login_fail", "error", "unknown",
            f"OIDC callback failed: {str(e)}",
            ip_address=_get_client_ip(),
        )
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

    # Compute KPI metrics
    metrics = iam_store.get_metrics_with_trends()

    # Fetch recent security events for SIEM panel
    security_events = iam_store.get_security_events(limit=50)
    kibana_error = request.args.get("kibana_error") == "1"

    return render_template(
        "dashboard.html",
        user=user,
        openbao_status=bao_healthy,
        live_health=live_health,
        audit_logs=session.get("audit_logs", []),
        metrics=metrics,
        security_events=security_events,
        kibana_error=kibana_error,
        active_page="dashboard",
    )


@app.route("/kibana/discover")
def launch_kibana_discover():
    """Open Kibana discover with a guard to avoid raw 502 errors."""
    guard = require_session()
    if guard:
        return guard

    user = get_user_info() or {}
    kibana_probe = probe_endpoint("https://nginx/kibana/api/status", timeout=3)

    if not kibana_probe.get("healthy"):
        detail_parts = ["Kibana unavailable from dashboard link"]
        if kibana_probe.get("response_code") is not None:
            detail_parts.append(f"code={kibana_probe['response_code']}")
        if kibana_probe.get("exception"):
            detail_parts.append(f"error={kibana_probe['exception']}")
        detail = " | ".join(detail_parts)

        append_audit_event("kibana_unavailable", "warning", detail)
        iam_store.log_security_event(
            "kibana_unavailable", "warning", user.get("username", "unknown"),
            detail,
            ip_address=_get_client_ip(),
        )
        return redirect("/app/dashboard?kibana_error=1")

    return redirect(KIBANA_DISCOVER_URL)


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
        iam_store.log_security_event(
            "secret_access", "info", user.get("username", "unknown"),
            "Viewed OpenBao secrets (masked)",
            ip_address=_get_client_ip(),
        )
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
    guard = require_session(required_roles=["zero-trust-admin"], mfa_required=True)
    if guard:
        return guard

    append_audit_event("admin_access", "ok", "Visited admin panel")
    iam_store.log_security_event(
        "admin_action", "info",
        get_user_info().get("username", "unknown"),
        "Accessed admin panel",
        ip_address=_get_client_ip(),
    )
    user = get_user_info()
    live_health = collect_live_health()

    return render_template(
        "dashboard.html",
        user=user,
        openbao_status=live_health["summary"]["openbao"],
        live_health=live_health,
        audit_logs=session.get("audit_logs", []),
        active_page="admin",
        mfa_bypass=session.get("mfa_bypass", False),
    )


# ═══════════════════════════════════════════════════
# Routes — JML Lifecycle
# ═══════════════════════════════════════════════════

@app.route("/admin/iam/joiner", methods=["GET", "POST"])
def iam_joiner():
    """JML Joiner — create a new user profile with baseline role."""
    guard = require_session(required_roles=["zero-trust-admin"], mfa_required=True)
    if guard:
        return guard

    user = get_user_info()
    error = None
    success = None

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip()
        full_name = (request.form.get("full_name") or "").strip()
        department = (request.form.get("department") or "").strip()

        if not all([username, email, full_name, department]):
            error = "All fields are required."
        elif department not in iam_store.DEPARTMENTS:
            error = f"Invalid department: {department}"
        else:
            uid, err = iam_store.create_iam_user(
                username, email, full_name, department,
                performed_by=user.get("username", "unknown"),
            )
            if err:
                error = err
            else:
                role = iam_store.DEPARTMENT_ROLE_MAP.get(department, "")
                success = f"User '{username}' created in {department} with role '{role}'."
                append_audit_event("jml_joiner", "ok", f"Created user {username}")
                iam_store.log_security_event(
                    "admin_action", "info", user.get("username", "unknown"),
                    f"JML Joiner: created {username} in {department} (role={role})",
                    ip_address=_get_client_ip(),
                )

    recent_events = iam_store.get_jml_events(event_type="joiner", limit=20)

    return render_template(
        "iam_joiner.html",
        user=user,
        error=error,
        success=success,
        departments=iam_store.DEPARTMENTS,
        dept_role_map=iam_store.DEPARTMENT_ROLE_MAP,
        dept_role_map_json=json.dumps(iam_store.DEPARTMENT_ROLE_MAP),
        recent_events=recent_events,
        mfa_bypass=session.get("mfa_bypass", False),
    )


@app.route("/admin/iam/mover", methods=["GET", "POST"])
def iam_mover():
    """JML Mover — change department and recompute role."""
    guard = require_session(required_roles=["zero-trust-admin"], mfa_required=True)
    if guard:
        return guard

    user = get_user_info()
    error = None
    success = None

    if request.method == "POST":
        user_id = request.form.get("user_id")
        new_department = (request.form.get("new_department") or "").strip()

        if not user_id or not new_department:
            error = "Please select a user and new department."
        elif new_department not in iam_store.DEPARTMENTS:
            error = f"Invalid department: {new_department}"
        else:
            try:
                uid = int(user_id)
            except ValueError:
                error = "Invalid user ID."
                uid = None

            if uid is not None:
                ok, err = iam_store.move_iam_user(
                    uid, new_department,
                    performed_by=user.get("username", "unknown"),
                )
                if err:
                    error = err
                else:
                    target = iam_store.get_iam_user(uid)
                    tname = target["username"] if target else f"ID:{uid}"
                    success = f"User '{tname}' transferred to {new_department}."
                    append_audit_event("jml_mover", "ok", f"Moved {tname} to {new_department}")
                    iam_store.log_security_event(
                        "admin_action", "info", user.get("username", "unknown"),
                        f"JML Mover: transferred {tname} to {new_department}",
                        ip_address=_get_client_ip(),
                    )

    active_users = iam_store.get_all_iam_users(status="active")
    recent_events = iam_store.get_jml_events(event_type="mover", limit=20)

    return render_template(
        "iam_mover.html",
        user=user,
        error=error,
        success=success,
        active_users=active_users,
        departments=iam_store.DEPARTMENTS,
        dept_role_map=iam_store.DEPARTMENT_ROLE_MAP,
        dept_role_map_json=json.dumps(iam_store.DEPARTMENT_ROLE_MAP),
        recent_events=recent_events,
        mfa_bypass=session.get("mfa_bypass", False),
    )


@app.route("/admin/iam/leaver", methods=["GET", "POST"])
def iam_leaver():
    """JML Leaver — disable user and revoke all roles/sessions."""
    guard = require_session(required_roles=["zero-trust-admin"], mfa_required=True)
    if guard:
        return guard

    user = get_user_info()
    error = None
    success = None

    if request.method == "POST":
        user_id = request.form.get("user_id")

        if not user_id:
            error = "Please select a user to offboard."
        else:
            try:
                uid = int(user_id)
            except ValueError:
                error = "Invalid user ID."
                uid = None

            if uid is not None:
                target = iam_store.get_iam_user(uid)
                ok, err = iam_store.disable_iam_user(
                    uid,
                    performed_by=user.get("username", "unknown"),
                )
                if err:
                    error = err
                else:
                    tname = target["username"] if target else f"ID:{uid}"
                    success = f"User '{tname}' has been disabled. All roles revoked."
                    append_audit_event("jml_leaver", "ok", f"Disabled user {tname}")
                    iam_store.log_security_event(
                        "admin_action", "info", user.get("username", "unknown"),
                        f"JML Leaver: disabled {tname}, roles revoked",
                        ip_address=_get_client_ip(),
                    )

    active_users = iam_store.get_all_iam_users(status="active")
    disabled_users = iam_store.get_all_iam_users(status="disabled")
    recent_events = iam_store.get_jml_events(event_type="leaver", limit=20)

    return render_template(
        "iam_leaver.html",
        user=user,
        error=error,
        success=success,
        active_users=active_users,
        disabled_users=disabled_users,
        recent_events=recent_events,
        mfa_bypass=session.get("mfa_bypass", False),
    )


# ═══════════════════════════════════════════════════
# Routes — Access Reviews
# ═══════════════════════════════════════════════════

@app.route("/admin/reviews")
def access_reviews():
    """Access review dashboard — list users and role assignments."""
    guard = require_session(required_roles=["zero-trust-admin"], mfa_required=True)
    if guard:
        return guard

    user = get_user_info()
    pending = iam_store.get_pending_reviews()
    history = iam_store.get_review_history(limit=50)

    # Compute completion percentage
    total = len(pending)
    reviewed = sum(1 for p in pending if p.get("last_review") and p["last_review"].get("decision"))
    completion_pct = round((reviewed / total) * 100, 0) if total > 0 else 0

    return render_template(
        "access_reviews.html",
        user=user,
        pending_reviews=pending,
        review_history=history,
        review_completion_pct=int(completion_pct),
        error=request.args.get("error"),
        success=request.args.get("success"),
        mfa_bypass=session.get("mfa_bypass", False),
    )


@app.route("/admin/reviews/decide", methods=["POST"])
def review_decide():
    """Process an access review decision (approve or revoke)."""
    guard = require_session(required_roles=["zero-trust-admin"], mfa_required=True)
    if guard:
        return guard

    user = get_user_info()
    user_id = request.form.get("user_id")
    username = request.form.get("username", "")
    role = request.form.get("role", "")
    risk_level = request.form.get("risk_level", "")
    decision = request.form.get("decision", "")
    reason = (request.form.get("reason") or "").strip()

    if not all([user_id, username, role, decision]):
        return redirect("/app/admin/reviews?error=Missing required fields.")

    if decision == "revoked" and len(reason) < 5:
        return redirect("/app/admin/reviews?error=Revocation requires a reason (min 5 chars).")

    try:
        uid = int(user_id)
    except ValueError:
        return redirect("/app/admin/reviews?error=Invalid user ID.")

    reviewer = user.get("username", "unknown")

    iam_store.save_review_decision(
        uid, username, role, risk_level, decision,
        reason if decision == "revoked" else "Role assignment approved",
        reviewer,
    )

    append_audit_event("review_decision", "ok", f"{decision} {role} for {username}")
    iam_store.log_security_event(
        "review_decision", "info" if decision == "approved" else "warning",
        reviewer,
        f"Access review: {decision} role '{role}' for {username}"
        + (f" — reason: {reason}" if reason else ""),
        ip_address=_get_client_ip(),
    )

    return redirect(f"/app/admin/reviews?success=Review recorded: {decision} '{role}' for {username}.")


@app.route("/admin/reviews/export")
def reviews_export():
    """Export access review decisions as CSV."""
    guard = require_session(required_roles=["zero-trust-admin"], mfa_required=True)
    if guard:
        return guard

    csv_data = iam_store.export_reviews_csv()

    iam_store.log_security_event(
        "admin_action", "info",
        get_user_info().get("username", "unknown"),
        "Exported access review CSV",
        ip_address=_get_client_ip(),
    )

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=access_reviews.csv"},
    )


# ═══════════════════════════════════════════════════
# Routes — API Endpoints
# ═══════════════════════════════════════════════════

@app.route("/api/security-events")
def api_security_events():
    """JSON endpoint for security events (SIEM panel async loading)."""
    guard = require_session()
    if guard:
        return jsonify({"error": "Authentication required"}), 401

    event_type = request.args.get("type")
    severity = request.args.get("severity")
    limit = min(int(request.args.get("limit", 50)), 200)

    events = iam_store.get_security_events(
        event_type=event_type, severity=severity, limit=limit
    )
    return jsonify(events)


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
        "token_claims": session.get("token_claims", {}),
        "mfa_strict": ADMIN_MFA_STRICT,
        "now_unix": now_unix(),
    })


@app.route("/logout")
def logout():
    """Clear session and redirect to Keycloak logout."""
    user = get_user_info()
    username = user.get("username", "unknown") if user else "unknown"

    id_token_hint = session.get("id_token_hint")
    append_audit_event("logout_initiated", "ok", "User started logout flow")

    # Log logout to persistent security events
    iam_store.log_security_event(
        "logout", "info", username,
        "User initiated logout",
        ip_address=_get_client_ip(),
    )

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
    # Initialize IAM data store
    logger.info("Initializing IAM data store...")
    os.makedirs("/app/data", exist_ok=True)
    iam_store.init_db()
    logger.info("IAM data store ready (SQLite at %s)", iam_store.DB_PATH)
    logger.info("MFA enforcement mode: %s", "STRICT" if ADMIN_MFA_STRICT else "DEMO (bypass with warning)")

    startup_config()
    app.run(host="0.0.0.0", port=5000, debug=False)
