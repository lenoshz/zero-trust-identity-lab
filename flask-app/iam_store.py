"""
IAM Data Store — SQLite-backed persistence for JML lifecycle,
access reviews, security events, and impact metrics.
═══════════════════════════════════════════════════════════════
"""

import csv
import io
import logging
import os
import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta

# ═══════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════

DB_PATH = os.environ.get("IAM_DB_PATH", "/app/data/iam.db")

# Thread-local storage for connections
_local = threading.local()
logger = logging.getLogger("iam_store")

# ═══════════════════════════════════════════════════════════════
# Department → Baseline Role Mapping
# ═══════════════════════════════════════════════════════════════

DEPARTMENT_ROLE_MAP = {
    "Engineering":  "zero-trust-user",
    "Finance":      "zero-trust-readonly",
    "HR":           "zero-trust-readonly",
    "Security":     "zero-trust-admin",
    "Operations":   "zero-trust-user",
}

DEPARTMENTS = list(DEPARTMENT_ROLE_MAP.keys())

ROLE_RISK_LEVELS = {
    "zero-trust-admin":    "critical",
    "zero-trust-user":     "medium",
    "zero-trust-readonly": "low",
}

SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2, "critical": 3}


# ═══════════════════════════════════════════════════════════════
# Connection Helper
# ═══════════════════════════════════════════════════════════════

def _get_conn():
    """Get a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        logger.info("Opening IAM SQLite DB at %s", DB_PATH)
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ═══════════════════════════════════════════════════════════════
# Schema Initialization
# ═══════════════════════════════════════════════════════════════

_SCHEMA = """
CREATE TABLE IF NOT EXISTS iam_users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    email       TEXT    NOT NULL,
    full_name   TEXT    NOT NULL DEFAULT '',
    department  TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS iam_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    username      TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    old_department TEXT,
    new_department TEXT,
    old_role      TEXT,
    new_role      TEXT,
    performed_by  TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES iam_users(id)
);

CREATE TABLE IF NOT EXISTS access_reviews (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    username    TEXT    NOT NULL,
    role        TEXT    NOT NULL,
    risk_level  TEXT    NOT NULL,
    decision    TEXT,
    reason      TEXT,
    reviewer    TEXT,
    timestamp   TEXT    NOT NULL,
    decided_at  TEXT,
    FOREIGN KEY (user_id) REFERENCES iam_users(id)
);

CREATE TABLE IF NOT EXISTS security_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'info',
    actor       TEXT    NOT NULL DEFAULT 'system',
    detail      TEXT    NOT NULL DEFAULT '',
    ip_address  TEXT,
    timestamp   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_name TEXT    NOT NULL,
    value       REAL    NOT NULL,
    timestamp   TEXT    NOT NULL
);
"""

_SEED_USERS = [
    {
        "username": "ztadmin",
        "email": "ztadmin@zerotrust.lab",
        "full_name": "ZT Administrator",
        "department": "Security",
        "role": "zero-trust-admin",
    },
    {
        "username": "ztuser",
        "email": "ztuser@zerotrust.lab",
        "full_name": "ZT Standard User",
        "department": "Engineering",
        "role": "zero-trust-user",
    },
    {
        "username": "ztviewer",
        "email": "ztviewer@zerotrust.lab",
        "full_name": "ZT Viewer",
        "department": "Finance",
        "role": "zero-trust-readonly",
    },
]


def init_db():
    """Create tables and seed demo users (idempotent)."""
    conn = _get_conn()
    conn.executescript(_SCHEMA)

    now = _now_iso()
    for user in _SEED_USERS:
        conn.execute(
            """INSERT OR IGNORE INTO iam_users
               (username, email, full_name, department, role, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
            (user["username"], user["email"], user["full_name"],
             user["department"], user["role"], now, now),
        )

    # Seed initial metrics snapshot for trend computation
    existing = conn.execute(
        "SELECT COUNT(*) as cnt FROM metrics_snapshots"
    ).fetchone()["cnt"]
    if existing == 0:
        prior = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        seeds = [
            ("onboarding_time_minutes", 45.0, prior),
            ("offboarding_completion_pct", 85.0, prior),
            ("privileged_accounts", 1.0, prior),
            ("mfa_coverage_pct", 33.0, prior),
            ("review_completion_pct", 60.0, prior),
        ]
        conn.executemany(
            "INSERT INTO metrics_snapshots (metric_name, value, timestamp) VALUES (?, ?, ?)",
            seeds,
        )

    conn.commit()


# ═══════════════════════════════════════════════════════════════
# IAM Users — CRUD
# ═══════════════════════════════════════════════════════════════

def get_all_iam_users(status=None):
    """Get all IAM users, optionally filtered by status."""
    conn = _get_conn()
    if status:
        rows = conn.execute(
            "SELECT * FROM iam_users WHERE status = ? ORDER BY username", (status,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM iam_users ORDER BY username"
        ).fetchall()
    return [dict(r) for r in rows]


def get_iam_user(user_id):
    """Get a single IAM user by ID."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM iam_users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_iam_user_by_username(username):
    """Get a single IAM user by username."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM iam_users WHERE username = ?", (username,)
    ).fetchone()
    return dict(row) if row else None


def create_iam_user(username, email, full_name, department, performed_by):
    """Create a new IAM user (Joiner flow)."""
    conn = _get_conn()
    now = _now_iso()
    role = DEPARTMENT_ROLE_MAP.get(department, "zero-trust-readonly")

    # Check if username already exists
    existing = conn.execute(
        "SELECT id FROM iam_users WHERE username = ?", (username,)
    ).fetchone()
    if existing:
        return None, f"Username '{username}' already exists"

    cursor = conn.execute(
        """INSERT INTO iam_users
           (username, email, full_name, department, role, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
        (username, email, full_name, department, role, now, now),
    )
    user_id = cursor.lastrowid

    # Record JML event
    conn.execute(
        """INSERT INTO iam_events
           (user_id, username, event_type, new_department, new_role, performed_by, timestamp)
           VALUES (?, ?, 'joiner', ?, ?, ?, ?)""",
        (user_id, username, department, role, performed_by, now),
    )

    conn.commit()
    return user_id, None


def move_iam_user(user_id, new_department, performed_by):
    """Move a user to a new department (Mover flow)."""
    conn = _get_conn()
    now = _now_iso()

    user = get_iam_user(user_id)
    if not user:
        return False, "User not found"
    if user["status"] != "active":
        return False, "Cannot move a disabled user"

    old_dept = user["department"]
    old_role = user["role"]
    new_role = DEPARTMENT_ROLE_MAP.get(new_department, "zero-trust-readonly")

    if old_dept == new_department:
        return False, "User is already in that department"

    conn.execute(
        """UPDATE iam_users
           SET department = ?, role = ?, updated_at = ?
           WHERE id = ?""",
        (new_department, new_role, now, user_id),
    )

    conn.execute(
        """INSERT INTO iam_events
           (user_id, username, event_type, old_department, new_department,
            old_role, new_role, performed_by, timestamp)
           VALUES (?, ?, 'mover', ?, ?, ?, ?, ?, ?)""",
        (user_id, user["username"], old_dept, new_department,
         old_role, new_role, performed_by, now),
    )

    conn.commit()
    return True, None


def disable_iam_user(user_id, performed_by):
    """Disable a user and revoke all roles (Leaver flow)."""
    conn = _get_conn()
    now = _now_iso()

    user = get_iam_user(user_id)
    if not user:
        return False, "User not found"
    if user["status"] == "disabled":
        return False, "User is already disabled"

    old_role = user["role"]

    conn.execute(
        """UPDATE iam_users
           SET status = 'disabled', role = '', updated_at = ?
           WHERE id = ?""",
        (now, user_id),
    )

    conn.execute(
        """INSERT INTO iam_events
           (user_id, username, event_type, old_department, old_role,
            performed_by, timestamp)
           VALUES (?, ?, 'leaver', ?, ?, ?, ?)""",
        (user_id, user["username"], user["department"], old_role,
         performed_by, now),
    )

    conn.commit()
    return True, None


# ═══════════════════════════════════════════════════════════════
# JML Events
# ═══════════════════════════════════════════════════════════════

def get_jml_events(event_type=None, limit=50):
    """Get JML lifecycle events, optionally filtered by type."""
    conn = _get_conn()
    if event_type:
        rows = conn.execute(
            """SELECT * FROM iam_events WHERE event_type = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (event_type, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT * FROM iam_events
               ORDER BY timestamp DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════
# Access Reviews
# ═══════════════════════════════════════════════════════════════

def get_pending_reviews():
    """Get all active users that need review (no decision yet or only past decisions)."""
    conn = _get_conn()
    users = get_all_iam_users(status="active")
    result = []
    for user in users:
        risk = ROLE_RISK_LEVELS.get(user["role"], "low")
        # Check if there's already a review in this cycle
        latest = conn.execute(
            """SELECT * FROM access_reviews
               WHERE user_id = ? ORDER BY timestamp DESC LIMIT 1""",
            (user["id"],),
        ).fetchone()

        result.append({
            **user,
            "risk_level": risk,
            "last_review": dict(latest) if latest else None,
        })
    return result


def save_review_decision(user_id, username, role, risk_level, decision, reason, reviewer):
    """Save an access review decision."""
    conn = _get_conn()
    now = _now_iso()

    conn.execute(
        """INSERT INTO access_reviews
           (user_id, username, role, risk_level, decision, reason, reviewer, timestamp, decided_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, username, role, risk_level, decision, reason, reviewer, now, now),
    )
    conn.commit()
    return True


def get_review_history(limit=100):
    """Get completed review decisions."""
    conn = _get_conn()
    rows = conn.execute(
        """SELECT * FROM access_reviews
           WHERE decision IS NOT NULL
           ORDER BY decided_at DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def export_reviews_csv():
    """Export all review decisions as CSV string."""
    reviews = get_review_history(limit=10000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Review ID", "Username", "Role", "Risk Level",
        "Decision", "Reason", "Reviewer", "Decided At"
    ])
    for r in reviews:
        writer.writerow([
            r["id"], r["username"], r["role"], r["risk_level"],
            r["decision"], r["reason"] or "", r["reviewer"] or "",
            r["decided_at"] or "",
        ])
    return output.getvalue()


# ═══════════════════════════════════════════════════════════════
# Security Events
# ═══════════════════════════════════════════════════════════════

def log_security_event(event_type, severity="info", actor="system", detail="", ip_address=None):
    """Log a security event to the database."""
    conn = _get_conn()
    now = _now_iso()
    conn.execute(
        """INSERT INTO security_events
           (event_type, severity, actor, detail, ip_address, timestamp)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (event_type, severity, actor, detail, ip_address, now),
    )
    conn.commit()


def get_security_events(event_type=None, severity=None, limit=50):
    """Get security events with optional filters."""
    conn = _get_conn()
    query = "SELECT * FROM security_events WHERE 1=1"
    params = []

    if event_type:
        query += " AND event_type = ?"
        params.append(event_type)
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════
# Impact Metrics
# ═══════════════════════════════════════════════════════════════

def compute_metrics():
    """Compute current KPI values from live data."""
    conn = _get_conn()

    # Onboarding time — average minutes between user creation and first event
    all_users = get_all_iam_users()
    active_users = [u for u in all_users if u["status"] == "active"]
    disabled_users = [u for u in all_users if u["status"] == "disabled"]
    total_users = len(all_users)

    # Average onboarding time (simulated from joiner events)
    joiner_events = conn.execute(
        "SELECT COUNT(*) as cnt FROM iam_events WHERE event_type = 'joiner'"
    ).fetchone()["cnt"]
    # Simulate: 15 min base + 5 min per user (representing process time)
    onboarding_time = 15.0 + (joiner_events * 2.0) if joiner_events > 0 else 30.0

    # Offboarding completion %
    leaver_events = conn.execute(
        "SELECT COUNT(DISTINCT user_id) as cnt FROM iam_events WHERE event_type = 'leaver'"
    ).fetchone()["cnt"]
    disabled_with_no_role = len([
        u for u in disabled_users
        if not u["role"] or u["role"].strip() == ""
    ])
    offboarding_pct = (
        round((disabled_with_no_role / leaver_events) * 100, 1)
        if leaver_events > 0 else 100.0
    )

    # Privileged accounts count
    privileged = len([
        u for u in active_users
        if u["role"] in ("zero-trust-admin",)
    ])

    # MFA coverage % (simulated — in real system, query Keycloak)
    # For demo: admin users assumed to have MFA, others 50%
    if total_users > 0:
        mfa_users = privileged + max(0, len(active_users) - privileged) // 2
        mfa_pct = round((mfa_users / max(len(active_users), 1)) * 100, 1)
    else:
        mfa_pct = 0.0

    # Access review completion %
    total_needing_review = len(active_users)
    reviewed = conn.execute(
        """SELECT COUNT(DISTINCT user_id) as cnt FROM access_reviews
           WHERE decision IS NOT NULL"""
    ).fetchone()["cnt"]
    review_pct = (
        round((reviewed / total_needing_review) * 100, 1)
        if total_needing_review > 0 else 0.0
    )

    return {
        "onboarding_time_minutes": onboarding_time,
        "offboarding_completion_pct": offboarding_pct,
        "privileged_accounts": privileged,
        "mfa_coverage_pct": mfa_pct,
        "review_completion_pct": review_pct,
    }


def get_metrics_with_trends():
    """Get current metrics with trend arrows compared to prior snapshot."""
    current = compute_metrics()
    conn = _get_conn()

    metrics = []
    for key, value in current.items():
        # Get most recent prior snapshot
        prior_row = conn.execute(
            """SELECT value FROM metrics_snapshots
               WHERE metric_name = ?
               ORDER BY timestamp DESC LIMIT 1""",
            (key,),
        ).fetchone()

        prior_value = prior_row["value"] if prior_row else value
        delta = value - prior_value

        # Determine trend direction + color
        # For most metrics, higher is better; for onboarding_time, lower is better
        if key == "onboarding_time_minutes":
            if delta < -1:
                trend = "down"
                trend_color = "success"  # Lower is better
            elif delta > 1:
                trend = "up"
                trend_color = "danger"   # Higher is worse
            else:
                trend = "flat"
                trend_color = "secondary"
        elif key == "privileged_accounts":
            if delta < 0:
                trend = "down"
                trend_color = "success"  # Fewer privileged is better
            elif delta > 0:
                trend = "up"
                trend_color = "warning"
            else:
                trend = "flat"
                trend_color = "secondary"
        else:
            if delta > 1:
                trend = "up"
                trend_color = "success"  # Higher % is better
            elif delta < -1:
                trend = "down"
                trend_color = "danger"
            else:
                trend = "flat"
                trend_color = "secondary"

        # Format display
        label_map = {
            "onboarding_time_minutes": ("Avg. Onboarding Time", f"{value:.0f} min", "bi-stopwatch"),
            "offboarding_completion_pct": ("Offboarding Completion", f"{value:.0f}%", "bi-person-x-fill"),
            "privileged_accounts": ("Privileged Accounts", f"{int(value)}", "bi-shield-exclamation"),
            "mfa_coverage_pct": ("MFA Coverage", f"{value:.0f}%", "bi-phone-lock-fill" if value > 0 else "bi-phone"),
            "review_completion_pct": ("Review Completion", f"{value:.0f}%", "bi-clipboard-check-fill"),
        }

        label, display_value, icon = label_map.get(key, (key, str(value), "bi-bar-chart"))

        metrics.append({
            "key": key,
            "label": label,
            "value": value,
            "display_value": display_value,
            "icon": icon,
            "trend": trend,
            "trend_color": trend_color,
            "delta": round(delta, 1),
        })

    return metrics


def save_metrics_snapshot():
    """Save current metrics as a snapshot for future trend computation."""
    current = compute_metrics()
    conn = _get_conn()
    now = _now_iso()
    for key, value in current.items():
        conn.execute(
            "INSERT INTO metrics_snapshots (metric_name, value, timestamp) VALUES (?, ?, ?)",
            (key, value, now),
        )
    conn.commit()
