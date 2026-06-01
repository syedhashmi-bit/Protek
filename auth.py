"""
auth.py — login, TOTP, session, rate limiting, IP whitelist, audit log.

Multi-admin (phase 42): the env-anchored admin (APP_USERNAME / APP_PASSWORD_HASH /
TOTP_SECRET) is mirrored into the `users` table as row #1 on every boot so it can
never be locked out. Additional admins are added via /admin/users; their creds
live ONLY in the users table.

Phase 43 attaches a `role` column drives RBAC (viewer / operator / admin).
"""

from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any

import bcrypt
import pyotp
from flask import flash, redirect, render_template, request, session, url_for

from db import get_conn

# ── env ─────────────────────────────────────────────────────────────────────

def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "") or ""
    # Tolerate dotenv leaving trailing "  # comment" on values.
    raw = raw.split("#", 1)[0].strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _max_attempts() -> int:
    return _env_int("MAX_LOGIN_ATTEMPTS", 5)


def _lockout_minutes() -> int:
    return _env_int("LOCKOUT_MINUTES", 15)


def _session_timeout_minutes() -> int:
    return _env_int("SESSION_TIMEOUT_MIN", 30)


def _clean(name: str) -> str:
    """Read an env value, tolerating trailing dotenv inline-comments / whitespace."""
    raw = os.environ.get(name, "") or ""
    return raw.split("#", 1)[0].strip()


def _admin_username() -> str:
    return _clean("APP_USERNAME")


def _admin_hash() -> str:
    # Bcrypt hashes contain no '#' so the same strip is safe here.
    return _clean("APP_PASSWORD_HASH")


def _totp_secret() -> str:
    return _clean("TOTP_SECRET")


# ── helpers ─────────────────────────────────────────────────────────────────

def client_ip() -> str:
    # Behind nginx; X-Forwarded-For is trusted (one hop). nginx sets it from
    # $remote_addr so a client-supplied header cannot spoof it.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


def ip_allowed(ip: str) -> bool:
    raw = os.environ.get("IP_WHITELIST", "") or ""
    raw = raw.split("#", 1)[0].strip()
    if not raw:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in (e.strip() for e in raw.split(",") if e.strip()):
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── rate limit ──────────────────────────────────────────────────────────────

def is_locked(ip: str) -> tuple[bool, int]:
    conn = get_conn()
    try:
        row = conn.execute("SELECT locked_until FROM login_attempts WHERE ip = ?", (ip,)).fetchone()
    finally:
        conn.close()
    if not row or not row["locked_until"]:
        return False, 0
    try:
        until = datetime.fromisoformat(row["locked_until"])
    except ValueError:
        return False, 0
    now = datetime.now(timezone.utc)
    if until > now:
        mins = max(1, int((until - now).total_seconds() // 60) + 1)
        return True, mins
    return False, 0


def record_failure(ip: str) -> None:
    now = datetime.now(timezone.utc)
    conn = get_conn()
    try:
        row = conn.execute("SELECT attempts FROM login_attempts WHERE ip = ?", (ip,)).fetchone()
        attempts = (row["attempts"] if row else 0) + 1
        locked_until = None
        if attempts >= _max_attempts():
            locked_until = (now + timedelta(minutes=_lockout_minutes())).isoformat()
        if row:
            conn.execute(
                "UPDATE login_attempts SET attempts = ?, locked_until = ?, last_attempt = ? WHERE ip = ?",
                (attempts, locked_until, now.isoformat(), ip),
            )
        else:
            conn.execute(
                "INSERT INTO login_attempts (ip, attempts, locked_until, last_attempt) VALUES (?, ?, ?, ?)",
                (ip, attempts, locked_until, now.isoformat()),
            )
    finally:
        conn.close()
    # Fire notifications + SIEM event (best-effort; never block auth on failure).
    try:
        import notifications
        notifications.send(
            "login_failure",
            f"Failed login from {ip}. Attempt {attempts}/{_max_attempts()}.",
            subject="Login failure",
        )
        if locked_until:
            notifications.send(
                "login_locked",
                f"IP {ip} locked for {_lockout_minutes()} minutes after {attempts} failed attempts.",
                subject="IP locked out",
            )
    except Exception:  # noqa: BLE001
        pass
    try:
        import siem
        siem.ship("auth.failure", {"ip": ip, "attempts": attempts,
                                   "max": _max_attempts()})
        if locked_until:
            siem.ship("auth.locked", {"ip": ip, "attempts": attempts,
                                      "lockout_min": _lockout_minutes()})
    except Exception:  # noqa: BLE001
        pass


def clear_failures(ip: str) -> None:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
    finally:
        conn.close()


def record_audit(ip: str, username: str, success: bool, reason: str = "") -> None:
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO login_audit (ip, username, success, reason, created_at) VALUES (?, ?, ?, ?, ?)",
            (ip, username, 1 if success else 0, reason, _now_iso()),
        )
    finally:
        conn.close()


# ── session ─────────────────────────────────────────────────────────────────

def _session_expired() -> bool:
    last = session.get("last_active")
    if not last:
        return True
    try:
        ts = datetime.fromisoformat(last)
    except ValueError:
        return True
    return datetime.now(timezone.utc) - ts > timedelta(minutes=_session_timeout_minutes())


def touch_session() -> None:
    session["last_active"] = _now_iso()


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        ip = client_ip()
        if not ip_allowed(ip):
            return render_template("blocked.html", ip=ip), 403
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        if _session_expired():
            session.clear()
            flash("Session expired — please log in again.", "warn")
            return redirect(url_for("login"))
        touch_session()
        return view(*args, **kwargs)

    return wrapper


# ── users table (phase 42 multi-admin) ──────────────────────────────────────

def seed_env_user() -> None:
    """Idempotent mirror of the .env-anchored admin into row #1 of `users`.

    Runs on every boot. Updates the row in place if the env values changed
    (e.g. operator rotated the password via setup_admin.py). The role for the
    env user is always `admin` — they can't be demoted, since they're the
    bootstrap identity that owns the .env file."""
    uname = _admin_username()
    hash_ = _admin_hash()
    secret = _totp_secret()
    if not (uname and hash_ and secret):
        return  # env-bootstrap not configured yet (fresh install)
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id, password_hash, totp_secret FROM users WHERE username = ?",
            (uname,),
        ).fetchone()
        now = _now_iso()
        if row:
            if row["password_hash"] != hash_ or row["totp_secret"] != secret:
                conn.execute(
                    "UPDATE users SET password_hash = ?, totp_secret = ?, "
                    "role = 'admin', disabled = 0 WHERE id = ?",
                    (hash_, secret, row["id"]),
                )
        else:
            conn.execute(
                "INSERT INTO users (username, password_hash, totp_secret, role, created_at) "
                "VALUES (?, ?, ?, 'admin', ?)",
                (uname, hash_, secret, now),
            )
    finally:
        conn.close()


def get_user(username: str) -> dict[str, Any] | None:
    if not username:
        return None
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND disabled = 0",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def list_users() -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, username, role, created_at, last_login_at, disabled "
            "FROM users ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def add_user(username: str, password: str, role: str = "viewer") -> dict[str, Any]:
    """Create a new admin/operator/viewer. Returns the new user dict + a
    fresh TOTP secret (caller is responsible for showing it ONCE to the
    operator — pyotp.TOTP(secret).provisioning_uri(...) for QR rendering)."""
    if not username or not username.replace("_", "").replace("-", "").isalnum():
        raise ValueError("username must be alphanumeric (plus _ and -)")
    if not password or len(password) < 8:
        raise ValueError("password must be ≥ 8 characters")
    if role not in ("viewer", "operator", "admin"):
        raise ValueError("role must be viewer / operator / admin")
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    secret = pyotp.random_base32()
    now = _now_iso()
    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret, role, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, pw_hash, secret, role, now),
        )
        uid = cur.lastrowid
    finally:
        conn.close()
    return {
        "id": uid, "username": username, "role": role, "totp_secret": secret,
        "totp_uri": pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Protek"),
        "created_at": now,
    }


def set_user_disabled(user_id: int, disabled: bool) -> None:
    conn = get_conn()
    try:
        # Refuse to disable user #1 (the env-anchored admin).
        if user_id == 1 and disabled:
            raise ValueError("cannot disable the env-anchored admin (user #1)")
        conn.execute("UPDATE users SET disabled = ? WHERE id = ?",
                     (1 if disabled else 0, user_id))
    finally:
        conn.close()


def set_user_role(user_id: int, role: str) -> None:
    if role not in ("viewer", "operator", "admin"):
        raise ValueError("role must be viewer / operator / admin")
    conn = get_conn()
    try:
        if user_id == 1 and role != "admin":
            raise ValueError("cannot demote the env-anchored admin (user #1)")
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    finally:
        conn.close()


def delete_user(user_id: int) -> None:
    if user_id == 1:
        raise ValueError("cannot delete the env-anchored admin (user #1)")
    conn = get_conn()
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    finally:
        conn.close()


def record_user_login(user_id: int) -> None:
    conn = get_conn()
    try:
        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?",
                     (_now_iso(), user_id))
    finally:
        conn.close()


# ── credential check ────────────────────────────────────────────────────────

def verify_password(username: str, password: str) -> dict[str, Any] | None:
    """Returns the user row on success, None on failure. Looks up the user by
    name from the `users` table (which is seeded from .env on every boot, so
    the env-anchored admin still works without explicit DB setup)."""
    if not username or not password:
        return None
    user = get_user(username)
    if not user:
        return None
    try:
        if bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
            return user
    except (ValueError, TypeError):
        pass
    return None


def verify_totp_for(user: dict[str, Any], code: str) -> bool:
    secret = user.get("totp_secret") or ""
    if not secret or not code:
        return False
    code = code.replace(" ", "").strip()
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=1)
    except Exception:  # noqa: BLE001
        return False


# ── RBAC (phase 43) ─────────────────────────────────────────────────────────

ROLE_ORDER = {"viewer": 1, "operator": 2, "admin": 3}


def current_role() -> str:
    return session.get("role", "viewer")


def has_role(required: str) -> bool:
    return ROLE_ORDER.get(current_role(), 0) >= ROLE_ORDER.get(required, 99)


def role_required(required: str):
    """Decorator: gate a route on a minimum role. Returns 403 (or redirects
    viewers back to /) if the current session's role is insufficient."""
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login", next=request.path))
            if not has_role(required):
                flash(f"Insufficient privileges — requires {required} role.", "error")
                return redirect(url_for("dashboard")), 403
            return view(*args, **kwargs)
        return wrapper
    return deco
