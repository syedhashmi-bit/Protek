"""
oidc.py — Arc 12 phase 70. OAuth 2.0 / OpenID Connect SSO.

Generic OIDC client built on Authlib — works with any OIDC provider that
exposes a discovery document at <ISSUER>/.well-known/openid-configuration.
Verified shapes:

  - Google Workspace:   OIDC_ISSUER=https://accounts.google.com
  - Authentik:          OIDC_ISSUER=https://auth.example.com/application/o/protek/
  - Auth0:              OIDC_ISSUER=https://yourtenant.auth0.com/
  - Keycloak:           OIDC_ISSUER=https://kc.example.com/realms/<realm>

Login flow:
  GET /sso/login   → redirect to OIDC provider authorize URL
  GET /sso/callback → exchange code for tokens, fetch userinfo, map to a
                      Protek user, set session

Claim → role mapping:
  Highest-precedence wins. Configurable via OIDC_GROUPS_* env vars:
    OIDC_GROUPS_ADMIN    — comma-separated groups granted admin
    OIDC_GROUPS_OPERATOR — comma-separated groups granted operator
    OIDC_GROUPS_VIEWER   — comma-separated groups granted viewer
    OIDC_GROUPS_CLAIM    — claim key holding groups (default "groups")
  Plus domain restriction:
    OIDC_ALLOWED_DOMAINS — comma-separated email domains (e.g. "syedhashmi.trade")
                           — empty = any domain accepted

  If a user has none of those groups, they're rejected unless
  OIDC_DEFAULT_ROLE is set (e.g. "viewer"). No default means SSO opens
  Protek to *anyone with a verified email at an allowed domain* — only
  do that if your IDP itself is the gate.

Break-glass: the env-anchored admin (APP_USERNAME / APP_PASSWORD_HASH /
TOTP_SECRET) ALWAYS works at /login regardless of OIDC state. Lock out
of OIDC ≠ lock out of Protek.

TOTP is skipped for OIDC users — the IDP is presumed to do MFA. Local
users (incl. break-glass) still go through TOTP.

When OIDC_ISSUER is unset, the /sso/* routes 404 and the login page
shows local login only.
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import bcrypt

from db import get_conn

log = logging.getLogger("protek.oidc")


def _envstr(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").split("#", 1)[0].strip()


def is_configured() -> bool:
    return bool(_envstr("OIDC_ISSUER") and _envstr("OIDC_CLIENT_ID")
                and _envstr("OIDC_CLIENT_SECRET"))


def status() -> dict[str, Any]:
    return {
        "configured": is_configured(),
        "issuer":     _envstr("OIDC_ISSUER") or "(unset)",
        "client_id":  _envstr("OIDC_CLIENT_ID") or "(unset)",
        "domains":    _envstr("OIDC_ALLOWED_DOMAINS") or "(any)",
        "groups_claim": _envstr("OIDC_GROUPS_CLAIM") or "groups",
        "default_role": _envstr("OIDC_DEFAULT_ROLE") or "(none)",
        "groups_admin":    _envstr("OIDC_GROUPS_ADMIN")    or "(none)",
        "groups_operator": _envstr("OIDC_GROUPS_OPERATOR") or "(none)",
        "groups_viewer":   _envstr("OIDC_GROUPS_VIEWER")   or "(none)",
    }


# ── role mapping ───────────────────────────────────────────────────────────

def _split(s: str) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


def role_for_claims(claims: dict[str, Any]) -> str | None:
    """Map an OIDC userinfo dict to a Protek role. Returns None if denied."""
    email = (claims.get("email") or "").lower()
    if not email or not claims.get("email_verified", True):
        # Some IDPs omit email_verified entirely — treat absence as verified.
        if "email_verified" in claims and not claims.get("email_verified"):
            return None

    domains = _split(_envstr("OIDC_ALLOWED_DOMAINS"))
    if domains:
        if not any(email.endswith("@" + d) for d in domains):
            return None

    claim_key = _envstr("OIDC_GROUPS_CLAIM") or "groups"
    groups = claims.get(claim_key) or []
    if isinstance(groups, str):
        groups = [groups]
    g_set = {str(g) for g in groups}

    admin_g    = set(_split(_envstr("OIDC_GROUPS_ADMIN")))
    operator_g = set(_split(_envstr("OIDC_GROUPS_OPERATOR")))
    viewer_g   = set(_split(_envstr("OIDC_GROUPS_VIEWER")))

    if g_set & admin_g:
        return "admin"
    if g_set & operator_g:
        return "operator"
    if g_set & viewer_g:
        return "viewer"

    default = _envstr("OIDC_DEFAULT_ROLE")
    if default in ("admin", "operator", "viewer"):
        return default
    return None  # explicit deny


# ── user provisioning ──────────────────────────────────────────────────────

def upsert_sso_user(email: str, role: str, idp_sub: str) -> dict[str, Any]:
    """Idempotently create / update a `users` row keyed by email. SSO users
    have a random unguessable password_hash (they can't log in via /login)
    and a placeholder totp_secret (TOTP is the IDP's job).
    """
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT id, role, disabled FROM users WHERE username = ?", (email,)
        ).fetchone()
        if row:
            if int(row["disabled"] or 0):
                raise PermissionError("user disabled")
            # Refresh role each login so IDP-side changes propagate
            conn.execute(
                "UPDATE users SET role = ?, last_login_at = ? WHERE id = ?",
                (role, now, row["id"]),
            )
            return {"id": row["id"], "username": email, "role": role}
        # Generate a random, unusable password hash — SSO users authenticate
        # via the IDP only. There's no local password to brute force.
        random_pw = secrets.token_urlsafe(64).encode()
        pw_hash = bcrypt.hashpw(random_pw, bcrypt.gensalt(rounds=10)).decode()
        # Random base32 totp_secret too (never validated for SSO users)
        cur = conn.execute(
            """
            INSERT INTO users (username, password_hash, totp_secret, role,
                               created_at, last_login_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (email, pw_hash, "X" * 32, role, now, now),
        )
        return {"id": cur.lastrowid, "username": email, "role": role}
    finally:
        conn.close()


def init_oauth(app):
    """Attach an Authlib OAuth registry to the Flask app.

    Lazy because authlib is optional — if not installed, the /sso/* routes
    simply 503 with a clear message.
    """
    if not is_configured():
        return None
    try:
        from authlib.integrations.flask_client import OAuth
    except ImportError:
        log.warning("authlib not installed — /sso/* will 503")
        return None
    oauth = OAuth(app)
    issuer = _envstr("OIDC_ISSUER").rstrip("/")
    oauth.register(
        name="oidc",
        client_id=_envstr("OIDC_CLIENT_ID"),
        client_secret=_envstr("OIDC_CLIENT_SECRET"),
        server_metadata_url=f"{issuer}/.well-known/openid-configuration",
        client_kwargs={"scope": _envstr("OIDC_SCOPES") or "openid email profile"},
    )
    return oauth
