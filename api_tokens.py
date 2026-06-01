"""
api_tokens.py — Phase 47 foundation. Bearer tokens for /api/v1/* and
/api/external/* and the protekctl CLI.

Storage: only sha256(token) is persisted, never the token itself. On creation
we return the plaintext token ONCE; the operator captures it then. Subsequent
reads can only show prefix + last_used metadata.

Scopes are comma-separated strings. Recognised values:
    read    — GET /api/v1/* (decisions, alerts, sync status, metrics-ish reads)
    write   — POST /api/external/decisions, POST /api/v1/sync/run, whitelist mgmt
    admin   — user/token management, settings updates

`require_token(scope)` is the decorator routes use to gate themselves. It also
stamps `last_used_at` + `last_used_ip` on every successful auth.
"""

from __future__ import annotations

import hashlib
import secrets as pysecrets
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from flask import g, jsonify, request

from db import get_conn

SCOPE_ORDER = {"read": 1, "write": 2, "admin": 3}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def create_token(name: str, scopes: str, created_by: str,
                 expires_at: str | None = None) -> dict[str, Any]:
    """Return {token, prefix, id, ...}. The plaintext token appears once."""
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError("name must be alphanumeric (plus _ and -)")
    scope_set = {s.strip() for s in (scopes or "").split(",") if s.strip()}
    for s in scope_set:
        if s not in SCOPE_ORDER:
            raise ValueError(f"unknown scope: {s}")
    if not scope_set:
        raise ValueError("at least one scope required")
    # 32 random bytes → 43-char urlsafe string. Prefix "pk_" so it's
    # recognisable in logs and so the prefix-display is meaningful.
    raw = "pk_" + pysecrets.token_urlsafe(32)
    h = _hash(raw)
    prefix = raw[:11]  # "pk_" + 8 chars
    conn = get_conn()
    try:
        cur = conn.execute(
            """INSERT INTO api_tokens
                 (name, token_hash, token_prefix, scopes, created_by, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (name, h, prefix, ",".join(sorted(scope_set)), created_by, _now(), expires_at),
        )
        tid = cur.lastrowid
    finally:
        conn.close()
    return {
        "id": tid, "token": raw, "prefix": prefix,
        "scopes": sorted(scope_set), "name": name,
        "warning": "This token is shown ONCE. Capture it now — it cannot be recovered.",
    }


def list_tokens() -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, name, token_prefix, scopes, created_by, created_at, "
            "expires_at, last_used_at, last_used_ip, disabled "
            "FROM api_tokens ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def revoke_token(token_id: int) -> None:
    conn = get_conn()
    try:
        conn.execute("UPDATE api_tokens SET disabled = 1 WHERE id = ?", (token_id,))
    finally:
        conn.close()


def delete_token(token_id: int) -> None:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM api_tokens WHERE id = ?", (token_id,))
    finally:
        conn.close()


def lookup(raw_token: str) -> dict[str, Any] | None:
    """Look up a token by its plaintext value. Updates last_used_* on hit.
    Returns the token row (with parsed scopes set) or None."""
    if not raw_token:
        return None
    h = _hash(raw_token)
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM api_tokens WHERE token_hash = ? AND disabled = 0",
            (h,),
        ).fetchone()
        if not row:
            return None
        # Expiry
        if row["expires_at"]:
            try:
                if datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")) < datetime.now(timezone.utc):
                    return None
            except (ValueError, AttributeError):
                pass
        # Stamp last_used
        try:
            ip = request.remote_addr or ""
        except RuntimeError:
            ip = ""
        conn.execute(
            "UPDATE api_tokens SET last_used_at = ?, last_used_ip = ? WHERE id = ?",
            (_now(), ip, row["id"]),
        )
    finally:
        conn.close()
    d = dict(row)
    d["scope_set"] = {s.strip() for s in (d.get("scopes") or "").split(",") if s.strip()}
    return d


def has_scope(token: dict[str, Any], required: str) -> bool:
    """A token granted `admin` also implies `write` + `read`. A `write` token
    implies `read`. Explicit scopes are still the source of truth for any
    custom granularity later."""
    granted = token.get("scope_set") or set()
    if required in granted:
        return True
    if required == "read" and ("write" in granted or "admin" in granted):
        return True
    if required == "write" and "admin" in granted:
        return True
    return False


def require_token(scope: str):
    """Flask decorator. Pulls `Authorization: Bearer <token>` (or
    `X-Protek-Token`), verifies + scope-checks, sets `g.api_token` on success.
    Replies 401 / 403 on failure (no body bytes given to a bad caller)."""
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            raw = ""
            auth_hdr = request.headers.get("Authorization", "")
            if auth_hdr.startswith("Bearer "):
                raw = auth_hdr[7:].strip()
            elif request.headers.get("X-Protek-Token"):
                raw = request.headers.get("X-Protek-Token", "").strip()
            tok = lookup(raw) if raw else None
            if not tok:
                return jsonify(error="unauthorized"), 401
            if not has_scope(tok, scope):
                return jsonify(error="insufficient_scope",
                               required=scope, granted=sorted(tok["scope_set"])), 403
            g.api_token = tok
            return view(*args, **kwargs)
        return wrapper
    return deco
