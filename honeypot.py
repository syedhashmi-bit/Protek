"""
honeypot.py — Phase 61. Honeypot routing for high-score attackers.

Protek doesn't run a honeypot — operator owns that. What we do:
  1. Maintain a tagged set of IPs flagged as 'honeypot-bound' (reputation
     ≥ threshold + matching criteria).
  2. Expose them via /api/v1/honeypot/targets so a CF Worker, nginx
     auth_request, or similar can route those IPs to the honeypot URL
     instead of blocking outright.
  3. Capture any callbacks the honeypot makes (operator can POST to
     /api/external/honeypot/callback with token auth) — feeds back into
     the reputation breakdown via tags.

Settings:
    honeypot.enabled        bool, default 0
    honeypot.url            optional URL for documentation only
    honeypot.min_reputation default 80 (auto tier)
    honeypot.max_targets    default 1000

This is purely additive — no decisions are removed from the active set; we
just mark them. The operator chooses what to do with the list (block, redirect,
slow-walk, etc.).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from db import get_conn, get_setting

log = logging.getLogger("protek.honeypot")


def _setting_int(key: str, default: int) -> int:
    v = get_setting(key)
    try:
        return int(v) if v else default
    except (TypeError, ValueError):
        return default


def is_enabled() -> bool:
    return (get_setting("honeypot.enabled") or "0") == "1"


def refresh_targets() -> dict:
    """Recompute the honeypot target set based on current decisions +
    reputation. Tags qualifying IPs with 'honeypot-bound'; clears the tag
    from IPs that no longer qualify.

    Called from the poller every N cycles when enabled.
    """
    if not is_enabled():
        return {"enabled": False}
    min_rep = _setting_int("honeypot.min_reputation", 80)
    max_targets = _setting_int("honeypot.max_targets", 1000)

    import reputation
    qualifying = sorted(reputation.bulk_compute_for_min(min_rep))[:max_targets]
    qualifying_set = set(qualifying)
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat()
    conn = get_conn()
    added = removed = 0
    try:
        existing = {r["ip"] for r in conn.execute(
            "SELECT ip FROM ip_tags WHERE tag = 'honeypot-bound' "
            "AND (expires_at IS NULL OR expires_at > datetime('now'))"
        ).fetchall()}
        for ip in qualifying_set - existing:
            conn.execute(
                """INSERT INTO ip_tags (ip, tag, source, created_at, expires_at)
                   VALUES (?, 'honeypot-bound', 'honeypot.refresh', ?, ?)
                   ON CONFLICT(ip, tag) DO UPDATE SET expires_at = excluded.expires_at""",
                (ip, now, expires),
            )
            added += 1
        for ip in existing - qualifying_set:
            conn.execute("DELETE FROM ip_tags WHERE ip = ? AND tag = 'honeypot-bound'", (ip,))
            removed += 1
    finally:
        conn.close()
    return {"enabled": True, "qualifying": len(qualifying),
            "added": added, "removed": removed,
            "min_reputation": min_rep, "max_targets": max_targets}


def list_targets(limit: int = 1000) -> list[str]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT ip FROM ip_tags WHERE tag = 'honeypot-bound' "
            "AND (expires_at IS NULL OR expires_at > datetime('now')) "
            "ORDER BY created_at DESC LIMIT ?", (int(limit),),
        ).fetchall()
    finally:
        conn.close()
    return [r["ip"] for r in rows]


def record_callback(ip: str, payload: dict) -> None:
    """Operator's honeypot reports back — we just SIEM it and tag the IP."""
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO ip_tags (ip, tag, source, created_at, expires_at)
               VALUES (?, 'honeypot-confirmed', 'honeypot.callback', ?, ?)
               ON CONFLICT(ip, tag) DO UPDATE SET expires_at = excluded.expires_at""",
            (ip, now, expires),
        )
    finally:
        conn.close()
    try:
        import siem
        siem.ship("honeypot.callback", {"ip": ip, "payload": payload})
    except Exception:  # noqa: BLE001
        pass
