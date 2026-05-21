"""
audit.py — Arc 6 phase 35. Append-only operator-action audit log.

Writes go into the `audit_log` table (created in db.py). The table has no
UPDATE/DELETE callers anywhere in Protek — by convention every meaningful
operator action passes through `record()` here, and the `/audit` page is
read-only.

A `before`/`after` diff (JSON-serialized) is captured per action so an
operator can see what changed without re-creating their reasoning.

For correlation with the SIEM, each audit row is also shipped as a
`settings.changed` SIEM event (event_type intentionally generic — the
`action` field carries the specifics).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from db import get_conn

log = logging.getLogger("protek.audit")


def record(action: str, *, actor: str = "", ip: str = "",
           target: str = "", before: Any = None, after: Any = None,
           note: str = "") -> int | None:
    """Append a row to audit_log. Returns the new row id (or None on failure).

    Best-effort — auditing must never break the action it is recording.
    """
    try:
        conn = get_conn()
        try:
            cur = conn.execute(
                """
                INSERT INTO audit_log
                    (created_at, actor, ip, action, target, before_json, after_json, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    actor or "",
                    ip or "",
                    action,
                    target or "",
                    "" if before is None else json.dumps(before, default=str)[:4000],
                    "" if after is None else json.dumps(after, default=str)[:4000],
                    note or "",
                ),
            )
            row_id = cur.lastrowid
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        log.warning("audit record failed (action=%s): %s", action, e)
        return None
    # Mirror to SIEM as a settings.changed event for downstream correlation.
    try:
        import siem
        siem.ship("settings.changed", {
            "action": action,
            "actor": actor or "",
            "ip": ip or "",
            "target": target or "",
            "note": note or "",
        })
    except Exception as e:  # noqa: BLE001
        log.debug("audit→siem mirror swallowed: %s", e)
    return row_id


def recent(limit: int = 200, action_filter: str = "") -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        if action_filter:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE action LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (f"%{action_filter}%", int(limit)),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]
