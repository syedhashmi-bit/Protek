"""
digest.py — daily roll-up notifier.

`maybe_fire_daily()` is called from poller.tick() on every cycle. It:
  1. Reads `digest.last_daily_at` setting.
  2. If the current calendar day differs from last_daily_at's day, builds a
     compact summary of the previous 24h and ships it as a `daily_digest`
     notification.
  3. Updates the setting so the next ~24h of cycles are no-ops.

This lives outside notifications.py because the digest needs to query
several tables (decisions / alerts / sync_events / login_audit) and the
notification module is intentionally I/O-thin.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from db import get_conn, get_setting, set_setting

log = logging.getLogger("protek.digest")


def _build_payload() -> dict[str, object]:
    """Snapshot the last 24h."""
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    conn = get_conn()
    try:
        new_bans = conn.execute(
            "SELECT COUNT(DISTINCT value) AS n FROM decisions "
            "WHERE first_seen_at >= ? AND deleted_at IS NULL",
            (since,),
        ).fetchone()["n"]
        active_total = conn.execute(
            "SELECT COUNT(DISTINCT value) AS n FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()["n"]
        top_scenarios = conn.execute(
            """SELECT scenario, COUNT(DISTINCT value) AS n
               FROM decisions
               WHERE first_seen_at >= ? AND deleted_at IS NULL
               GROUP BY scenario
               ORDER BY n DESC LIMIT 5""",
            (since,),
        ).fetchall()
        top_countries = conn.execute(
            """SELECT g.country_code AS cc, COUNT(DISTINCT d.value) AS n
               FROM decisions d
               LEFT JOIN geo_cache g ON g.ip = d.value
               WHERE d.first_seen_at >= ? AND d.deleted_at IS NULL
                 AND g.country_code IS NOT NULL AND g.country_code != ''
               GROUP BY g.country_code
               ORDER BY n DESC LIMIT 5""",
            (since,),
        ).fetchall()
        sync_cycles = conn.execute(
            "SELECT COUNT(*) AS n, SUM(errors) AS errs "
            "FROM sync_events WHERE started_at >= ?",
            (since,),
        ).fetchone()
        login_fails = conn.execute(
            "SELECT COUNT(*) AS n FROM login_audit "
            "WHERE created_at >= ? AND success = 0",
            (since,),
        ).fetchone()["n"]
        whitelist_saves = conn.execute(
            "SELECT COUNT(*) AS n FROM whitelist_hits WHERE created_at >= ?",
            (since,),
        ).fetchone()["n"]
    finally:
        conn.close()
    return {
        "new_bans": int(new_bans or 0),
        "active_total": int(active_total or 0),
        "top_scenarios": [(r["scenario"], r["n"]) for r in top_scenarios],
        "top_countries": [(r["cc"], r["n"]) for r in top_countries],
        "sync_cycles": int(sync_cycles["n"] or 0),
        "sync_errors": int(sync_cycles["errs"] or 0),
        "login_fails": int(login_fails or 0),
        "whitelist_saves": int(whitelist_saves or 0),
    }


def _format(p: dict[str, object]) -> str:
    lines = [
        f"📊 **Last 24h** — {p['new_bans']} new bans (total active: {p['active_total']})",
        "",
        "Top scenarios:",
    ]
    for scen, n in p["top_scenarios"] or [("(none)", 0)]:
        lines.append(f"  • {scen} — {n}")
    if p["top_countries"]:
        lines.append("")
        lines.append("Top source countries:")
        for cc, n in p["top_countries"]:
            lines.append(f"  • {cc} — {n}")
    lines.append("")
    lines.append(
        f"Reconcile: {p['sync_cycles']} cycles · {p['sync_errors']} errors  "
        f"·  Whitelist saves: {p['whitelist_saves']}  ·  Failed logins: {p['login_fails']}"
    )
    return "\n".join(lines)


def maybe_fire_daily() -> bool:
    """Returns True if a digest was actually fired this call."""
    now = datetime.now(timezone.utc)
    last_at = get_setting("digest.last_daily_at") or ""
    if last_at:
        try:
            last_dt = datetime.fromisoformat(last_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            last_dt = now - timedelta(days=2)
        if last_dt.date() == now.date():
            return False  # already fired today
    payload = _build_payload()
    body = _format(payload)
    try:
        import notifications, siem
        notifications.send("daily_digest", body, subject="Daily digest")
        siem.ship("digest.daily", payload)
    except Exception as e:  # noqa: BLE001
        log.warning("daily digest send failed: %s", e)
        return False
    set_setting("digest.last_daily_at", now.isoformat())
    log.info("daily digest fired: %d new bans, %d cycles", payload["new_bans"], payload["sync_cycles"])
    return True
