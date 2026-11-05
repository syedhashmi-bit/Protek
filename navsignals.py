"""
navsignals.py — which advanced pages are in use, and which need attention.

Roadmap #3. In the simple view, advanced pages are hidden — unless the feature
is configured (hiding it would lose track of something that's running), and a
failing one shows with a warning badge. This answers both, per NAV tab key:

    signals() -> {"configured": set[str], "failing": set[str]}

It runs for every page render, so it is cheap by construction: one DB
connection, a handful of COUNTs, one `settings` read with IN (...), no
network, no cscli, no page helpers (those probe targets or touch schema).
Results are cached per process for CACHE_SEC. Tables created lazily
(protek_peers, synthetic_tests, backup_runs) may not exist yet — every query
tolerates that.
"""

from __future__ import annotations

import os
import time
from typing import Any

CACHE_SEC = 15.0

_cache: dict[str, Any] = {"at": 0.0, "value": None}

_SETTING_KEYS = (
    "intel.publish.enabled", "settings.approval_required", "synthetic.enabled",
    "synthetic.last_status", "honeypot.enabled", "backup.enabled",
    "backup.last_daily_at", "backup.last_test_ok", "dr_drill.reminder_enabled",
    "backup.offsite.last_error", "backup.offsite.last_test_ok",
    "ha.role", "ha.auto_failover_enabled",
    "disk.warn_alerted", "disk.critical_alerted", "disk.wal_alerted",
)


def _count(conn, sql: str, args: tuple = ()) -> int:
    try:
        row = conn.execute(sql, args).fetchone()
        return int(row[0] or 0) if row else 0
    except Exception:  # noqa: BLE001 — missing lazy table, old schema
        return 0


def _compute() -> dict[str, set[str]]:
    from db import get_conn
    configured: set[str] = set()
    failing: set[str] = set()
    conn = get_conn()
    try:
        try:
            ph = ",".join("?" * len(_SETTING_KEYS))
            st = {r[0]: r[1] for r in conn.execute(
                f"SELECT key, value FROM settings WHERE key IN ({ph})", _SETTING_KEYS)}
        except Exception:  # noqa: BLE001
            st = {}
        on = lambda k: (st.get(k) or "") == "1"  # noqa: E731

        # Sources — the `local` row always exists, so only remote ones count.
        if _count(conn, "SELECT COUNT(*) FROM sources WHERE name != 'local' AND enabled = 1"):
            configured.add("federation")
        if _count(conn, "SELECT COUNT(*) FROM sources WHERE name != 'local' AND enabled = 1 "
                        "AND paused = 0 AND COALESCE(last_error, '') != ''"):
            failing.add("federation")
        if _count(conn, "SELECT COUNT(*) FROM protek_peers WHERE enabled = 1"):
            configured.add("peers")
        if _count(conn, "SELECT COUNT(*) FROM protek_peers WHERE enabled = 1 AND "
                        "(COALESCE(last_error, '') != '' OR "
                        "(last_pull_at IS NOT NULL AND last_pull_ok = 0))"):
            failing.add("peers")

        # Targets added beyond the .env router.
        if _count(conn, "SELECT COUNT(*) FROM bouncer_targets WHERE enabled = 1"):
            configured.add("fleet")

        if on("settings.approval_required") or _count(
                conn, "SELECT COUNT(*) FROM approval_queue WHERE status = 'pending'"):
            configured.add("approvals")
        if _count(conn, "SELECT COUNT(*) FROM alert_states "
                        "WHERE rule_key = 'approval_backlog' AND firing = 1"):
            failing.add("approvals")

        if on("intel.publish.enabled"):
            configured.add("intel_publish")
        if _count(conn, "SELECT COUNT(*) FROM asn_escalations WHERE status = 'pending'"):
            configured.add("asn_escalations")

        if on("synthetic.enabled"):
            configured.add("synthetic")
        if (st.get("synthetic.last_status") or "") in ("failed", "partial"):
            failing.add("synthetic")
        if any(on(k) for k in ("disk.warn_alerted", "disk.critical_alerted", "disk.wal_alerted")):
            failing.add("perf")

        if _count(conn, "SELECT COUNT(*) FROM webhook_subs WHERE enabled = 1"):
            configured.add("webhooks")
        if _count(conn, "SELECT COUNT(*) FROM webhook_subs WHERE enabled = 1 AND consec_failures > 0"):
            failing.add("webhooks")
        if (os.environ.get("SYSLOG_HOST") or os.environ.get("SIEM_WEBHOOK_URL") or "").strip():
            configured.add("siem")

        if on("honeypot.enabled"):
            configured.add("honeypot")
        if _count(conn, "SELECT COUNT(*) FROM api_tokens WHERE disabled = 0"):
            configured.add("admin_tokens")

        # Off-box backups may run from a systemd timer with backup.enabled=0
        # (MEMORY.md), so a recent run counts as configured too.
        if on("backup.enabled") or st.get("backup.last_daily_at"):
            configured.add("admin_backup_auto")
        if (st.get("backup.last_test_ok") or "") == "0" \
                or (st.get("backup.offsite.last_error") or "") \
                or (st.get("backup.offsite.last_test_ok") or "") == "0":
            failing.add("admin_backup_auto")
        else:
            try:
                row = conn.execute("SELECT status FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone()
                if row and row[0] == "failed":
                    failing.add("admin_backup_auto")
            except Exception:  # noqa: BLE001
                pass

        if on("dr_drill.reminder_enabled"):
            configured.add("dr_drill")
        if (st.get("ha.role") or "").strip() or on("ha.auto_failover_enabled") \
                or (os.environ.get("HA_ROLE") or "").strip():
            configured.add("admin_ha")
    finally:
        conn.close()
    # Anything failing is in use by definition.
    configured |= failing
    return {"configured": configured, "failing": failing}


def signals() -> dict[str, set[str]]:
    now = time.monotonic()
    if _cache["value"] is None or now - _cache["at"] > CACHE_SEC:
        try:
            _cache["value"] = _compute()
        except Exception:  # noqa: BLE001 — the menu must still render
            _cache["value"] = {"configured": set(), "failing": set()}
        _cache["at"] = now
    return _cache["value"]


def reset_cache() -> None:
    _cache["value"] = None
