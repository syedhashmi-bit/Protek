"""
alerting.py — Arc 6 phase 38. Composite alert rules with dedup, auto-resolve,
per-channel routing, and silencing.

Design:
  - Each rule is a pure-Python predicate `(state) -> (firing: bool, msg: str)`.
  - `tick()` runs every rule once, then for each rule:
      * if the rule was firing last cycle AND is firing now      → unchanged (dedup)
      * if the rule was NOT firing last cycle AND fires now      → emit "firing" notification
      * if the rule was firing last cycle AND no longer fires    → emit "resolved" notification (auto-resolve)
      * suppressed by an active silence?                         → don't emit, but still track state
  - Notification channel routing is by SEVERITY:
      crit (level 2)  → all configured channels (Discord + Telegram + Email)
      warn (level 4)  → Discord only
      info (level 6)  → Discord only (silent by default; user can disable)
  - Notifications are also mirrored as `alert.firing`/`alert.resolved` SIEM events.

Acceptance for phase 38:
  - Simulated MT outage → critical alert within 2 min (mt_unreachable_2m has
    debounce 12 cycles × 10s = 120s).
  - Recovery within one cycle (10s) → auto-resolve notification.
"""

from __future__ import annotations

import fnmatch
import logging
from datetime import datetime, timezone
from typing import Any, Callable

from db import get_conn, get_setting

log = logging.getLogger("protek.alerting")

# Severity values match RFC 5424 used in siem.py.
LVL_CRIT = 2
LVL_ERR  = 3
LVL_WARN = 4
LVL_INFO = 6


# ── Rule definitions ───────────────────────────────────────────────────────

def _state_snapshot() -> dict[str, Any]:
    """One-shot read of everything the rules might need."""
    now = datetime.now(timezone.utc)
    last_at_str = get_setting("poller.last_at") or ""
    last_at = None
    if last_at_str:
        try:
            last_at = datetime.fromisoformat(last_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            last_at = None
    poll_lag_sec = (now - last_at).total_seconds() if last_at else 1e9
    conn = get_conn()
    try:
        recent_errs = conn.execute(
            "SELECT errors FROM sync_events ORDER BY id DESC LIMIT 5"
        ).fetchall()
        approval_pending = conn.execute(
            "SELECT COUNT(*) AS n FROM approval_queue WHERE status = 'pending'"
        ).fetchone()["n"]
        # MT cache (the small TTL'd snapshot kept in app.py)
        mt_last = get_setting("mt.last_ok_at")
        mt_status = get_setting("mt.last_status") or ""
    finally:
        conn.close()
    return {
        "now": now,
        "poll_lag_sec": poll_lag_sec,
        "poller_last_ok": (get_setting("poller.last_ok") == "1"),
        "poller_last_error": get_setting("poller.last_error") or "",
        "recent_errs": [int(r["errors"] or 0) for r in recent_errs],
        "reconcile_errors": int(get_setting("reconcile.last_errors") or "0"),
        "approval_pending": int(approval_pending or 0),
        "mt_last_ok_at": mt_last,
        "mt_status": mt_status,
    }


def _rule_lapi_down(s) -> tuple[bool, str]:
    return (not s["poller_last_ok"],
            f"poller last error: {s['poller_last_error']}")


def _rule_sync_stale(s) -> tuple[bool, str]:
    # Stale = > 5 min since end-of-cycle; far stricter than /health's threshold.
    return (s["poll_lag_sec"] > 300,
            f"last poll {s['poll_lag_sec']:.0f}s ago")


def _rule_mt_unreachable(s) -> tuple[bool, str]:
    return (s["mt_status"] == "down",
            f"mt status = {s['mt_status']}")


def _rule_sync_errors_burst(s) -> tuple[bool, str]:
    # All of the last 5 cycles had errors.
    burst = s["recent_errs"] and len(s["recent_errs"]) == 5 and all(e > 0 for e in s["recent_errs"])
    return (bool(burst),
            f"5/5 recent cycles errored ({s['recent_errs']})")


def _rule_approval_backlog(s) -> tuple[bool, str]:
    return (s["approval_pending"] > 50,
            f"{s['approval_pending']} decisions awaiting approval")


# (rule_key, title, level, predicate, debounce_cycles)
RULES: list[tuple[str, str, int, Callable, int]] = [
    ("lapi_down_5m",        "LAPI down ≥ 5 min",              LVL_CRIT, _rule_lapi_down,        30),
    ("sync_stale_5m",       "Reconcile cycle stale ≥ 5 min",  LVL_CRIT, _rule_sync_stale,        1),
    ("mt_unreachable_2m",   "MikroTik unreachable ≥ 2 min",   LVL_CRIT, _rule_mt_unreachable,   12),
    ("sync_errors_burst",   "Sync errors on 5 consecutive cycles", LVL_WARN, _rule_sync_errors_burst, 1),
    ("approval_backlog",    "Approval queue > 50",            LVL_INFO, _rule_approval_backlog,  6),
]


# ── State persistence ──────────────────────────────────────────────────────

def _load_state(rule_key: str) -> dict[str, Any]:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM alert_states WHERE rule_key = ?", (rule_key,)
        ).fetchone()
    finally:
        conn.close()
    if row:
        return dict(row)
    return {
        "rule_key": rule_key, "firing": 0, "level": LVL_INFO,
        "firing_since": None, "last_check": "", "last_message": "",
        "last_notified": None, "consecutive": 0,
    }


def _save_state(rule_key: str, *, firing: bool, level: int,
                firing_since: str | None, message: str,
                consecutive: int, notified: bool) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        existing = conn.execute(
            "SELECT 1 FROM alert_states WHERE rule_key = ?", (rule_key,)
        ).fetchone()
        if existing:
            conn.execute(
                """UPDATE alert_states SET
                       firing = ?, level = ?, firing_since = ?, last_check = ?,
                       last_message = ?, consecutive = ?,
                       last_notified = CASE WHEN ? = 1 THEN ? ELSE last_notified END
                   WHERE rule_key = ?""",
                (1 if firing else 0, level, firing_since, now, message[:300],
                 consecutive, 1 if notified else 0, now, rule_key),
            )
        else:
            conn.execute(
                """INSERT INTO alert_states
                     (rule_key, firing, level, firing_since, last_check, last_message,
                      last_notified, consecutive)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (rule_key, 1 if firing else 0, level, firing_since, now,
                 message[:300], now if notified else None, consecutive),
            )
    finally:
        conn.close()


# ── Silencing ──────────────────────────────────────────────────────────────

def is_silenced(rule_key: str) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM alert_silences WHERE until_at > ?", (now,)
        ).fetchall()
    finally:
        conn.close()
    for r in rows:
        if fnmatch.fnmatchcase(rule_key, r["pattern"]):
            return dict(r)
    return None


def add_silence(pattern: str, until_at: str, reason: str, actor: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        cur = conn.execute(
            """INSERT INTO alert_silences (pattern, until_at, reason, created_at, created_by)
               VALUES (?, ?, ?, ?, ?)""",
            (pattern, until_at, reason, now, actor),
        )
        return cur.lastrowid or 0
    finally:
        conn.close()


def remove_silence(silence_id: int) -> None:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM alert_silences WHERE id = ?", (silence_id,))
    finally:
        conn.close()


def list_silences(include_expired: bool = False) -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        if include_expired:
            rows = conn.execute(
                "SELECT * FROM alert_silences ORDER BY id DESC"
            ).fetchall()
        else:
            now = datetime.now(timezone.utc).isoformat()
            rows = conn.execute(
                "SELECT * FROM alert_silences WHERE until_at > ? ORDER BY id DESC",
                (now,),
            ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# ── Notification routing ───────────────────────────────────────────────────

def _route_for(level: int) -> list[str]:
    """Return notification channels for a given severity."""
    if level <= LVL_CRIT:
        return ["discord", "telegram", "email"]
    return ["discord"]


def _notify(rule_key: str, title: str, level: int, message: str,
            resolved: bool = False) -> None:
    """Best-effort: fire to allowed channels + ship a SIEM event.

    Channel routing precedence:
      1. Per-rule override from settings (`alerting.rule.<key>.channels` —
         comma-separated like "discord,telegram"). Operator-set at /alerts/rules.
      2. Default severity → channels map (crit → all, warn/info → discord only).
    """
    import notifications as notif
    import siem
    from db import get_setting as _gs
    subject = f"[{'RESOLVED' if resolved else 'FIRING'}] {title}"
    body = message if not resolved else f"RESOLVED — {message}"
    override = _gs(f"alerting.rule.{rule_key}.channels") or ""
    if override:
        channels = [c.strip() for c in override.split(",") if c.strip()]
    else:
        channels = _route_for(level)
    notif.send("alert.firing" if not resolved else "alert.resolved",
               body, subject=subject, channels=channels)
    try:
        siem.ship("alert.resolved" if resolved else "alert.firing", {
            "rule": rule_key, "title": title, "level": level, "message": message,
            "channels": channels,
        })
    except Exception:  # noqa: BLE001
        pass


# ── Main tick ─────────────────────────────────────────────────────────────

def tick() -> list[dict[str, Any]]:
    """Evaluate all rules; persist state; fire notifications on transition.

    Returns a list of {rule_key, firing, level, message, since, suppressed}.
    """
    s = _state_snapshot()
    out: list[dict[str, Any]] = []
    for key, title, level, predicate, debounce in RULES:
        try:
            firing_now, msg = predicate(s)
        except Exception as e:  # noqa: BLE001
            log.warning("rule %s crashed: %s", key, e)
            continue
        prev = _load_state(key)
        was_firing = bool(prev["firing"])
        consecutive = prev["consecutive"] or 0
        if firing_now:
            consecutive += 1
        else:
            consecutive = 0
        # Debounce: rule is "active" only after N consecutive matches.
        active = consecutive >= debounce

        silence = is_silenced(key)
        suppressed = silence is not None

        notified = False
        firing_since = prev["firing_since"]
        # Transition into firing (post-debounce, not suppressed)
        if active and not was_firing and not suppressed:
            firing_since = s["now"].isoformat()
            _notify(key, title, level, msg, resolved=False)
            notified = True
        # Transition out of firing (rule no longer matches at all)
        elif was_firing and not firing_now and not suppressed:
            _notify(key, title, level, msg or "condition cleared", resolved=True)
            firing_since = None
            notified = True

        store_firing = active and not suppressed
        _save_state(key, firing=store_firing, level=level,
                    firing_since=firing_since, message=msg,
                    consecutive=consecutive, notified=notified)
        out.append({
            "rule_key": key, "title": title, "level": level,
            "firing": store_firing, "message": msg,
            "firing_since": firing_since, "suppressed": suppressed,
            "silence": silence,
            "consecutive": consecutive, "debounce": debounce,
        })
    return out
