"""hygiene.py — alert on the slow, silent failures.

2026-10-16. The disk incidents were loud; what let them build up was quiet:
`retention.enabled` sat at '0' for weeks (decisions reached 15.7M rows,
mt_pushes 5.3M), and there was no successful backup from 2026-09-01 to
2026-10-15. backup.py notifies when a run *fails*, but nothing noticed a
run that never happened, and nothing noticed retention being off at all.

So this checks outcomes, not events:
  - backup_stale       newest successful daily backup older than
                       hygiene.backup_max_age_h (default 36h). Catches a
                       failing job, a dead timer and a broken wrapper alike.
  - backup_unverified  the last restore-test failed.
  - retention_disabled retention.enabled is not '1'.

Each finding alerts once, re-alerts every hygiene.renag_h (default 24h)
while it persists, and sends one recovery message when it clears. State
lives in the settings table, so a service restart neither re-alerts nor
forgets. Called hourly from the poller's maintenance slot; `findings()`
is side-effect free and also feeds /health's `warnings`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from db import get_setting, set_setting

log = logging.getLogger("protek.hygiene")

DEFAULT_BACKUP_MAX_AGE_H = 36
DEFAULT_RENAG_H = 24

MESSAGES = {
    "backup_stale": "No successful Protek backup in {age}. Check "
                    "`systemctl status protek-backup.timer protek-backup.service` "
                    "and `journalctl -u protek-backup`.",
    "backup_unverified": "The last Protek backup failed its restore-test — "
                         "the newest bundle may not be restorable.",
    "retention_disabled": "Protek retention is disabled (retention.enabled != '1'). "
                          "mt_pushes and decision tombstones will grow without bound.",
}


def _hours(key: str, default: int) -> float:
    try:
        return max(1.0, float(get_setting(key) or default))
    except (TypeError, ValueError):
        return float(default)


def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def findings(now: datetime | None = None) -> dict[str, str]:
    """{finding: detail} for every current problem. No side effects."""
    now = now or datetime.now(timezone.utc)
    out: dict[str, str] = {}

    # Only judge freshness once a backup has ever succeeded here — an
    # install that never configured backups shouldn't nag about them.
    last = _parse(get_setting("backup.last_daily_at"))
    if last is not None:
        age_h = (now - last).total_seconds() / 3600
        if age_h > _hours("hygiene.backup_max_age_h", DEFAULT_BACKUP_MAX_AGE_H):
            age = f"{age_h / 24:.1f} days" if age_h >= 48 else f"{age_h:.0f}h"
            out["backup_stale"] = MESSAGES["backup_stale"].format(age=age)

    if get_setting("backup.last_test_ok") == "0":
        out["backup_unverified"] = MESSAGES["backup_unverified"]

    if (get_setting("retention.enabled") or "1") != "1":
        out["retention_disabled"] = MESSAGES["retention_disabled"]

    return out


def _send(subject: str, message: str) -> None:
    try:
        import notifications
        notifications.send("sync_error", message, subject=subject)
    except Exception as e:  # noqa: BLE001 — alerting must never break the caller
        log.warning("hygiene notify failed: %s", e)


def check_and_alert(now: datetime | None = None) -> dict[str, str]:
    """Alert on new or persisting findings, announce recoveries."""
    now = now or datetime.now(timezone.utc)
    current = findings(now)
    renag_s = _hours("hygiene.renag_h", DEFAULT_RENAG_H) * 3600

    for key in MESSAGES:
        state_key = f"hygiene.{key}.alerted_at"
        alerted_at = _parse(get_setting(state_key))
        if key in current:
            if alerted_at is None or (now - alerted_at).total_seconds() >= renag_s:
                log.warning("hygiene: %s — %s", key, current[key])
                _send(f"[Protek] {key.replace('_', ' ')}", current[key])
                set_setting(state_key, now.isoformat())
        elif alerted_at is not None:
            log.info("hygiene: %s recovered", key)
            _send(f"[Protek] {key.replace('_', ' ')} — recovered",
                  f"Recovered: {key.replace('_', ' ')} is no longer a problem.")
            set_setting(state_key, "")
    return current


def warnings() -> list[str]:
    """Finding names for /health. Never raises."""
    try:
        return sorted(findings())
    except Exception:  # noqa: BLE001
        return []


def status() -> dict[str, Any]:
    return {"findings": findings(),
            "backup_last_daily_at": get_setting("backup.last_daily_at"),
            "retention_enabled": (get_setting("retention.enabled") or "1") == "1"}
