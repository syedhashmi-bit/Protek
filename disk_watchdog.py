"""
disk_watchdog.py — Arc 15 phase 93. Disk pressure surfacing.

Two ENOSPC incidents within 3 days (2026-05-25 unbounded WAL growth,
2026-05-28 unbounded Litestream local-stage growth from a silent
SSH_FX_FAILURE) shared a single shape: the failure was externally
visible (`df -h` showed 100%) but invisible to `/health`. SQLite went
read-only underneath a still-green `/health` because the existing
checks gate on poll/MT state, not on filesystem capacity.

This module is the missing observability:

  - `sample()` — write one row to `disk_samples` (used_pct, free_bytes,
    total_bytes). Pruning is local to this call (FIFO at 1440 rows
    ≈ 24h @ 1/min) so no extra timer is needed.
  - `check_and_alert()` — edge-triggered warn/critical notification
    with hysteresis recovery, mirroring slo.alert_if_breached()'s
    pattern (settings-tracked `disk.*_alerted` so the operator gets
    exactly one notification per breach, plus a recovery edge).
  - `current()` — read latest sample for /perf rendering and /health.
  - `maybe_auto_rebaseline()` — at critical AND when
    `.protek.db-litestream/` accounts for >50% of /var/www/Protek/,
    optionally `rm -rf` the local LTX stage and restart litestream
    (which rebaselines from the replica). Master-gated by
    `disk.allow_auto_rebaseline='0'` default OFF — losing the local
    LTX chain is destructive and must be an explicit opt-in.

Thresholds + cadence settings (all read with defaults; no migration
row insert needed):

    disk.warn_pct                 default 70
    disk.critical_pct             default 90
    disk.check_every_cycles       default 6   (≈60 s at 10 s interval)
    disk.allow_auto_rebaseline    default '0' (off; '1' enables)
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db import DB_PATH, get_conn, get_setting, set_setting

log = logging.getLogger("protek.disk_watchdog")

# Recovery hysteresis: must drop this many points below warn_pct before we
# emit the recovery notification + clear the alerted flag. Stops flapping
# right at the threshold.
HYSTERESIS_PCT = 5

# Disk samples retention (24 h @ 1/min)
SAMPLES_CAP = 1440

# Default thresholds (settings override at runtime)
DEFAULT_WARN_PCT = 70
DEFAULT_CRITICAL_PCT = 90

PROTEK_DIR = Path(__file__).resolve().parent
LITESTREAM_STAGE_DIR = PROTEK_DIR / ".protek.db-litestream"


def _setting_float(key: str, default: float) -> float:
    raw = get_setting(key)
    if not raw:
        return float(default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float(default)


def sample() -> dict[str, Any]:
    """Take one disk sample, persist it, prune to the 1440-row cap.

    The sample is keyed off the filesystem holding protek.db (which is
    where ENOSPC actually hurts — the gunicorn worker can't checkpoint
    the WAL if that mount is full). `shutil.disk_usage(DB_PATH)` does
    the right thing here.
    """
    du = shutil.disk_usage(str(DB_PATH))
    used_pct = (du.used / du.total) * 100.0 if du.total else 0.0
    ts = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO disk_samples (ts, used_pct, free_bytes, total_bytes) "
            "VALUES (?, ?, ?, ?)",
            (ts, used_pct, du.free, du.total),
        )
        # Prune FIFO: keep newest SAMPLES_CAP rows. Cheap with the ts index.
        conn.execute(
            "DELETE FROM disk_samples WHERE id NOT IN ("
            "  SELECT id FROM disk_samples ORDER BY id DESC LIMIT ?"
            ")",
            (SAMPLES_CAP,),
        )
    finally:
        conn.close()
    return {"ts": ts, "used_pct": used_pct,
            "free_bytes": du.free, "total_bytes": du.total}


def current() -> dict[str, Any]:
    """Latest sample plus current thresholds — for /perf and /health.

    Falls back to a live `shutil.disk_usage` call if `disk_samples` is
    empty (boot before the first watchdog tick) so /health is never
    blind.
    """
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT ts, used_pct, free_bytes, total_bytes "
            "FROM disk_samples ORDER BY id DESC LIMIT 1"
        ).fetchone()
        max_row = conn.execute(
            "SELECT MAX(used_pct) AS max_pct FROM disk_samples "
            "WHERE ts >= datetime('now', '-1 day')"
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        du = shutil.disk_usage(str(DB_PATH))
        used_pct = (du.used / du.total) * 100.0 if du.total else 0.0
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "used_pct": used_pct,
            "free_bytes": du.free,
            "total_bytes": du.total,
            "max_pct_24h": used_pct,
            "warn_pct": _setting_float("disk.warn_pct", DEFAULT_WARN_PCT),
            "critical_pct": _setting_float("disk.critical_pct",
                                            DEFAULT_CRITICAL_PCT),
        }
    return {
        "ts": row["ts"],
        "used_pct": float(row["used_pct"]),
        "free_bytes": int(row["free_bytes"]),
        "total_bytes": int(row["total_bytes"]),
        "max_pct_24h": float(max_row["max_pct"] or row["used_pct"]),
        "warn_pct": _setting_float("disk.warn_pct", DEFAULT_WARN_PCT),
        "critical_pct": _setting_float("disk.critical_pct",
                                        DEFAULT_CRITICAL_PCT),
    }


def is_critical(used_pct: float | None = None) -> bool:
    """Lightweight check for /health. Reads the latest sample (or a live
    `shutil.disk_usage` call) and compares against `disk.critical_pct`.
    """
    if used_pct is None:
        used_pct = current()["used_pct"]
    return used_pct >= _setting_float("disk.critical_pct",
                                       DEFAULT_CRITICAL_PCT)


def check_and_alert() -> dict[str, Any]:
    """Edge-triggered warn/critical alerts with hysteresis recovery.

    Algorithm (mirrors slo.alert_if_breached's settings-tracked state
    machine, but with two thresholds instead of one):

      warn:
        - used_pct ≥ warn_pct AND not warn_alerted → fire notification
          once, set warn_alerted='1'.
        - used_pct < (warn_pct - HYSTERESIS) AND warn_alerted='1' →
          fire recovery notification, clear warn_alerted.
      critical: same shape with critical_pct + critical_alerted.

    Both edges always sample fresh state via sample(). Returns a dict
    describing what (if anything) fired this call — used by tests and
    optionally logged by the caller.
    """
    s = sample()
    warn_pct = _setting_float("disk.warn_pct", DEFAULT_WARN_PCT)
    crit_pct = _setting_float("disk.critical_pct", DEFAULT_CRITICAL_PCT)
    used_pct = s["used_pct"]

    out: dict[str, Any] = {
        "ts": s["ts"], "used_pct": used_pct,
        "warn_pct": warn_pct, "critical_pct": crit_pct,
        "fired": [],
    }

    # Lazy imports avoid circulars via app.py at module load.
    try:
        import notifications as nmod
    except Exception:  # noqa: BLE001
        nmod = None
    try:
        import siem as siem_mod
    except Exception:  # noqa: BLE001
        siem_mod = None

    warn_alerted = (get_setting("disk.warn_alerted") or "0") == "1"
    crit_alerted = (get_setting("disk.critical_alerted") or "0") == "1"

    free_gb = s["free_bytes"] / (1024 ** 3)
    total_gb = s["total_bytes"] / (1024 ** 3)

    def _fire(category: str, level: str, recovery: bool = False) -> None:
        verb = "recovered" if recovery else level
        msg = (f"Disk usage {used_pct:.1f}% on the protek.db filesystem "
               f"({free_gb:.1f} GB free / {total_gb:.1f} GB total). "
               f"Threshold: {warn_pct:.0f}% warn / {crit_pct:.0f}% critical. "
               f"Category: {verb}.")
        if nmod:
            try:
                nmod.send("sync_error", msg,
                          subject=f"[Protek] disk {verb}")
            except Exception:  # noqa: BLE001
                pass
        if siem_mod:
            try:
                siem_mod.ship(f"disk.{category}", {
                    "used_pct": round(used_pct, 1),
                    "free_bytes": s["free_bytes"],
                    "total_bytes": s["total_bytes"],
                    "warn_pct": warn_pct,
                    "critical_pct": crit_pct,
                    "recovery": recovery,
                }, severity=2 if level == "critical" else 4)
            except Exception:  # noqa: BLE001
                pass
        try:
            _audit(f"disk.{category}", {
                "used_pct": round(used_pct, 1),
                "free_bytes": s["free_bytes"],
                "recovery": recovery,
            })
        except Exception:  # noqa: BLE001
            pass
        out["fired"].append(f"{category}{'_recovery' if recovery else ''}")

    # Critical (evaluated first so we never silently skip critical because
    # the warn edge already fired this cycle).
    if used_pct >= crit_pct:
        if not crit_alerted:
            _fire("critical", "critical")
            set_setting("disk.critical_alerted", "1")
    elif used_pct < (crit_pct - HYSTERESIS_PCT) and crit_alerted:
        _fire("critical", "critical", recovery=True)
        set_setting("disk.critical_alerted", "0")

    # Warn
    if used_pct >= warn_pct:
        if not warn_alerted:
            _fire("warn", "warn")
            set_setting("disk.warn_alerted", "1")
    elif used_pct < (warn_pct - HYSTERESIS_PCT) and warn_alerted:
        _fire("warn", "warn", recovery=True)
        set_setting("disk.warn_alerted", "0")

    return out


def maybe_auto_rebaseline() -> dict[str, Any]:
    """Optional self-healing for the 2026-05-28 failure mode.

    Gate stack (all must be true):
      - `disk.allow_auto_rebaseline='1'` in settings (default '0', OFF)
      - current used_pct ≥ critical_pct
      - .protek.db-litestream/ accounts for >50% of /var/www/Protek/
        — guards against rebaselining when something else (the DB
        itself, logs in /var/log) is the real culprit.

    Action: stop litestream → rm -rf the local stage → start litestream.
    Litestream rebaselines from the replica's current state. Audited and
    notified loudly so the operator always knows it fired.

    Off by default because losing the local LTX chain is destructive;
    the 2026-05-28 incident proved this is sometimes the right call but
    never the safe default.
    """
    enabled = (get_setting("disk.allow_auto_rebaseline") or "0") == "1"
    s = sample() if not enabled else current()  # cheap; current() if enabled
    crit_pct = _setting_float("disk.critical_pct", DEFAULT_CRITICAL_PCT)
    out: dict[str, Any] = {
        "enabled": enabled,
        "used_pct": s["used_pct"],
        "critical_pct": crit_pct,
        "fired": False,
        "reason": "",
    }
    if not enabled:
        out["reason"] = "disk.allow_auto_rebaseline=0"
        return out
    if s["used_pct"] < crit_pct:
        out["reason"] = "below critical"
        return out
    if not LITESTREAM_STAGE_DIR.exists():
        out["reason"] = "litestream stage dir not present"
        return out
    try:
        stage_bytes = _dir_size(LITESTREAM_STAGE_DIR)
        protek_bytes = _dir_size(PROTEK_DIR)
        share = (stage_bytes / protek_bytes) if protek_bytes else 0
    except Exception as e:  # noqa: BLE001
        out["reason"] = f"dir-size scan failed: {e}"
        return out
    out["stage_bytes"] = stage_bytes
    out["protek_bytes"] = protek_bytes
    out["share_of_protek_dir"] = round(share, 3)
    if share <= 0.5:
        out["reason"] = (f"stage is only {share*100:.1f}% of /var/www/Protek "
                         f"— another path is the culprit, not auto-rebaselining")
        return out

    # Do it. Loud notification before + after.
    try:
        import notifications as nmod
        nmod.send("sync_error",
                  f"Auto-rebaselining Litestream: used_pct={s['used_pct']:.1f}, "
                  f"stage={stage_bytes/(1024**3):.1f} GB ({share*100:.0f}% of "
                  f"/var/www/Protek). Replication paused briefly.",
                  subject="[Protek] auto-rebaselining Litestream")
    except Exception:  # noqa: BLE001
        pass

    try:
        subprocess.run(["systemctl", "stop", "litestream"],
                       capture_output=True, text=True, timeout=20, check=False)
        # rm -rf is the cheapest reclaim; mv would just rename without
        # freeing space (lesson from the 2026-05-28 incident).
        import shutil as _sh
        _sh.rmtree(LITESTREAM_STAGE_DIR, ignore_errors=True)
        subprocess.run(["systemctl", "start", "litestream"],
                       capture_output=True, text=True, timeout=20, check=False)
        out["fired"] = True
        out["reason"] = "rebaselined"
        _audit("disk.auto_rebaseline", {
            "used_pct": round(s["used_pct"], 1),
            "stage_bytes": stage_bytes,
            "protek_bytes": protek_bytes,
            "share": round(share, 3),
        })
    except Exception as e:  # noqa: BLE001
        out["fired"] = False
        out["reason"] = f"rebaseline failed: {e}"
        log.exception("auto-rebaseline failed")

    return out


def _dir_size(path: Path) -> int:
    """Total bytes under `path`, following the same accounting `du -shx`
    uses (single filesystem, no symlink-follow). Cheap on the Protek tree
    in steady state (~thousand small files + one big LTX dir)."""
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _audit(action: str, payload: dict[str, Any]) -> None:
    """One-line append to `audit_log`. Same pattern as the existing
    dr.drill.* and notifications-test audit rows."""
    import json
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO audit_log (created_at, actor, action, after_json) "
            "VALUES (?, 'system', ?, ?)",
            (datetime.now(timezone.utc).isoformat(),
             action, json.dumps(payload)),
        )
    finally:
        conn.close()
