"""
litestream.py — Arc 11 phase 64. Litestream WAL replication scaffolding.

Litestream is a sidecar binary that streams a SQLite WAL to S3-compatible
object storage in near-real time. RPO < 60s, RTO < 5 min. We don't run
Litestream ourselves (no embedded library); we provide:

  1. A reference systemd unit (`docs/litestream/protek-litestream.service.example`)
  2. A reference config (`docs/litestream/litestream.yml.example`) keyed to
     the same Backblaze B2 bucket already used by `backup.py` — or any other
     S3-compatible target.
  3. A status surface this module exposes for the /admin/backup-automation
     page: is `litestream.service` installed? Is it running? When did it last
     successfully replicate? Plus a "how to enable" hint when it's not.

Status sources, in preference order:
  - `systemctl is-active litestream.service` exit code (cheap, no parsing)
  - `litestream snapshots <db>` mtime of the most recent snapshot (when
     the binary is present)
  - Fallback: "not installed" with copy-paste install commands.

Why scaffolding-only: Litestream config is per-deployment (S3 endpoint,
bucket, retention, encryption) and the operator owns that config. Shipping
opinionated defaults that don't match the operator's bucket would do more
harm than good.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("protek.litestream")

DOCS_DIR = Path(__file__).resolve().parent / "docs" / "litestream"
SAMPLE_UNIT = DOCS_DIR / "protek-litestream.service.example"
SAMPLE_CONFIG = DOCS_DIR / "litestream.yml.example"
LIVE_CONFIG = Path("/etc/litestream.yml")
LIVE_UNIT = Path("/etc/systemd/system/litestream.service")


def _which(name: str) -> str:
    p = shutil.which(name)
    return p or ""


def _systemctl(cmd: str, unit: str) -> tuple[int, str]:
    try:
        out = subprocess.run(
            ["systemctl", cmd, unit],
            capture_output=True, text=True, timeout=5,
        )
        return out.returncode, (out.stdout or out.stderr).strip()
    except Exception as e:  # noqa: BLE001
        return 99, f"systemctl error: {e}"


def status() -> dict[str, Any]:
    binary = _which("litestream")
    installed = bool(binary)

    config_exists = LIVE_CONFIG.exists()
    unit_exists = LIVE_UNIT.exists()

    unit_active = False
    unit_status = ""
    unit_since = ""
    if unit_exists:
        rc, _ = _systemctl("is-active", "litestream.service")
        unit_active = (rc == 0)
        # `systemctl show ... -p ActiveState,SubState,ActiveEnterTimestamp`
        try:
            shown = subprocess.run(
                ["systemctl", "show", "litestream.service",
                 "-p", "ActiveState", "-p", "SubState",
                 "-p", "ActiveEnterTimestamp"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            parts = dict(
                line.split("=", 1) for line in shown.strip().splitlines() if "=" in line
            )
            unit_status = f"{parts.get('ActiveState','?')}/{parts.get('SubState','?')}"
            unit_since = parts.get("ActiveEnterTimestamp", "") or ""
        except Exception:  # noqa: BLE001
            pass

    last_snapshot = ""
    snapshot_age_s: int | None = None
    if installed and config_exists:
        try:
            from db import DB_PATH
            out = subprocess.run(
                [binary, "snapshots", str(DB_PATH)],
                capture_output=True, text=True, timeout=8,
            )
            # Parse last column as ISO-ish timestamp; pick max.
            best = None
            for line in out.stdout.splitlines():
                tokens = line.split()
                if not tokens:
                    continue
                # First token of header is "replica" or similar; skip non-data lines
                ts = tokens[-1]
                if ts.count("-") >= 2 and ts.count(":") >= 1:
                    try:
                        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if best is None or d > best:
                            best = d
                    except ValueError:
                        continue
            if best:
                last_snapshot = best.isoformat()
                snapshot_age_s = int(
                    (datetime.now(best.tzinfo) - best).total_seconds()
                )
        except Exception as e:  # noqa: BLE001
            log.debug("litestream snapshots query failed: %s", e)

    health = "down"
    if installed and config_exists and unit_active:
        if snapshot_age_s is None or snapshot_age_s < 600:
            health = "ok"
        else:
            health = "lagging"
    elif installed and config_exists and unit_exists:
        health = "stopped"
    elif installed:
        health = "configured-pending"
    else:
        health = "not-installed"

    return {
        "binary": binary,
        "installed": installed,
        "config_path": str(LIVE_CONFIG),
        "config_exists": config_exists,
        "unit_path": str(LIVE_UNIT),
        "unit_exists": unit_exists,
        "unit_active": unit_active,
        "unit_status": unit_status,
        "unit_since": unit_since,
        "last_snapshot": last_snapshot,
        "snapshot_age_s": snapshot_age_s,
        "health": health,
        "sample_unit": str(SAMPLE_UNIT),
        "sample_config": str(SAMPLE_CONFIG),
    }


# ── Phase 93 — journal error scraper ───────────────────────────────────────
#
# Litestream's daemon failures (retention enforcement, upload, ssh) don't
# surface on its own /metrics endpoint or on systemctl is-active — they
# only show as `level=ERROR` lines in `journalctl -u litestream`. The
# 2026-05-28 incident filled 25 GB of local LTX stage while
# `systemctl is-active litestream` returned ok the entire time. The fix
# is reading the journal ourselves and surfacing errors as notifications.
#
# Design:
#   - One subprocess call to `journalctl -u litestream --since <cursor>
#     --no-pager`. Cursor advances on every call (settings-tracked).
#   - Errors are categorized by substring match (`retention enforcement
#     failed`, `upload`, `ssh:`, generic `error`). Each category has its
#     own 1-hour rate-limit so a single recurring failure doesn't spam
#     the notification channel.
#   - Non-blocking: subprocess timeout 5s. If journalctl is slow or
#     missing, we return early and try again next cycle.

ERROR_CATEGORIES: list[tuple[str, str]] = [
    # (category-key, substring-to-match on the lower-cased line)
    # Order matters — first match wins. Most-specific first.
    ("retention",  "retention enforcement failed"),
    ("compaction", "compaction failed"),
    ("upload",     "upload"),
    ("ssh",        "ssh:"),
    ("replica",    "replica"),
    ("other",      "error"),  # fallback bucket — checked last
]

RATE_LIMIT_SECONDS = 3600  # one notification per category per hour


def _categorize(line_lower: str) -> str:
    for key, sub in ERROR_CATEGORIES:
        if sub in line_lower:
            return key
    return "other"


def scan_journal_errors(since_seconds: int = 3600) -> dict[str, Any]:
    """Scan `journalctl -u litestream` for level=ERROR lines and fire one
    notification per category per RATE_LIMIT_SECONDS window.

    `since_seconds` bounds the journalctl query so we don't pull hours of
    history on every cycle. The settings-tracked cursor
    (`litestream.journal_cursor`) further narrows the window to "since
    last successful scan" once we have one.

    Returns a dict describing what was scanned and what fired — used by
    tests and (optionally) logged by the poller.
    """
    from db import get_setting, set_setting
    out: dict[str, Any] = {
        "scanned_at": datetime.now().isoformat(),
        "errors_by_category": {},
        "fired": [],
    }
    cursor = get_setting("litestream.journal_cursor") or ""
    if cursor:
        since_arg = ["--since", cursor]
    else:
        # No cursor yet — bound the first scan to since_seconds ago so we
        # don't dredge up days of history on a fresh deploy.
        from datetime import datetime as _dt, timedelta as _td
        start = _dt.now() - _td(seconds=since_seconds)
        since_arg = ["--since", start.strftime("%Y-%m-%d %H:%M:%S")]

    try:
        proc = subprocess.run(
            ["journalctl", "-u", "litestream",
             *since_arg, "--no-pager", "-o", "short-iso"],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        out["error"] = f"journalctl unavailable: {e}"
        return out

    last_ts_str = ""
    for raw in proc.stdout.splitlines():
        if "level=ERROR" not in raw:
            continue
        # `short-iso` format: "2026-05-28T01:35:05+0000 host litestream[..]: ..."
        parts = raw.split(" ", 1)
        line_ts = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else raw
        category = _categorize(body.lower())
        out["errors_by_category"].setdefault(category, []).append(body)
        if line_ts > last_ts_str:
            last_ts_str = line_ts

    # Per-category rate-limited notification
    try:
        import notifications as nmod
    except Exception:  # noqa: BLE001
        nmod = None
    try:
        import siem as siem_mod
    except Exception:  # noqa: BLE001
        siem_mod = None

    from db import get_setting as _gs, set_setting as _ss
    now_iso = datetime.now().isoformat()
    for category, lines in out["errors_by_category"].items():
        last_at = _gs(f"litestream.last_err_{category}") or ""
        if last_at:
            try:
                last = datetime.fromisoformat(last_at)
                if (datetime.now() - last).total_seconds() < RATE_LIMIT_SECONDS:
                    continue  # rate-limited
            except (ValueError, TypeError):
                pass
        sample_line = lines[0][:300]
        msg = (f"Litestream `{category}` error ({len(lines)} occurrence(s) "
               f"this scan). Latest: {sample_line}")
        if nmod:
            try:
                nmod.send("sync_error", msg,
                          subject=f"[Protek] litestream {category} error")
            except Exception:  # noqa: BLE001
                pass
        if siem_mod:
            try:
                siem_mod.ship("litestream.error", {
                    "category": category,
                    "count": len(lines),
                    "sample": sample_line,
                }, severity=3)
            except Exception:  # noqa: BLE001
                pass
        _ss(f"litestream.last_err_{category}", now_iso)
        out["fired"].append(category)

    # Advance cursor — even on a clean scan, so the next call doesn't
    # re-read these lines. We add 1s to last_ts to avoid re-matching the
    # boundary line (`--since` is inclusive).
    if last_ts_str:
        try:
            ts = datetime.fromisoformat(last_ts_str.replace("Z", "+00:00"))
            from datetime import timedelta as _td
            set_setting("litestream.journal_cursor",
                         (ts + _td(seconds=1)).strftime("%Y-%m-%d %H:%M:%S"))
        except (ValueError, TypeError):
            pass

    return out

