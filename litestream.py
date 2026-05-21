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
