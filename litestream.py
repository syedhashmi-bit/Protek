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


# ── Phase 99 — SFTP destination probe ──────────────────────────────────────
#
# Phase 93's disk_watchdog covers VPS A's `/`. It cannot see VPS B's disk
# state — and the 2026-05-28 ENOSPC #3 incident proved that destination
# disk pressure causes L1+ compaction to fail silently, which then breaks
# L0 retention, which then bloats VPS A's local stage. Symptoms reach
# VPS A only after the destination has already filled for ~30 hours.
#
# This probe runs over the same SFTP channel Litestream uses, every
# `litestream.probe_every_cycles` poller cycles (default 30 = ~5 min):
#
#   1. Parse /etc/litestream.yml to find the SFTP destination + key path.
#   2. `df` over SFTP to read destination disk usage.
#   3. Round-trip write/read/delete of a tiny marker file to verify
#      writability — catches read-only-mounted, quota-exceeded, and
#      permission-revoked failures that `df` alone wouldn't reveal.
#   4. Edge-triggered warn (70%) + critical (90%) notifications with
#      per-category 1h rate limit (mirrors scan_journal_errors).
#
# Failure modes categorised:
#   - `space`      destination usage ≥ probe_critical_pct OR write fails
#                  with "no space left" / "disk quota exceeded"
#   - `network`    SSH itself failed (connection refused, timeout, key
#                  rejected, host key mismatch)
#   - `permission` SFTP succeeded but write/delete denied
#   - `other`      anything else

import re as _re

PROBE_RATE_LIMIT_SECONDS = 3600
PROBE_MARKER_NAME = ".protek-probe-marker"

DEFAULT_PROBE_WARN_PCT = 70
DEFAULT_PROBE_CRITICAL_PCT = 90


def _parse_litestream_yml() -> dict[str, Any] | None:
    """Read /etc/litestream.yml and extract the first SFTP destination.
    Returns dict with keys: host, port, user, path, key_path — or None
    if the file is missing or the config doesn't include an SFTP
    replica. Tolerant parser: doesn't require PyYAML (the field shapes
    are simple).
    """
    if not LIVE_CONFIG.exists():
        return None
    try:
        text = LIVE_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # Find the first `url: sftp://...` line + the matching `key-path:`
    sftp_url = ""
    key_path = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("url:") and "sftp://" in s:
            sftp_url = s.split(":", 1)[1].strip()
        elif s.startswith("key-path:"):
            key_path = s.split(":", 1)[1].strip()
        if sftp_url and key_path:
            break
    if not sftp_url:
        return None
    # sftp://user@host:port/path/...
    m = _re.match(r"^sftp://([^@]+)@([^:/]+)(?::(\d+))?(/.*)?$", sftp_url)
    if not m:
        return None
    user, host, port, path = m.groups()
    return {
        "host":     host,
        "port":     int(port) if port else 22,
        "user":     user,
        "path":     path or "/",
        "key_path": key_path or "",
    }


def _categorize_probe_error(stderr: str, exit_code: int) -> str:
    s = (stderr or "").lower()
    if "no space left" in s or "disk quota" in s or "quota exceeded" in s:
        return "space"
    if "permission denied" in s or "operation not permitted" in s:
        return "permission"
    if ("connection refused" in s or "timed out" in s or "no route to host" in s
            or "host key" in s or "permission denied (publickey" in s
            or "could not resolve hostname" in s):
        return "network"
    if exit_code != 0 and not s:
        return "network"  # connect-time failures often have empty stderr
    return "other"


def _run_sftp_batch(cfg: dict[str, Any], batch: str,
                     timeout_s: int = 15) -> tuple[int, str, str]:
    """Run an SFTP batch script against the configured destination.
    Returns (returncode, stdout, stderr). Never raises."""
    cmd = [
        "sftp",
        "-b", "-",                 # read batch from stdin
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"ConnectTimeout={min(10, timeout_s)}",
    ]
    if cfg.get("key_path"):
        cmd.extend(["-i", cfg["key_path"]])
    if cfg.get("port") and cfg["port"] != 22:
        cmd.extend(["-P", str(cfg["port"])])
    cmd.append(f"{cfg['user']}@{cfg['host']}")
    try:
        proc = subprocess.run(
            cmd, input=batch, capture_output=True, text=True,
            timeout=timeout_s,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 99, "", f"sftp invocation failed: {e}"


def _parse_df_output(stdout: str) -> dict[str, Any] | None:
    """Parse the `df` output that OpenSSH SFTP's `df` command produces.

    Typical shape:
        Size     Used    Avail   (root)    %Capacity
        38G       12G      24G      26G       34%

    Returns dict with parsed values or None if we couldn't make sense
    of the lines. Tolerant — different OpenSSH versions vary slightly.
    """
    for line in stdout.splitlines():
        s = line.strip()
        if not s or s.lower().startswith("size") or "capacity" in s.lower():
            continue
        # Last column is "NN%" — that's the only field we strictly need
        m = _re.search(r"(\d+(?:\.\d+)?)\s*%", s)
        if m:
            try:
                used_pct = float(m.group(1))
                return {"used_pct": used_pct, "raw": s}
            except ValueError:
                continue
    return None


def probe_replica_destination() -> dict[str, Any]:
    """Top-level probe entry point. Returns a dict describing what was
    seen and what fired. Cheap to call every ~5 min from the poller.
    """
    from db import get_setting, set_setting
    out: dict[str, Any] = {
        "checked_at": datetime.now().isoformat(),
        "enabled":    (get_setting("litestream.probe_enabled") or "1") == "1",
        "configured": False,
        "ok":         None,
        "category":   "",
        "used_pct":   None,
        "fired":      [],
    }
    if not out["enabled"]:
        out["reason"] = "litestream.probe_enabled=0"
        return out

    cfg = _parse_litestream_yml()
    if not cfg:
        out["reason"] = "no SFTP replica in /etc/litestream.yml"
        return out
    out["configured"] = True
    out["host"] = cfg["host"]
    out["path"] = cfg["path"]

    warn_pct = _setting_float_local("litestream.probe_warn_pct",
                                     DEFAULT_PROBE_WARN_PCT)
    crit_pct = _setting_float_local("litestream.probe_critical_pct",
                                     DEFAULT_PROBE_CRITICAL_PCT)

    # 1. df — destination disk usage
    marker_path = f"{cfg['path'].rstrip('/')}/{PROBE_MARKER_NAME}"
    df_batch = f"df {cfg['path']}\n"
    rc, df_out, df_err = _run_sftp_batch(cfg, df_batch)
    if rc != 0:
        out["ok"] = False
        out["category"] = _categorize_probe_error(df_err, rc)
        out["error"] = (df_err or "df failed")[:300]
        _maybe_fire_probe(out["category"], out)
        return out

    df_parsed = _parse_df_output(df_out)
    used_pct = df_parsed["used_pct"] if df_parsed else None
    out["used_pct"] = used_pct
    out["df_raw"] = (df_parsed or {}).get("raw", df_out.strip()[:200])

    # 2. write / read / delete — verify writability
    rw_batch = (
        f"!echo 'protek-probe' > /tmp/.protek-probe-local\n"
        f"put /tmp/.protek-probe-local {marker_path}\n"
        f"get {marker_path} /tmp/.protek-probe-readback\n"
        f"rm {marker_path}\n"
        f"!rm -f /tmp/.protek-probe-local /tmp/.protek-probe-readback\n"
    )
    rc2, rw_out, rw_err = _run_sftp_batch(cfg, rw_batch, timeout_s=20)
    out["rw_ok"] = (rc2 == 0)
    if rc2 != 0:
        out["ok"] = False
        out["category"] = _categorize_probe_error(rw_err, rc2)
        out["error"] = (rw_err or "write/read/delete failed")[:300]
        _maybe_fire_probe(out["category"], out)
        return out

    # 3. Edge-triggered thresholds on used_pct
    if used_pct is None:
        out["ok"] = True
        out["category"] = ""
        # Couldn't parse df but rw round-trip worked — treat as ok, no fire
        set_setting("litestream.last_probe_at", out["checked_at"])
        set_setting("litestream.last_probe_pct", "")
        return out

    set_setting("litestream.last_probe_at", out["checked_at"])
    set_setting("litestream.last_probe_pct", f"{used_pct:.1f}")

    if used_pct >= crit_pct:
        out["ok"] = False
        out["category"] = "space"
        out["error"] = (f"destination {cfg['host']}:{cfg['path']} at "
                        f"{used_pct:.1f}% — critical")
        _maybe_fire_probe("space", out, severity="critical")
    elif used_pct >= warn_pct:
        out["ok"] = False
        out["category"] = "space"
        out["error"] = (f"destination {cfg['host']}:{cfg['path']} at "
                        f"{used_pct:.1f}% — warn")
        _maybe_fire_probe("space", out, severity="warn")
    else:
        out["ok"] = True
        # Recovery: if we'd previously fired a space alert, clear it now.
        last_at = get_setting("litestream.last_err_probe_space") or ""
        if last_at:
            _fire_probe_recovery("space", out)

    return out


def _setting_float_local(key: str, default: float) -> float:
    """Inline duplicate of disk_watchdog._setting_float; importing the
    other module here would risk a circular import on plugin load. Tiny."""
    from db import get_setting
    raw = get_setting(key)
    if not raw:
        return float(default)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return float(default)


def _maybe_fire_probe(category: str, out: dict[str, Any],
                       severity: str = "warn") -> None:
    """Per-category 1h rate-limited notification + SIEM event + audit row.
    Mirrors scan_journal_errors's rate-limit pattern verbatim so operators
    see consistent semantics across both signals."""
    from db import get_setting, set_setting
    key = f"litestream.last_err_probe_{category}"
    last_at = get_setting(key) or ""
    if last_at:
        try:
            last = datetime.fromisoformat(last_at)
            if (datetime.now() - last).total_seconds() < PROBE_RATE_LIMIT_SECONDS:
                return  # rate-limited
        except (ValueError, TypeError):
            pass

    try:
        import notifications as nmod
    except Exception:  # noqa: BLE001
        nmod = None
    try:
        import siem as siem_mod
    except Exception:  # noqa: BLE001
        siem_mod = None

    msg = (f"Litestream destination probe failed (`{category}` / "
           f"{severity}). Host: {out.get('host', '?')}. "
           f"Detail: {out.get('error', '')[:200]}")
    if nmod:
        try:
            nmod.send("sync_error", msg,
                      subject=f"[Protek] litestream destination {severity}")
        except Exception:  # noqa: BLE001
            pass
    if siem_mod:
        try:
            siem_mod.ship("litestream.destination_probe", {
                "category": category,
                "severity": severity,
                "used_pct": out.get("used_pct"),
                "host":     out.get("host"),
                "error":    out.get("error", "")[:300],
            }, severity=2 if severity == "critical" else 4)
        except Exception:  # noqa: BLE001
            pass

    # Audit row
    try:
        from db import get_conn
        import json as _json
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO audit_log (created_at, actor, action, after_json) "
                "VALUES (?, 'system', ?, ?)",
                (datetime.now().isoformat(), f"litestream.probe.{category}",
                 _json.dumps({
                    "severity":  severity,
                    "used_pct":  out.get("used_pct"),
                    "host":      out.get("host"),
                    "error":     out.get("error", "")[:300],
                 })),
            )
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass

    set_setting(key, datetime.now().isoformat())
    out["fired"].append(f"{category}_{severity}")


def _fire_probe_recovery(category: str, out: dict[str, Any]) -> None:
    """Recovery edge — clears the rate-limit key + emits a recovery
    notification so the operator knows the alert is resolved."""
    from db import set_setting
    try:
        import notifications as nmod
        nmod.send("sync_error",
                  (f"Litestream destination probe recovered "
                   f"(`{category}`). Host: {out.get('host', '?')}. "
                   f"Currently at {out.get('used_pct', 0):.1f}% used."),
                  subject="[Protek] litestream destination recovered")
    except Exception:  # noqa: BLE001
        pass
    set_setting(f"litestream.last_err_probe_{category}", "")
    out["fired"].append(f"{category}_recovery")


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

