"""
scenarios_admin.py — Arc 4 helpers.

Wraps `cscli` for the scenarios browser + custom editor, plus pure Python
helpers for whitelist matching and the approval queue.

cscli is invoked via subprocess (sudo not needed — protek.service runs as
root). Outputs are parsed JSON or stripped text; never piped untrusted
input back into the shell.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from db import get_conn

log = logging.getLogger("protek.scenarios_admin")

CSCLI = shutil.which("cscli") or "cscli"


# ── cscli wrappers ─────────────────────────────────────────────────────────

def hub_list() -> dict[str, list[dict[str, Any]]]:
    """`cscli hub list -o json` — categorized by parsers/scenarios/collections/etc."""
    try:
        out = subprocess.run(
            [CSCLI, "hub", "list", "-o", "json"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if out.returncode != 0:
            log.warning("cscli hub list failed: %s", out.stderr[:300])
            return {}
        return json.loads(out.stdout or "{}")
    except Exception as e:  # noqa: BLE001
        log.warning("cscli hub list crashed: %s", e)
        return {}


def hub_install(kind: str, name: str) -> dict[str, Any]:
    """Install a hub item. `kind` is one of parsers/scenarios/collections/etc."""
    if not _name_safe(name):
        return {"ok": False, "error": "invalid name"}
    if kind not in {"parsers", "scenarios", "collections", "postoverflows", "contexts"}:
        return {"ok": False, "error": "invalid kind"}
    try:
        out = subprocess.run(
            [CSCLI, kind, "install", name],
            capture_output=True, text=True, timeout=120, check=False,
        )
        if out.returncode != 0:
            return {"ok": False, "error": (out.stderr or out.stdout)[:400]}
        return {"ok": True, "output": (out.stdout or "")[:500]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def hub_remove(kind: str, name: str) -> dict[str, Any]:
    if not _name_safe(name):
        return {"ok": False, "error": "invalid name"}
    if kind not in {"parsers", "scenarios", "collections", "postoverflows", "contexts"}:
        return {"ok": False, "error": "invalid kind"}
    try:
        out = subprocess.run(
            [CSCLI, kind, "remove", name, "--force"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if out.returncode != 0:
            return {"ok": False, "error": (out.stderr or out.stdout)[:400]}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def reload_agent() -> dict[str, Any]:
    """systemctl reload crowdsec — cheaper than restart for scenario changes."""
    try:
        out = subprocess.run(
            ["systemctl", "reload", "crowdsec"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if out.returncode != 0:
            # Fall back to restart if reload isn't supported.
            out = subprocess.run(
                ["systemctl", "restart", "crowdsec"],
                capture_output=True, text=True, timeout=15, check=False,
            )
        if out.returncode != 0:
            return {"ok": False, "error": out.stderr[:300]}
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def _name_safe(name: str) -> bool:
    return name and all(c.isalnum() or c in "/_-." for c in name)


# ── Custom scenario files ──────────────────────────────────────────────────

CUSTOM_DIR = Path("/etc/crowdsec/scenarios")


def list_custom_scenarios() -> list[dict[str, Any]]:
    if not CUSTOM_DIR.exists():
        return []
    out = []
    for p in sorted(CUSTOM_DIR.glob("*.yaml")):
        try:
            content = p.read_text()[:200]
        except (OSError, PermissionError):
            content = ""
        out.append({
            "name": p.name,
            "size": p.stat().st_size if p.exists() else 0,
            "modified": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat(),
            "preview": content,
        })
    return out


def read_custom_scenario(name: str) -> str | None:
    if not _name_safe(name) or not name.endswith(".yaml"):
        return None
    p = CUSTOM_DIR / name
    if not p.exists() or not p.is_file():
        return None
    try:
        return p.read_text()
    except (OSError, PermissionError):
        return None


def save_custom_scenario(name: str, content: str) -> dict[str, Any]:
    if not _name_safe(name) or not name.endswith(".yaml"):
        return {"ok": False, "error": "name must be alphanumeric + .yaml"}
    if len(content) > 200_000:
        return {"ok": False, "error": "file too large"}
    p = CUSTOM_DIR / name
    try:
        CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return {"ok": True, "path": str(p)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


# ── Scenario performance metrics ───────────────────────────────────────────

def scenario_stats(window_hours: int = 24) -> list[dict[str, Any]]:
    """Per-scenario stats over a window."""
    conn = get_conn()
    try:
        rows = conn.execute(
            f"""
            SELECT scenario,
                   COUNT(*) AS fires,
                   COUNT(DISTINCT value) AS unique_ips,
                   MIN(first_seen_at) AS first_fire,
                   MAX(last_seen_at) AS last_fire
            FROM decisions
            WHERE last_seen_at > datetime('now', '-{int(window_hours)} hours')
              AND scenario != ''
            GROUP BY scenario
            ORDER BY fires DESC
            """
        ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        ratio = r["fires"] / max(1, r["unique_ips"])
        out.append({
            "scenario": r["scenario"],
            "fires": r["fires"],
            "unique_ips": r["unique_ips"],
            "fires_per_ip": round(ratio, 1),
            "first_fire": r["first_fire"],
            "last_fire": r["last_fire"],
        })
    return out


def noisy_scenarios(min_fires: int = 100, ratio_threshold: float = 5.0) -> list[str]:
    """Scenarios firing a lot but producing few unique bans — false-positive proxy."""
    stats = scenario_stats(24)
    return [s["scenario"] for s in stats
            if s["fires"] >= min_fires and (s["fires"] / max(1, s["unique_ips"])) >= ratio_threshold]


def sleeping_scenarios(days: int = 30) -> list[str]:
    """Hub scenarios installed but never fired in N days."""
    installed = {s["name"] for s in (hub_list().get("scenarios") or [])
                 if s.get("status") == "enabled"}
    conn = get_conn()
    try:
        seen = {r["scenario"] for r in conn.execute(
            f"SELECT DISTINCT scenario FROM decisions WHERE last_seen_at > datetime('now', '-{int(days)} days')"
        ).fetchall()}
    finally:
        conn.close()
    return sorted(installed - seen)


# ── Whitelist ──────────────────────────────────────────────────────────────

def list_whitelist(include_expired: bool = False) -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        if include_expired:
            rows = conn.execute("SELECT * FROM whitelist ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM whitelist WHERE expires_at IS NULL OR expires_at > datetime('now') ORDER BY id DESC"
            ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def add_whitelist(kind: str, value: str, note: str = "", expires_at: str | None = None) -> dict[str, Any]:
    if kind not in {"ip", "cidr", "asn", "country"}:
        return {"ok": False, "error": "invalid kind"}
    value = value.strip()
    if kind == "ip":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return {"ok": False, "error": "invalid IP"}
    elif kind == "cidr":
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return {"ok": False, "error": "invalid CIDR"}
    elif kind == "asn":
        if not (value.upper().startswith("AS") and value[2:].isdigit()):
            return {"ok": False, "error": "ASN must look like AS12345"}
    elif kind == "country":
        if not (len(value) == 2 and value.isalpha()):
            return {"ok": False, "error": "country must be 2-letter ISO code"}
        value = value.upper()

    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO whitelist (kind, value, note, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            (kind, value, note, expires_at, now),
        )
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def delete_whitelist(wid: int) -> None:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM whitelist WHERE id = ?", (wid,))
    finally:
        conn.close()


def matches_whitelist(ip: str, asn: str = "", country: str = "",
                      rules: list[dict[str, Any]] | None = None) -> dict | None:
    """Return the whitelist row that matches, else None. Active rows only.

    Callers in hot paths (reconcile loop) should pass `rules` pre-fetched to
    avoid one DB roundtrip per IP.
    """
    rows = rules if rules is not None else list_whitelist(include_expired=False)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    for w in rows:
        kind, val = w["kind"], w["value"]
        if kind == "ip" and val == ip:
            return w
        if kind == "cidr" and addr is not None:
            try:
                if addr in ipaddress.ip_network(val, strict=False):
                    return w
            except ValueError:
                pass
        if kind == "asn" and asn and val.upper() == asn.upper():
            return w
        if kind == "country" and country and val.upper() == country.upper():
            return w
    return None


def record_whitelist_hit(ip: str, whitelist_id: int, scenario: str = "") -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            "INSERT INTO whitelist_hits (ip, whitelist_id, scenario, created_at) VALUES (?, ?, ?, ?)",
            (ip, whitelist_id, scenario, now),
        )
    finally:
        conn.close()


# ── Approval queue (semi-auto mode) ────────────────────────────────────────

def approval_required() -> bool:
    from db import get_setting
    return (get_setting("settings.approval_required") or "0") == "1"


def queue_decision(ip: str, scope: str, scenario: str, origin: str,
                   origin_source: str, decision_id: int | None = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        cur = conn.execute(
            """INSERT INTO approval_queue (ip, scope, scenario, origin, origin_source, decision_id, status, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)""",
            (ip, scope, scenario, origin, origin_source, decision_id, now),
        )
        return cur.lastrowid or 0
    finally:
        conn.close()


def list_queue(status: str = "pending", limit: int = 200) -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM approval_queue WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def decide(queue_id: int, decision: str, decided_by: str) -> None:
    if decision not in {"approved", "rejected"}:
        raise ValueError("decision must be approved|rejected")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE approval_queue SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
            (decision, decided_by, now, queue_id),
        )
    finally:
        conn.close()
