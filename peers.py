"""
peers.py — Arc 13 phase 76. Read-only aggregation across peer Protek instances.

The Arc 2 federation feature already lets one Protek pull decisions from
many CrowdSec LAPIs. Phase 76 is the inverse direction: many Protek
instances each running on its own VPS, with one "hub" Protek aggregating
their dashboards into a single pane.

Scope for 2.0: **read-only aggregation**. The hub fetches each peer's
`/api/v1/tile/summary` + the count of `/api/v1/decisions` and surfaces
them on `/peers`. Click a peer row to open its own /dashboard in a new
tab (via SSO cookie sharing from phase 74 if both are on the same parent
domain, otherwise per-peer login).

What's NOT in 2.0: cross-peer decision propagation. Pushing a ban on
peer A and having it land on peer B's bouncers requires bidirectional
sync, conflict resolution, and a peer-trust model that's a multi-month
design exercise. For now: each peer's bouncers are independent. Use the
hub for visibility, not control.

Peers are stored in `protek_peers` (lazy-created) — name, url, token,
enabled, last_pull metadata. Token is a `read`-scoped API token issued
by the peer (created via that peer's /admin/tokens page).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from db import get_conn, get_setting, set_setting

log = logging.getLogger("protek.peers")

PEER_TIMEOUT = 8.0  # seconds


def _ensure_table() -> None:
    conn = get_conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS protek_peers (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT UNIQUE NOT NULL,
                url           TEXT NOT NULL,
                token         TEXT NOT NULL,
                enabled       INTEGER NOT NULL DEFAULT 1,
                last_pull_at  TEXT DEFAULT NULL,
                last_pull_ok  INTEGER NOT NULL DEFAULT 0,
                last_summary_json TEXT NOT NULL DEFAULT '{}',
                last_error    TEXT NOT NULL DEFAULT '',
                created_at    TEXT NOT NULL
            )
            """
        )
    finally:
        conn.close()


def list_peers(include_disabled: bool = True) -> list[dict[str, Any]]:
    _ensure_table()
    conn = get_conn()
    try:
        if include_disabled:
            rows = conn.execute("SELECT * FROM protek_peers ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM protek_peers WHERE enabled = 1 ORDER BY id"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_peer(name: str, url: str, token: str) -> int:
    _ensure_table()
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO protek_peers (name, url, token, enabled, created_at)
            VALUES (?, ?, ?, 1, ?)
            """,
            (name, url.rstrip("/"), token, now),
        )
        return cur.lastrowid
    finally:
        conn.close()


def toggle_peer(peer_id: int, enabled: bool) -> None:
    _ensure_table()
    conn = get_conn()
    try:
        conn.execute("UPDATE protek_peers SET enabled = ? WHERE id = ?",
                     (1 if enabled else 0, peer_id))
    finally:
        conn.close()


def delete_peer(peer_id: int) -> None:
    _ensure_table()
    conn = get_conn()
    try:
        conn.execute("DELETE FROM protek_peers WHERE id = ?", (peer_id,))
    finally:
        conn.close()


def _hdrs(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": "protek-peer-aggregator/1.0",
        "Accept": "application/json",
    }


def _fetch_peer(peer: dict[str, Any]) -> dict[str, Any]:
    """Hit /api/v1/tile/summary on a peer. Returns the summary + raw counts
    or an error string."""
    try:
        import ratelimit
        if not ratelimit.acquire(f"peer.{peer['name']}"):
            return {"ok": False, "error": "backpressure — peer bucket exhausted"}
    except ImportError:
        pass
    url = peer["url"].rstrip("/") + "/api/v1/tile/summary"
    try:
        r = requests.get(url, headers=_hdrs(peer["token"]), timeout=PEER_TIMEOUT)
    except requests.RequestException as e:
        return {"ok": False, "error": f"network: {e}"}
    if r.status_code == 429:
        try:
            import ratelimit
            ratelimit.record_429(f"peer.{peer['name']}")
        except ImportError:
            pass
        return {"ok": False, "error": "HTTP 429 rate limited"}
    if r.status_code != 200:
        return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
    try:
        data = r.json()
    except ValueError as e:
        return {"ok": False, "error": f"invalid JSON: {e}"}
    return {"ok": True, "summary": data}


def refresh_all() -> dict[str, Any]:
    """Hit every enabled peer; persist last_summary + status."""
    out = {"refreshed": 0, "failed": 0, "skipped": 0}
    now = datetime.now(timezone.utc).isoformat()
    for p in list_peers(include_disabled=False):
        result = _fetch_peer(p)
        ok = bool(result.get("ok"))
        conn = get_conn()
        try:
            conn.execute(
                """
                UPDATE protek_peers
                   SET last_pull_at = ?, last_pull_ok = ?,
                       last_summary_json = ?, last_error = ?
                 WHERE id = ?
                """,
                (
                    now, 1 if ok else 0,
                    __import__("json").dumps(result.get("summary", {}))[:4000],
                    result.get("error", "")[:400],
                    p["id"],
                ),
            )
        finally:
            conn.close()
        if ok:
            out["refreshed"] += 1
        else:
            out["failed"] += 1
    set_setting("peers.last_refresh_at", now)
    return out


def aggregated_kpis() -> dict[str, Any]:
    """Sum of active_bans / sync_lag_max / etc. across all enabled peers
    (plus the local instance)."""
    _ensure_table()
    peers = list_peers(include_disabled=False)
    total_bans = 0
    max_lag = 0.0
    cycle_total = 0
    healthy = 0
    rows = []
    for p in peers:
        try:
            import json as _json
            summary = _json.loads(p.get("last_summary_json") or "{}")
        except Exception:  # noqa: BLE001
            summary = {}
        if p.get("last_pull_ok"):
            healthy += 1
            total_bans += int(summary.get("active_bans", 0) or 0)
            max_lag = max(max_lag, float(summary.get("sync_lag_seconds", 0) or 0))
            cycle_total += int(summary.get("cycle_count", 0) or 0)
        rows.append({
            "id": p["id"], "name": p["name"], "url": p["url"],
            "ok": bool(p.get("last_pull_ok")),
            "active_bans": int(summary.get("active_bans", 0) or 0),
            "sync_lag_seconds": float(summary.get("sync_lag_seconds", 0) or 0),
            "dry_run": bool(summary.get("dry_run", True)),
            "sources_total": int(summary.get("sources_total", 1) or 1),
            "last_pull_at": p.get("last_pull_at"),
            "last_error": p.get("last_error") or "",
            "enabled": bool(p.get("enabled")),
        })
    # Add the local instance row so the hub aggregates itself too
    local = {
        "id": 0, "name": "(this instance)", "url": "",
        "ok": True,
        "active_bans": int(get_setting("poller.active_total") or "0"),
        "sync_lag_seconds": 0.0,
        "dry_run": (get_setting("reconcile.last_dry_run") or "1") == "1",
        "sources_total": int(get_setting("poller.source_count") or "1"),
        "last_pull_at": get_setting("poller.last_at"),
        "last_error": "",
        "enabled": True,
    }
    total_bans += local["active_bans"]
    return {
        "instances": [local] + rows,
        "total_active_bans": total_bans,
        "peers_healthy": healthy,
        "peers_total": len(peers),
        "max_sync_lag_seconds": max_lag,
        "cycle_total": cycle_total,
        "last_refresh": get_setting("peers.last_refresh_at"),
    }


def maybe_run_scheduled() -> None:
    """Called from the poller. Refresh peers every 60s."""
    if not list_peers(include_disabled=False):
        return
    last = get_setting("peers.last_refresh_at")
    if last:
        try:
            d = datetime.fromisoformat(last.replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - d) < timedelta(seconds=60):
                return
        except Exception:  # noqa: BLE001
            pass
    try:
        refresh_all()
    except Exception as e:  # noqa: BLE001
        log.debug("peer refresh swallowed: %s", e)
