"""
api_v1.py — Phase 47. Frozen REST surface under /api/v1/*.

Contract:
  - Path-versioned: /api/v1/* paths are stable; breaking changes go in /api/v2/*.
  - Bearer-token auth via Authorization or X-Protek-Token headers
    (see api_tokens.require_token).
  - Reads need `read` scope, writes need `write`, admin ops need `admin`.
  - JSON in, JSON out. Errors as {"error": "<key>", ...}.

Routes live under a Flask blueprint registered in app.py.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, g, jsonify, request

import api_tokens as at
from db import get_conn, get_setting

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")


# ── meta ───────────────────────────────────────────────────────────────────

@bp.route("/ping")
def v1_ping():
    """No-auth liveness for the API surface itself."""
    return jsonify(ok=True, api="v1", version="1.0.0", service="protek",
                    time=datetime.now(timezone.utc).isoformat()), 200


# ── decisions ──────────────────────────────────────────────────────────────

@bp.route("/decisions")
@at.require_token("read")
def v1_decisions_ls():
    """List active decisions. Filters: ?scope=Ip&origin=crowdsec&q=<substring>&limit=N."""
    try:
        limit = max(1, min(5000, int(request.args.get("limit", "200"))))
    except (TypeError, ValueError):
        limit = 200
    scope = (request.args.get("scope") or "").strip()
    origin = (request.args.get("origin") or "").strip()
    q = (request.args.get("q") or "").strip()
    where = ["deleted_at IS NULL"]
    params: list[Any] = []
    if scope:
        where.append("scope = ?"); params.append(scope)
    if origin:
        where.append("origin LIKE ?"); params.append(f"%{origin}%")
    if q:
        where.append("(value LIKE ? OR scenario LIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    sql = ("SELECT origin_source, lapi_id, value, scope, scenario, origin, "
           "duration, until, first_seen_at "
           f"FROM decisions WHERE {' AND '.join(where)} "
           "ORDER BY id DESC LIMIT ?")
    params.append(limit)
    conn = get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()
    return jsonify(items=[dict(r) for r in rows], count=len(rows), limit=limit)


@bp.route("/decisions", methods=["POST"])
@at.require_token("write")
def v1_decisions_add():
    """Add a decision. Same semantics as /api/external/decisions but versioned."""
    data = request.get_json(silent=True) or {}
    ip_val = (data.get("ip") or data.get("value") or "").strip()
    if not ip_val:
        return jsonify(error="ip required"), 400
    # Reuse the external-add path by re-emitting an internal call. Cleanest:
    # call the same helper. We import lazily to avoid a circular import.
    from flask import current_app
    with current_app.test_request_context(
        "/api/external/decisions", method="POST", json=data,
        headers={"Authorization": request.headers.get("Authorization", "")},
    ):
        # Use the same view function so behaviour is bitwise identical.
        view = current_app.view_functions["api_external_decisions"]
        return view()


@bp.route("/decisions/by-ip/<ip>", methods=["DELETE"])
@at.require_token("write")
def v1_decisions_rm(ip: str):
    """Soft-delete all decisions for a given IP (sets deleted_at)."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        cur = conn.execute(
            "UPDATE decisions SET deleted_at = ? WHERE value = ? AND deleted_at IS NULL",
            (now, ip),
        )
        n = cur.rowcount
    finally:
        conn.close()
    try:
        import siem
        siem.ship("decision.deleted", {"ip": ip, "source": "api_v1",
                                       "actor": f"token:{g.api_token['name']}"})
    except Exception:  # noqa: BLE001
        pass
    return jsonify(deleted=n, ip=ip)


# ── alerts (read-only) ─────────────────────────────────────────────────────

@bp.route("/alerts")
@at.require_token("read")
def v1_alerts_ls():
    try:
        limit = max(1, min(1000, int(request.args.get("limit", "100"))))
    except (TypeError, ValueError):
        limit = 100
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT created_at, source_ip, source_country, source_asn, scenario, events_count "
            "FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    finally:
        conn.close()
    return jsonify(items=[dict(r) for r in rows], count=len(rows))


# ── sync ───────────────────────────────────────────────────────────────────

@bp.route("/sync/status")
@at.require_token("read")
def v1_sync_status():
    return jsonify(
        last_at=get_setting("reconcile.last_at"),
        duration_ms=int(get_setting("reconcile.last_duration_ms") or "0"),
        to_add=int(get_setting("reconcile.last_to_add") or "0"),
        to_remove=int(get_setting("reconcile.last_to_remove") or "0"),
        errors=int(get_setting("reconcile.last_errors") or "0"),
        dry_run=(get_setting("reconcile.last_dry_run") or "1") == "1",
        notes=get_setting("reconcile.last_notes") or "",
        active_decisions=int(get_setting("poller.active_total") or "0"),
    )


@bp.route("/sync/run", methods=["POST"])
@at.require_token("write")
def v1_sync_run():
    """Force an immediate reconcile cycle."""
    from reconciler import run_once
    from db import get_setting as _gs
    dry = (_gs("settings.dry_run") or "1") == "1"
    try:
        batch_cap = max(1, int(_gs("settings.batch_cap") or "200"))
    except (TypeError, ValueError):
        batch_cap = 200
    result = run_once(source="manual", dry_run=dry, batch_cap=batch_cap)
    return jsonify(result)


# ── whitelist ──────────────────────────────────────────────────────────────

@bp.route("/whitelist")
@at.require_token("read")
def v1_whitelist_ls():
    import scenarios_admin as sa
    return jsonify(items=sa.list_whitelist(include_expired=False))


@bp.route("/whitelist", methods=["POST"])
@at.require_token("write")
def v1_whitelist_add():
    import scenarios_admin as sa
    data = request.get_json(silent=True) or {}
    res = sa.add_whitelist(
        (data.get("kind") or "ip").strip(),
        (data.get("value") or "").strip(),
        (data.get("note") or "").strip(),
        (data.get("expires_at") or None),
    )
    if not res.get("ok"):
        return jsonify(error=res.get("error", "add failed")), 400
    return jsonify(res), 201


@bp.route("/whitelist/<int:wid>", methods=["DELETE"])
@at.require_token("write")
def v1_whitelist_rm(wid: int):
    import scenarios_admin as sa
    sa.delete_whitelist(wid)
    return jsonify(deleted=wid)


# ── sources (federation) ───────────────────────────────────────────────────

@bp.route("/sources")
@at.require_token("read")
def v1_sources_ls():
    import federation
    out = []
    for s in federation.list_sources():
        out.append({
            "id": s.id, "name": s.name, "url": s.url,
            "enabled": s.enabled, "paused": s.paused,
            "confidence": s.confidence,
            "last_pull_at": s.last_pull_at,
            "last_pull_n": s.last_pull_n,
            "last_error": s.last_error,
        })
    return jsonify(items=out)


# ── tile (cross-app shortcut) ─────────────────────────────────────────────

@bp.route("/feed/banned-ips")
@at.require_token("read")
def v1_feed_banned_ips():
    """Compact polling feed for external systems (atom, custom scripts).
    Returns just IPs + scenarios + countries — no metadata.

    Query params:
      - since=<iso>   only IPs first-seen on or after this timestamp
      - limit=N       cap (default 5000, max 50000)
      - origin=...    filter by origin substring (e.g. "crowdsec")
    """
    try:
        limit = max(1, min(50000, int(request.args.get("limit", "5000"))))
    except (TypeError, ValueError):
        limit = 5000
    since = (request.args.get("since") or "").strip()
    origin = (request.args.get("origin") or "").strip()
    where = ["deleted_at IS NULL"]
    params: list[Any] = []
    if since:
        where.append("first_seen_at >= ?"); params.append(since)
    if origin:
        where.append("origin LIKE ?"); params.append(f"%{origin}%")
    sql = ("SELECT DISTINCT value AS ip, scope, scenario, origin "
           f"FROM decisions WHERE {' AND '.join(where)} "
           "ORDER BY id DESC LIMIT ?")
    params.append(limit)
    conn = get_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()
    return jsonify(
        feed_version=1,
        emitted_at=datetime.now(timezone.utc).isoformat(),
        count=len(rows),
        items=[dict(r) for r in rows],
    )


@bp.route("/tile/summary")
@at.require_token("read")
def v1_tile_summary():
    """Compact JSON for cross-app dashboard tiles (e.g. the othoni grid)."""
    return jsonify(
        active_bans=int(get_setting("poller.active_total") or "0"),
        sync_lag_seconds=_sync_lag(),
        last_reconcile_ms=int(get_setting("reconcile.last_duration_ms") or "0"),
        dry_run=(get_setting("reconcile.last_dry_run") or "1") == "1",
        sources_total=int(get_setting("poller.source_count") or "1"),
        cycle_count=int(get_setting("poller.cycles") or "0"),
        version="1.0",
    )


def _sync_lag() -> float:
    last_at = get_setting("poller.last_at") or ""
    if not last_at:
        return 1e9
    try:
        t = datetime.fromisoformat(last_at.replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - t).total_seconds())
    except (ValueError, AttributeError):
        return 1e9


# ── OpenAPI ────────────────────────────────────────────────────────────────

OPENAPI_SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {
        "title": "Protek API",
        "version": "1.0.0",
        "description": "Bouncer + observability API. All endpoints (except /ping) "
                       "require a bearer token with the appropriate scope.",
    },
    "servers": [{"url": "/api/v1"}],
    "components": {
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
        },
    },
    "security": [{"bearer": []}],
    "paths": {
        "/ping": {"get": {"summary": "Liveness probe (no auth)",
                          "security": [],
                          "responses": {"200": {"description": "ok"}}}},
        "/decisions": {
            "get": {"summary": "List active decisions",
                    "parameters": [
                        {"name": "scope", "in": "query", "schema": {"type": "string"}},
                        {"name": "origin", "in": "query", "schema": {"type": "string"}},
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 200}},
                    ],
                    "responses": {"200": {"description": "list"}}},
            "post": {"summary": "Add a decision",
                     "responses": {"202": {"description": "accepted"}}}},
        "/decisions/by-ip/{ip}": {
            "delete": {"summary": "Soft-delete decisions for an IP",
                       "parameters": [{"name": "ip", "in": "path", "required": True,
                                       "schema": {"type": "string"}}],
                       "responses": {"200": {"description": "ok"}}}},
        "/alerts": {"get": {"summary": "List alerts (requires machine creds upstream)",
                            "responses": {"200": {"description": "list"}}}},
        "/sync/status": {"get": {"summary": "Reconcile cycle status",
                                  "responses": {"200": {"description": "ok"}}}},
        "/sync/run": {"post": {"summary": "Force a reconcile cycle",
                                "responses": {"200": {"description": "result"}}}},
        "/whitelist": {
            "get": {"summary": "List whitelist rules",
                    "responses": {"200": {"description": "list"}}},
            "post": {"summary": "Add a whitelist rule",
                     "responses": {"201": {"description": "created"}}}},
        "/whitelist/{wid}": {
            "delete": {"summary": "Delete a whitelist rule",
                       "parameters": [{"name": "wid", "in": "path", "required": True,
                                       "schema": {"type": "integer"}}],
                       "responses": {"200": {"description": "ok"}}}},
        "/sources": {"get": {"summary": "List federation sources",
                              "responses": {"200": {"description": "list"}}}},
        "/tile/summary": {"get": {"summary": "Compact JSON for cross-app dashboard tiles",
                                   "responses": {"200": {"description": "summary"}}}},
    },
}


@bp.route("/search")
@at.require_token("read")
def v1_search():
    """Search across decisions, alerts, scenarios, audit log, and bouncer targets.

    Single query param `q` (substring). Returns a flat list of {kind, label,
    hint, href} suitable for rendering in the cmd-K palette.
    """
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify(items=[], count=0)
    try:
        limit_per_kind = max(1, min(50, int(request.args.get("limit", "8"))))
    except (TypeError, ValueError):
        limit_per_kind = 8
    pat = f"%{q}%"
    out: list[dict[str, Any]] = []
    conn = get_conn()
    try:
        # Decisions — match IP or scenario
        for r in conn.execute(
            "SELECT DISTINCT value, scenario, origin FROM decisions "
            "WHERE deleted_at IS NULL AND (value LIKE ? OR scenario LIKE ?) "
            "ORDER BY id DESC LIMIT ?", (pat, pat, limit_per_kind),
        ).fetchall():
            out.append({
                "kind": "decision",
                "label": r["value"],
                "hint": f"{r['scenario']} · {r['origin']}",
                "href": f"/attackers/{r['value']}",
            })
        # Alerts — by source IP or scenario
        for r in conn.execute(
            "SELECT source_ip, scenario, source_country FROM alerts "
            "WHERE source_ip LIKE ? OR scenario LIKE ? "
            "ORDER BY id DESC LIMIT ?", (pat, pat, limit_per_kind),
        ).fetchall():
            if not r["source_ip"]:
                continue
            out.append({
                "kind": "alert",
                "label": r["source_ip"],
                "hint": f"{r['scenario']} · {r['source_country'] or '?'}",
                "href": f"/attackers/{r['source_ip']}",
            })
        # Whitelist rules
        for r in conn.execute(
            "SELECT id, kind, value, note FROM whitelist "
            "WHERE (value LIKE ? OR note LIKE ?) "
            "AND (expires_at IS NULL OR expires_at > datetime('now')) "
            "ORDER BY id DESC LIMIT ?", (pat, pat, limit_per_kind),
        ).fetchall():
            out.append({
                "kind": "whitelist",
                "label": f"{r['kind']}={r['value']}",
                "hint": r["note"] or "whitelist rule",
                "href": "/whitelist",
            })
        # Bouncer targets
        for r in conn.execute(
            "SELECT id, name, kind FROM bouncer_targets WHERE name LIKE ? "
            "ORDER BY id LIMIT ?", (pat, limit_per_kind),
        ).fetchall():
            out.append({
                "kind": "bouncer",
                "label": r["name"],
                "hint": r["kind"],
                "href": f"/bouncers/edit/{r['id']}",
            })
        # Audit log
        for r in conn.execute(
            "SELECT action, target, actor, created_at FROM audit_log "
            "WHERE action LIKE ? OR target LIKE ? OR actor LIKE ? "
            "ORDER BY id DESC LIMIT ?", (pat, pat, pat, limit_per_kind),
        ).fetchall():
            out.append({
                "kind": "audit",
                "label": f"{r['action']}",
                "hint": f"{r['target'] or '—'} · {r['actor'] or '?'} · {r['created_at'][:19]}",
                "href": f"/audit?q={r['action']}",
            })
    finally:
        conn.close()
    return jsonify(items=out, count=len(out), q=q)


@bp.route("/openapi.json")
def v1_openapi():
    return jsonify(OPENAPI_SPEC)
