"""
graphql_api.py — Arc 12 phase 73. GraphQL surface alongside REST.

Strawberry-based read-mostly schema covering the data the REST surface
already exposes plus the multi-source joins that would otherwise need
several REST round-trips:

  - decisions (filterable by scope/scenario/origin/value substring)
  - alerts
  - reputation (per-IP composite score from phase 58)
  - bouncers (multi-target snapshot)
  - synthetic test history
  - sync events

Auth: same bearer-token model as /api/v1/* — `read` scope required for
queries, `write` for any future mutations. Anonymous queries 401.

GraphiQL explorer at /api/graphql/explorer (admin role only — exposes
the full schema, you don't want random visitors crawling it). The bare
endpoint at /api/graphql accepts POSTs with JSON `{query, variables}`.

Why GraphQL on top of a CRUD-ish REST: useful when a dashboard needs
"all active SSH bruteforcers from China with reputation>70 plus their
CTI dossier" — REST would take ~50 calls; GraphQL does it in one.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import strawberry
from strawberry.flask.views import GraphQLView

from db import get_conn

log = logging.getLogger("protek.graphql")


# ── Types ───────────────────────────────────────────────────────────────────

@strawberry.type
class Decision:
    id: int
    origin_source: str
    lapi_id: int
    value: str
    scope: str
    type: str
    scenario: str
    origin: str
    until: Optional[str]
    first_seen_at: str
    last_seen_at: str
    asn: Optional[str]
    as_org: Optional[str]


@strawberry.type
class Alert:
    id: int
    origin_source: str
    scenario: str
    source_ip: str
    source_asn: str
    source_country: str
    events_count: int
    created_at: str


@strawberry.type
class ReputationBreakdown:
    cti: int
    severity: int
    cross_source: int
    age_decay: int
    cti_behaviors: int


@strawberry.type
class Reputation:
    ip: str
    score: int
    tier: str
    breakdown: Optional[ReputationBreakdown]
    computed_at: str


@strawberry.type
class BouncerTarget:
    id: int
    name: str
    kind: str
    enabled: bool
    dry_run: bool
    last_sync_at: Optional[str]
    last_error: Optional[str]


@strawberry.type
class SyncEvent:
    id: int
    started_at: str
    duration_ms: int
    added: int
    removed: int
    unchanged: int
    errors: int
    source: str
    dry_run: bool


@strawberry.type
class SyntheticRun:
    id: int
    started_at: str
    status: str
    targets_n: int
    ok_n: int
    duration_ms: int


# ── Query root ─────────────────────────────────────────────────────────────

def _row_to_decision(r) -> Decision:
    return Decision(
        id=r["id"], origin_source=r["origin_source"], lapi_id=r["lapi_id"],
        value=r["value"], scope=r["scope"], type=r["type"],
        scenario=r["scenario"] or "", origin=r["origin"] or "",
        until=r["until"], first_seen_at=r["first_seen_at"],
        last_seen_at=r["last_seen_at"],
        asn=(r["asn"] if "asn" in r.keys() else "") or "",
        as_org=(r["as_org"] if "as_org" in r.keys() else "") or "",
    )


@strawberry.type
class Query:
    @strawberry.field
    def decisions(
        self,
        scope: Optional[str] = None,
        scenario_contains: Optional[str] = None,
        value_contains: Optional[str] = None,
        origin_source: Optional[str] = None,
        country: Optional[str] = None,
        min_reputation: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Decision]:
        clauses = ["deleted_at IS NULL"]
        params: list[Any] = []
        if scope:
            clauses.append("scope = ?")
            params.append(scope)
        if scenario_contains:
            clauses.append("scenario LIKE ?")
            params.append(f"%{scenario_contains}%")
        if value_contains:
            clauses.append("value LIKE ?")
            params.append(f"%{value_contains}%")
        if origin_source:
            clauses.append("origin_source = ?")
            params.append(origin_source)
        sql = ("SELECT d.* FROM decisions d "
               + (" JOIN geo_cache g ON g.ip = d.value " if country else "")
               + " WHERE " + " AND ".join(clauses)
               + (" AND g.country_code = ? " if country else "")
               + " ORDER BY d.id DESC LIMIT ? OFFSET ?")
        if country:
            params.append(country.upper())
        params.append(int(min(1000, max(1, limit))))
        params.append(int(max(0, offset)))
        conn = get_conn()
        try:
            rows = conn.execute(sql, tuple(params)).fetchall()
        finally:
            conn.close()

        out = [_row_to_decision(r) for r in rows]
        if min_reputation is not None and out:
            from reputation import get_or_compute
            ips = {d.value for d in out}
            kept = set()
            for ip in ips:
                try:
                    rep = get_or_compute(ip)
                    if rep and rep.get("score", 0) >= int(min_reputation):
                        kept.add(ip)
                except Exception:  # noqa: BLE001
                    continue
            out = [d for d in out if d.value in kept]
        return out

    @strawberry.field
    def alerts(self, limit: int = 100) -> list[Alert]:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                (int(min(1000, max(1, limit))),),
            ).fetchall()
        finally:
            conn.close()
        return [Alert(id=r["id"], origin_source=r["origin_source"],
                      scenario=r["scenario"], source_ip=r["source_ip"],
                      source_asn=r["source_asn"], source_country=r["source_country"],
                      events_count=int(r["events_count"] or 0),
                      created_at=r["created_at"])
                for r in rows]

    @strawberry.field
    def reputation(self, ip: str) -> Optional[Reputation]:
        try:
            from reputation import get_or_compute
            data = get_or_compute(ip)
        except Exception:  # noqa: BLE001
            return None
        if not data:
            return None
        bd = data.get("breakdown") or {}
        breakdown = ReputationBreakdown(
            cti=int(bd.get("cti", 0)),
            severity=int(bd.get("severity", 0)),
            cross_source=int(bd.get("cross_source", 0)),
            age_decay=int(bd.get("age_decay", 0)),
            cti_behaviors=int(bd.get("cti_behaviors", 0)),
        )
        return Reputation(ip=ip, score=int(data.get("score", 0)),
                          tier=data.get("tier", ""),
                          breakdown=breakdown,
                          computed_at=data.get("computed_at", ""))

    @strawberry.field
    def bouncers(self) -> list[BouncerTarget]:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM bouncer_targets ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
        return [BouncerTarget(
            id=r["id"], name=r["name"], kind=r["kind"],
            enabled=bool(r["enabled"]), dry_run=bool(r["dry_run"]),
            last_sync_at=r["last_sync_at"],
            last_error=r["last_error"] or "",
        ) for r in rows]

    @strawberry.field
    def sync_events(self, limit: int = 50) -> list[SyncEvent]:
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM sync_events ORDER BY id DESC LIMIT ?",
                (int(min(500, max(1, limit))),),
            ).fetchall()
        finally:
            conn.close()
        return [SyncEvent(
            id=r["id"], started_at=r["started_at"],
            duration_ms=int(r["duration_ms"] or 0),
            added=int(r["added"] or 0), removed=int(r["removed"] or 0),
            unchanged=int(r["unchanged"] or 0), errors=int(r["errors"] or 0),
            source=r["source"], dry_run=bool(r["dry_run"]),
        ) for r in rows]

    @strawberry.field
    def synthetic_runs(self, limit: int = 20) -> list[SyntheticRun]:
        try:
            import synthetic
            rows = synthetic.list_runs(int(min(200, max(1, limit))))
        except Exception:  # noqa: BLE001
            return []
        return [SyntheticRun(
            id=r["id"], started_at=r["started_at"],
            status=r["status"], targets_n=int(r["targets_n"] or 0),
            ok_n=int(r["ok_n"] or 0),
            duration_ms=int(r["duration_ms"] or 0),
        ) for r in rows]


schema = strawberry.Schema(query=Query)


# ── Auth wrapper for the Flask view ────────────────────────────────────────

def _requires_bearer(view_func):
    """Strawberry's Flask integration runs the view directly; we wrap the
    request handler to require a `read`-scoped bearer token."""
    from functools import wraps
    from flask import request, jsonify
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        import api_tokens as at
        raw = ""
        h = request.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            raw = h[7:].strip()
        elif request.headers.get("X-Protek-Token"):
            raw = request.headers.get("X-Protek-Token", "").strip()
        tok = at.lookup(raw) if raw else None
        # Sessions also work — admin/operator/viewer in /api/graphql/explorer
        from flask import session
        is_session_user = session.get("logged_in") and session.get("role") in (
            "viewer", "operator", "admin")
        if not (tok or is_session_user):
            return jsonify(errors=[{"message": "unauthorized"}]), 401
        if tok and not at.has_scope(tok, "read"):
            return jsonify(errors=[{"message": "token lacks read scope"}]), 403
        return view_func(*args, **kwargs)
    return wrapper


def register(app, csrf) -> None:
    """Wire /api/graphql + /api/graphql/explorer onto the Flask app."""
    # Strawberry's Flask GraphQLView already handles POST JSON + GET introspection.
    api_view = GraphQLView.as_view(
        "graphql_api", schema=schema, graphql_ide="graphiql",
    )
    # CSRF exempt — GraphQL endpoints authenticate via Bearer header, not session,
    # so a CSRF token isn't applicable in the standard XHR-from-browser case.
    csrf.exempt(api_view)
    app.add_url_rule(
        "/api/graphql",
        view_func=_requires_bearer(api_view),
        methods=["GET", "POST"],
    )
    # Explorer at a separate URL so we can session-gate it without breaking
    # the API endpoint's token auth.
    explorer_view = GraphQLView.as_view(
        "graphql_explorer", schema=schema, graphql_ide="graphiql",
    )
    csrf.exempt(explorer_view)

    from functools import wraps
    from flask import session, redirect, url_for
    @wraps(explorer_view)
    def gated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return ("admin role required for the GraphQL explorer", 403)
        return explorer_view(*args, **kwargs)
    app.add_url_rule(
        "/api/graphql/explorer",
        view_func=gated,
        methods=["GET", "POST"],
    )
