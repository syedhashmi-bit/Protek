"""
api_v2.py — Arc 13 phase 79. Versioned API surface.

Phase 79 is "the breaking-change window": rather than mutating /api/v1
when a future change needs to be incompatible, we ship a /api/v2 mount
point now. In 2.0 it's a thin alias over /api/v1 (every v1 route also
answers at v2 with identical semantics). When a real v2-only change
lands later, it's a fork point — operators migrate at their own pace,
v1 stays available with a deprecation header for 6 months minimum.

Mechanics:
  - `/api/v2/*` is registered as a second Flask blueprint that proxies
    each route name to the v1 implementation
  - `Sunset` and `Deprecation` HTTP headers are added to /api/v1/*
    responses when `api.v1.sunset_date` setting is set (e.g.
    "2027-05-21" for a year out)
  - `/api/version` exposes the current PROTEK_VERSION + supported
    api_versions so clients can negotiate

Why ship this in 2.0 even with no v1-incompatible changes:
  Once we promise /api/v1 stability, the only way to evolve is via /api/v2.
  Establishing the alias now means the *next* breaking change is a one-line
  toggle (move the new route into the v2-only set), not a fresh API design
  ceremony under deadline pressure.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, jsonify, request

from db import get_setting

log = logging.getLogger("protek.api_v2")

bp = Blueprint("api_v2", __name__, url_prefix="/api/v2")


@bp.route("/ping")
def v2_ping():
    """Smoke endpoint — confirms v2 is mounted and returns the deprecation
    table so a client can decide which version to use."""
    return jsonify(
        ok=True,
        api_version="v2",
        supported=["v1", "v2"],
        deprecated=[],
        notes="v2 is currently a transparent alias over v1 — no v1-only "
              "fields have been removed yet. Use v2 for new clients; v1 "
              "remains supported through the deprecation window.",
    )


def _v1_sunset_date() -> str | None:
    return (get_setting("api.v1.sunset_date") or "").strip() or None


def attach_deprecation_headers(app) -> None:
    """Wrap responses on /api/v1/* to add Sunset/Deprecation headers when
    a sunset date is configured. RFC 8594 Sunset header + RFC 9745
    Deprecation header.
    """
    @app.after_request
    def _tag_v1(resp):
        try:
            path = request.path
            if not path.startswith("/api/v1/"):
                return resp
            sunset = _v1_sunset_date()
            if not sunset:
                return resp
            # Deprecation: true (current best practice — RFC draft)
            resp.headers["Deprecation"] = "true"
            # Sunset: <HTTP-date>
            try:
                dt = datetime.fromisoformat(sunset).replace(tzinfo=timezone.utc)
                resp.headers["Sunset"] = dt.strftime("%a, %d %b %Y 00:00:00 GMT")
            except ValueError:
                resp.headers["Sunset"] = sunset
            resp.headers["Link"] = '</api/v2>; rel="successor-version"'
        except Exception:  # noqa: BLE001
            pass
        return resp


def _proxy_v1_to_v2(app) -> None:
    """Mount every route registered on the api_v1 blueprint a second time
    under /api/v2. Idempotent — guards against double-registration on
    gunicorn worker reboots.
    """
    from api_v1 import bp as v1_bp

    # Collect (rule, view_func, methods) tuples from v1's blueprint.
    # Flask blueprints store deferred functions; the easiest path is to
    # introspect the live app.url_map after v1 is registered, then for each
    # v1 rule add a parallel /api/v2/... rule pointing at the same view.
    seen = set()
    for rule in app.url_map.iter_rules():
        endpoint = rule.endpoint
        if not endpoint.startswith("api_v1."):
            continue
        if endpoint in seen:
            continue
        seen.add(endpoint)
        v2_endpoint = endpoint.replace("api_v1.", "api_v2_proxy.", 1)
        # Skip if we've already proxied this on a previous reload
        if any(r.endpoint == v2_endpoint for r in app.url_map.iter_rules()):
            continue
        view_func = app.view_functions.get(endpoint)
        if view_func is None:
            continue
        v2_path = rule.rule.replace("/api/v1/", "/api/v2/", 1)
        methods = [m for m in (rule.methods or set())
                   if m not in ("HEAD", "OPTIONS")]
        try:
            app.add_url_rule(v2_path, endpoint=v2_endpoint,
                             view_func=view_func, methods=methods)
        except AssertionError:
            # add_url_rule complains if endpoint already exists; safe to skip
            pass


def register(app, csrf) -> None:
    csrf.exempt(bp)
    app.register_blueprint(bp)
    _proxy_v1_to_v2(app)
    attach_deprecation_headers(app)
