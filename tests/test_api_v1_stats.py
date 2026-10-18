"""GET /api/v1/stats — counts-only summary for public displays, and the
narrow `stats` token scope that opens it and nothing else."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

NOW = datetime.now(timezone.utc)

# (value, origin_source, scenario, first_seen, last_seen, deleted_at, country)
ROWS = [
    # new this week, active, geolocated
    ("198.51.100.1", "local", "ssh-bf", NOW - timedelta(hours=1), NOW, None, "AU"),
    # same IP, second scenario: a separate active decision, same country
    ("198.51.100.1", "local", "http-probing", NOW - timedelta(days=2), NOW, None, "AU"),
    # new this week, since expired (still a new ban), different country
    ("198.51.100.2", "local", "ssh-bf", NOW - timedelta(days=3),
     NOW - timedelta(days=2), NOW - timedelta(days=1), "DE"),
    # new this week, active, not geolocated yet
    ("198.51.100.3", "peer", "ssh-bf", NOW - timedelta(days=6), NOW, None, None),
    # old ban re-seen recently (last_seen bumped): active but NOT new
    ("198.51.100.4", "local", "ssh-bf", NOW - timedelta(days=30), NOW, None, "US"),
    # old and long gone
    ("198.51.100.5", "local", "ssh-bf", NOW - timedelta(days=40),
     NOW - timedelta(days=39), NOW - timedelta(days=38), "FR"),
]
IPS = sorted({r[0] for r in ROWS})

# Every route a `stats` token must NOT open: (method, path, json body or None).
# Covers each read-scoped /api/v1 GET, the v2 alias, the write routes, the
# external endpoints and GraphQL.
FORBIDDEN_FOR_STATS = [
    ("GET", "/api/v1/decisions", None),
    ("GET", "/api/v1/alerts", None),
    ("GET", "/api/v1/whitelist", None),
    ("GET", "/api/v1/sources", None),
    ("GET", "/api/v1/feed/banned-ips", None),
    ("GET", "/api/v1/tile/summary", None),
    ("GET", "/api/v1/sync/status", None),
    ("GET", "/api/v1/search?q=198", None),
    ("GET", "/api/v1/reputation/198.51.100.1", None),
    ("GET", "/api/v1/honeypot/targets", None),
    ("GET", "/api/v1/ml/anomalies", None),
    ("GET", "/api/v2/decisions", None),
    ("POST", "/api/v1/decisions", {"ip": "203.0.113.7"}),
    ("POST", "/api/v1/sync/run", {}),
    ("POST", "/api/v1/whitelist", {"cidr": "203.0.113.0/24"}),
    ("POST", "/api/external/decisions", {"ip": "203.0.113.7"}),
    ("POST", "/api/external/introspect", {"ip": "203.0.113.7"}),
    ("POST", "/api/external/honeypot/callback", {"ip": "203.0.113.7"}),
    ("GET", "/api/graphql?query=%7B__typename%7D", None),
    ("POST", "/api/graphql", {"query": "{ decisions { value } }"}),
]


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    conn = db.get_conn()
    try:
        for i, (ip, src, scen, first, last, deleted, cc) in enumerate(ROWS):
            conn.execute(
                "INSERT INTO decisions (origin_source, lapi_id, value, scope, scenario, "
                "origin, first_seen_at, last_seen_at, deleted_at) "
                "VALUES (?, ?, ?, 'Ip', ?, 'crowdsec', ?, ?, ?)",
                (src, i + 1, ip, scen, first.isoformat(), last.isoformat(),
                 deleted.isoformat() if deleted else None),
            )
            if cc:
                conn.execute(
                    "INSERT OR IGNORE INTO geo_cache (ip, country, country_code, cached_at) "
                    "VALUES (?, ?, ?, ?)", (ip, cc, cc, NOW.isoformat()))
    finally:
        conn.close()

    import api_tokens
    import api_v1
    import app
    import poller
    # What the poller stamps at the end of every cycle; /stats reads it.
    db.set_setting("poller.active_total", str(poller._count_active()))
    app.app.config["TESTING"] = True
    api_v1._reset_stats_cache()
    tokens = {
        scope: api_tokens.create_token(f"t-{scope}", scope, "pytest")["token"]
        for scope in ("stats", "read", "write", "admin")
    }
    yield db, api_v1, app.app.test_client(), tokens
    api_v1._reset_stats_cache()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_requires_a_token(env):
    _, _, client, _ = env
    assert client.get("/api/v1/stats").status_code == 401
    r = client.get("/api/v1/stats", headers=_auth("pk_not-a-real-token"))
    assert r.status_code == 401
    assert "active_bans" not in r.get_data(as_text=True)


def test_shape_and_counts(env):
    _, _, client, tokens = env
    r = client.get("/api/v1/stats", headers=_auth(tokens["stats"]))
    assert r.status_code == 200
    body = r.get_json()
    assert set(body) == {"active_bans", "new_bans_7d", "countries_7d", "generated_at"}
    for key in ("active_bans", "new_bans_7d", "countries_7d"):
        assert type(body[key]) is int, key
    # DISTINCT active values (.1 counted once despite two scenarios, plus .3, .4)
    assert body["active_bans"] == 3
    assert body["new_bans_7d"] == 4      # decisions first seen in the last 7 days, deleted or not
    assert body["countries_7d"] == 2     # AU + DE among the new ones; ungeolocated skipped
    gen = datetime.fromisoformat(body["generated_at"].replace("Z", "+00:00"))
    assert gen.tzinfo is not None and gen.utcoffset() == timedelta(0)
    assert abs((datetime.now(timezone.utc) - gen).total_seconds()) < 60


def test_active_bans_matches_tile_summary(env):
    _, _, client, tokens = env
    stats = client.get("/api/v1/stats", headers=_auth(tokens["read"])).get_json()
    tile = client.get("/api/v1/tile/summary", headers=_auth(tokens["read"])).get_json()
    status = client.get("/api/v1/sync/status", headers=_auth(tokens["read"])).get_json()
    assert stats["active_bans"] == tile["active_bans"] == status["active_decisions"]


def test_body_carries_no_identifiers(env):
    _, _, client, tokens = env
    text = client.get("/api/v1/stats", headers=_auth(tokens["stats"])).get_data(as_text=True)
    for needle in IPS + ["ssh-bf", "http-probing", "crowdsec", "peer", "AU", "DE"]:
        assert needle not in text


def test_x_protek_token_header_also_works(env):
    _, _, client, tokens = env
    r = client.get("/api/v1/stats", headers={"X-Protek-Token": tokens["stats"]})
    assert r.status_code == 200


@pytest.mark.parametrize("scope", ["stats", "read", "write", "admin"])
def test_every_scope_opens_stats(env, scope):
    _, _, client, tokens = env
    assert client.get("/api/v1/stats", headers=_auth(tokens[scope])).status_code == 200


@pytest.mark.parametrize(("method", "path", "body"), FORBIDDEN_FOR_STATS,
                         ids=[f"{m} {p}" for m, p, _ in FORBIDDEN_FOR_STATS])
def test_stats_token_is_refused_everywhere_else(env, method, path, body):
    _, _, client, tokens = env
    r = client.open(path, method=method, json=body, headers=_auth(tokens["stats"]))
    assert r.status_code == 403, r.get_data(as_text=True)
    text = r.get_data(as_text=True)
    for needle in IPS:
        assert needle not in text


def test_read_token_still_opens_a_read_route(env):
    # The control for the test above: the refusal is the scope, not the route.
    _, _, client, tokens = env
    r = client.get("/api/v1/decisions", headers=_auth(tokens["read"]))
    assert r.status_code == 200
    assert "198.51.100.1" in r.get_data(as_text=True)


def test_has_scope_matrix():
    from api_tokens import has_scope

    def tok(*scopes: str) -> dict:
        return {"scope_set": set(scopes)}

    expected = {
        "stats": {"stats"},
        "read": {"stats", "read"},
        "write": {"stats", "read", "write"},
        "admin": {"stats", "read", "write", "admin"},
    }
    for granted, ok in expected.items():
        for required in ("stats", "read", "write", "admin"):
            assert has_scope(tok(granted), required) is (required in ok), (granted, required)
    # Unknown scopes match only themselves and never escalate.
    assert has_scope(tok("custom"), "custom")
    assert not has_scope(tok("custom"), "stats")
    assert not has_scope(tok("admin"), "custom")
    assert not has_scope(tok(), "stats")


def test_create_token_accepts_stats_scope(env):
    import api_tokens
    res = api_tokens.create_token("only-stats", "stats", "pytest")
    assert res["scopes"] == ["stats"]
    row = next(t for t in api_tokens.list_tokens() if t["id"] == res["id"])
    assert row["scopes"] == "stats"
    with pytest.raises(ValueError):
        api_tokens.create_token("bad", "statz", "pytest")


def test_revoked_token_is_refused(env):
    import api_tokens
    _, _, client, _ = env
    res = api_tokens.create_token("to-revoke", "stats", "pytest")
    assert client.get("/api/v1/stats", headers=_auth(res["token"])).status_code == 200
    api_tokens.revoke_token(res["id"])
    assert client.get("/api/v1/stats", headers=_auth(res["token"])).status_code == 401


def test_result_is_cached_for_the_ttl(env, monkeypatch: pytest.MonkeyPatch):
    db, api_v1, client, tokens = env
    token = tokens["stats"]
    clock = [1000.0]
    monkeypatch.setattr(api_v1, "_clock", lambda: clock[0])
    first = client.get("/api/v1/stats", headers=_auth(token)).get_json()

    conn = db.get_conn()
    try:
        conn.execute(
            "INSERT INTO decisions (origin_source, lapi_id, value, scope, scenario, "
            "first_seen_at, last_seen_at) VALUES ('local', 99, '203.0.113.9', 'Ip', 'x', ?, ?)",
            (NOW.isoformat(), NOW.isoformat()))
    finally:
        conn.close()
    import poller
    db.set_setting("poller.active_total", str(poller._count_active()))  # next poller cycle

    clock[0] += api_v1.STATS_TTL_SEC - 1
    assert client.get("/api/v1/stats", headers=_auth(token)).get_json() == first

    clock[0] += 2
    fresh = client.get("/api/v1/stats", headers=_auth(token)).get_json()
    assert fresh["active_bans"] == first["active_bans"] + 1
    assert fresh["new_bans_7d"] == first["new_bans_7d"] + 1
