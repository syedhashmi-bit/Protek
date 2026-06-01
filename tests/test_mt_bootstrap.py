"""Arc 16 phase 94 — MikroTik RouterOS bootstrap script tests.

Acceptance gates from ROADMAP.md:
  - Endpoint returns 200 with the expected Content-Type.
  - Rendered script contains the minimum perms string.
  - Templated values flow through correctly.
  - Bad query parameter is rejected with 400 (anti-injection).
"""
from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Flask test client pointed at a temp DB. Logs in by forging the
    session — same trick the screenshot pipeline uses (see MEMORY.md
    confluence_docs entry)."""
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()

    import app
    from datetime import datetime, timezone
    app.app.config["TESTING"] = True
    # SESSION_COOKIE_SECURE defaults to True in production — the Flask
    # test_client uses HTTP, so without this override the forged session
    # cookie is never sent back to the server.
    app.app.config["SESSION_COOKIE_SECURE"] = False
    # SESSION_COOKIE_DOMAIN may be set in production to share auth
    # across apps (phase 74). The test client serves from localhost, so
    # clear the domain to keep the cookie matching.
    app.app.config["SESSION_COOKIE_DOMAIN"] = None
    c = app.app.test_client()
    with c.session_transaction() as s:
        s["logged_in"] = True
        s["username"] = "testop"
        s["role"] = "operator"
        # `_upgrade_legacy_session` before_request hook clears the
        # session if role is set but user_id isn't resolvable from the
        # users table. Setting both keys skips that path entirely.
        s["user_id"] = 1
        s["last_active"] = datetime.now(timezone.utc).isoformat()
    return c


def test_rsc_endpoint_returns_text_plain(client):
    r = client.get("/bouncers/mt-bootstrap.rsc")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/plain")
    assert "protek-mt-bootstrap.rsc" in r.headers["Content-Disposition"]


def test_rsc_contains_minimum_perms(client):
    """The whole point of the bootstrap is the constrained permission
    set — verify the .rsc body actually contains the policy line we
    expect. Anything else means the script grants more rights than
    documented."""
    r = client.get("/bouncers/mt-bootstrap.rsc")
    body = r.get_data(as_text=True)
    assert "policy=api,read,write,test" in body
    # Sanity-check that we're NOT granting these:
    for forbidden in [",policy,", ",ftp,", ",winbox,", ",web,",
                       ",password,", ",sensitive,", ",local,"]:
        assert forbidden not in body, (
            f"bootstrap script unexpectedly grants {forbidden!r}")


def test_default_values_render(client):
    r = client.get("/bouncers/mt-bootstrap.rsc")
    body = r.get_data(as_text=True)
    assert 'username "protek"' in body
    assert 'groupname "protek-bouncer"' in body
    # Address-list default is `crowdsec` per CLAUDE.md convention
    assert 'listname "crowdsec"' in body


def test_query_params_template_through(client):
    r = client.get(
        "/bouncers/mt-bootstrap.rsc"
        "?username=edge-bouncer&group=fleet-bouncer&list_name=cs-edge"
    )
    body = r.get_data(as_text=True)
    assert 'username "edge-bouncer"' in body
    assert 'groupname "fleet-bouncer"' in body
    assert 'listname "cs-edge"' in body


def test_html_page_renders_and_embeds_script(client):
    r = client.get("/bouncers/mt-bootstrap")
    assert r.status_code == 200
    assert b"<pre" in r.data
    assert b"policy=api,read,write,test" in r.data
    # Copy-to-clipboard button is present
    assert b"copy-btn" in r.data


def test_bad_param_returns_400(client):
    """Anti-injection: a query value containing RouterOS syntax must NOT
    flow into the rendered script body. Anything outside
    [A-Za-z0-9_-]{1,32} is rejected at the route boundary."""
    # Spaces, semicolons, slashes — typical injection payloads
    for bad in [
        "?username=evil; /user remove [find]",
        "?group=foo bar",
        "?list_name=/etc/passwd",
        "?username=" + "x" * 50,  # too long
    ]:
        r = client.get("/bouncers/mt-bootstrap.rsc" + bad)
        assert r.status_code == 400, f"expected 400 for {bad!r}"


def test_html_page_requires_login(monkeypatch: pytest.MonkeyPatch,
                                  tmp_path: Path):
    """The bootstrap script is a credential-issuing artifact. The route
    is gated behind login_required — verify that's actually enforced."""
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()

    import app
    app.app.config["TESTING"] = True
    c = app.app.test_client()
    # No session forged → request should redirect to /login (302) or
    # return 401, never 200.
    r = c.get("/bouncers/mt-bootstrap", follow_redirects=False)
    assert r.status_code in (302, 401)
    r = c.get("/bouncers/mt-bootstrap.rsc", follow_redirects=False)
    assert r.status_code in (302, 401)
