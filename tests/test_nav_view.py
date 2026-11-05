"""Roadmap #3 — the simple / advanced view.

Covers: the simple sidebar, the toggle (per user, survives a new session),
in-use and failing advanced features showing anyway (with a badge), direct
links to hidden pages still working with their tab shown, the palette still
listing everything (labelled "advanced"), role × view, the install default
(fresh = simple, upgraded = advanced), and navsignals tolerating tables that
don't exist yet.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone

import pytest

import navsignals

SIMPLE_ITEMS = ["Overview", "Blocked IPs", "Alerts", "Detections", "Targets", "Rules",
                "Settings", "Access &amp; backup"]
ADVANCED_ITEMS = ["Threat intel", "Sources", "Activity", "Integrations"]


@pytest.fixture
def make_client(monkeypatch, tmp_path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    import app
    # Importing app starts the real poller thread, whose disk watchdog writes
    # disk.*_alerted into whichever DB is current — which would make
    # "Activity" legitimately appear. Stop it so the signals are ours.
    if app.poller:
        app.poller.stop()
        if app.poller._thread:
            app.poller._thread.join(timeout=30)
    from db import get_conn
    conn = get_conn()
    try:
        conn.execute("DELETE FROM settings WHERE key LIKE 'disk.%'")
    finally:
        conn.close()
    navsignals.reset_cache()
    app.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False, SESSION_COOKIE_DOMAIN=None)
    monkeypatch.setitem(app.app.config, "WTF_CSRF_ENABLED", False)

    def make(role="admin", name=None):
        name = name or f"u-{role}"
        now = datetime.now(timezone.utc).isoformat()
        conn = db.get_conn()
        try:
            row = conn.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()
            if not row:
                conn.execute("INSERT INTO users (username, password_hash, totp_secret, role, "
                             "created_at, disabled) VALUES (?, 'x', 'y', ?, ?, 0)", (name, role, now))
                row = conn.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()
        finally:
            conn.close()
        c = app.app.test_client()
        with c.session_transaction() as s:
            s.update(logged_in=True, username=name, role=role, user_id=row["id"], last_active=now)
        return c
    yield make
    navsignals.reset_cache()


def sidebar(html: str) -> str:
    return html[html.index('<nav class="side"'):html.index("</nav>")]


def labels(html: str) -> list[str]:
    return [re.sub(r"<.*", "", m).strip()
            for m in re.findall(r'<a href="[^"]*" class="[^"]*"\s*(?:title="[^"]*")?>\s*([^<]+)', sidebar(html))]


def palette(html: str) -> str:
    return html[html.index("var ITEMS = ["):html.index("var sel = 0")]


def test_fresh_install_starts_simple(make_client):
    html = make_client().get("/").get_data(as_text=True)
    got = labels(html)
    for item in SIMPLE_ITEMS:
        assert item in got, (item, got)
    for item in ADVANCED_ITEMS:
        assert item not in got, (item, got)
    assert "Advanced view: <b>off</b>" in html


def test_toggle_shows_everything_and_survives_a_new_session(make_client):
    c = make_client()
    r = c.post("/ui/view", data={"advanced": "1", "next": "/decisions"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/decisions")
    navsignals.reset_cache()
    fresh = make_client()                      # same user, new session = after logout/login
    html = fresh.get("/").get_data(as_text=True)
    got = labels(html)
    for item in SIMPLE_ITEMS + ADVANCED_ITEMS:
        assert item in got, (item, got)
    assert "Advanced view: <b>on</b>" in html
    fresh.post("/ui/view", data={"advanced": "0"})
    assert "Threat intel" not in labels(fresh.get("/").get_data(as_text=True))


def test_toggle_refuses_offsite_next(make_client):
    r = make_client().post("/ui/view", data={"advanced": "1", "next": "https://evil.example/"})
    assert "evil.example" not in r.headers["Location"]


def test_in_use_feature_stays_visible(make_client):
    from db import get_conn
    conn = get_conn()
    try:
        conn.execute("INSERT INTO sources (name, url, api_key, enabled, created_at) "
                     "VALUES ('vps-b', 'http://10.0.0.2:8080', 'k', 1, '2026-01-01')")
    finally:
        conn.close()
    navsignals.reset_cache()
    html = make_client().get("/").get_data(as_text=True)
    assert "Sources" in labels(html)
    assert "nav-dot" not in sidebar(html)


def test_failing_feature_gets_a_badge(make_client):
    from db import get_conn
    conn = get_conn()
    try:
        conn.execute("INSERT INTO sources (name, url, api_key, enabled, created_at, last_error) "
                     "VALUES ('vps-b', 'http://10.0.0.2:8080', 'k', 1, '2026-01-01', 'timed out')")
    finally:
        conn.close()
    navsignals.reset_cache()
    html = make_client().get("/").get_data(as_text=True)
    side = sidebar(html)
    assert "Sources" in labels(html)
    assert re.search(r"Sources<span class=\"nav-dot\"", side)


def test_in_use_tab_of_a_simple_item(make_client):
    from db import set_setting
    set_setting("honeypot.enabled", "1")
    navsignals.reset_cache()
    html = make_client().get("/settings").get_data(as_text=True)
    tabs = html[html.index('<div class="tabs">'):]
    tabs = tabs[:tabs.index("</div>")]
    assert "Honeypot" in tabs and "Connection &amp; sync" in tabs


def test_hidden_page_still_opens_with_its_tab(make_client):
    c = make_client()
    r = c.get("/fleet")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    tabs = html[html.index('<div class="tabs">'):]
    tabs = tabs[:tabs.index("</div>")]
    assert ">Fleet" in tabs
    # The Activity group stays hidden even while Fleet is open.
    assert "Activity" not in labels(html)


def test_hidden_item_opens_and_appears_while_open(make_client):
    html = make_client().get("/federation").get_data(as_text=True)
    assert "Sources" in labels(html)


def test_palette_lists_advanced_pages_in_the_simple_view(make_client):
    pal = palette(make_client().get("/").get_data(as_text=True))
    for label in ("Threat intel", "Sources", "Fleet", "DR drill", "High availability"):
        assert re.search(r"kind:'advanced', label:'" + re.escape(label) + "'", pal), label
    assert "kind:'monitor', label:'Overview'" in pal


def test_roles_still_apply_in_the_advanced_view(make_client):
    viewer = make_client("viewer")
    viewer.post("/ui/view", data={"advanced": "1"})
    html = viewer.get("/").get_data(as_text=True)
    assert "Access &amp; backup" not in labels(html)
    assert "Publish feed" not in palette(html)
    op = make_client("operator")
    op.post("/ui/view", data={"advanced": "1"})
    assert "Publish feed" not in palette(op.get("/").get_data(as_text=True))


def test_upgraded_install_defaults_advanced(tmp_path, monkeypatch):
    import db
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, "
                "password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin', "
                "created_at TEXT NOT NULL, last_login_at TEXT DEFAULT NULL, disabled INTEGER NOT NULL DEFAULT 0)")
    old.commit()
    old.close()
    monkeypatch.setattr(db, "DB_PATH", path)
    db.init_db()
    assert db.get_setting("ui.advanced_default") == "1"
    cols = {r[1] for r in sqlite3.connect(path).execute("PRAGMA table_info(users)")}
    assert "ui_advanced" in cols


def test_fresh_install_default_is_simple(tmp_path, monkeypatch):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "new.db")
    db.init_db()
    assert db.get_setting("ui.advanced_default") == "0"
    db.init_db()                                   # a later boot doesn't flip it
    assert db.get_setting("ui.advanced_default") == "0"


def test_signals_tolerate_missing_lazy_tables(tmp_path, monkeypatch):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "s.db")
    db.init_db()
    navsignals.reset_cache()
    s = navsignals.signals()                       # protek_peers etc. don't exist yet
    assert s == {"configured": set(), "failing": set()}


def test_disk_alert_surfaces_activity_with_a_badge(make_client):
    from db import set_setting
    set_setting("disk.warn_alerted", "1")
    navsignals.reset_cache()
    html = make_client().get("/").get_data(as_text=True)
    assert re.search(r"Activity<span class=\"nav-dot\"", sidebar(html))



def test_viewers_keep_the_security_and_setup_tabs(make_client):
    html = make_client("viewer").get("/security").get_data(as_text=True)
    tabs = html[html.index('<div class="tabs">'):]
    tabs = tabs[:tabs.index("</div>")]
    assert "Security" in tabs and "Setup guide" in tabs
    assert "Connection &amp; sync" not in tabs              # operator-only tab


def test_toggle_after_a_post_rendered_page_goes_back_to_a_get(make_client):
    import connection
    c = make_client("admin")
    r = c.post("/settings/connection", data={"lapi_url": "nope"},
               headers={"Referer": "http://localhost/settings"})
    assert r.status_code == 400
    html = r.get_data(as_text=True)
    assert 'name="next" value="/settings"' in html
    assert connection  # imported for the route


def test_scenario_editor_keeps_its_catalog_tab(make_client):
    import app
    c = make_client("admin")
    with app.app.test_request_context("/scenarios/editor"):
        from flask import session
        with c.session_transaction() as s:
            session.update(dict(s))
        keys = [t["key"] for t in app.nav_tabs_for("scenarios_editor")]
        assert keys == ["scenarios", "catalog"]
        assert app.nav_owner_of("scenarios_editor") == "scenarios"
