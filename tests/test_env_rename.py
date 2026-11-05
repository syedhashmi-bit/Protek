"""Renaming the .env-configured router (Targets → All targets → rename).

The name is a label in the settings table: load_all_targets() picks it up
on the next call, it must be unique across targets (the Targets page and
the reconciler look targets up by name), and the change is audited.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

import bouncers


@pytest.fixture
def make_client(monkeypatch, tmp_path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    import app
    if app.poller:
        app.poller.stop()
    app.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False, SESSION_COOKIE_DOMAIN=None)
    monkeypatch.setitem(app.app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.setenv("MT_HOST", "192.0.2.1")
    monkeypatch.setenv("MT_USERNAME", "protek")
    monkeypatch.setenv("MT_PASSWORD", "pw")

    def make(role="operator"):
        now = datetime.now(timezone.utc).isoformat()
        conn = db.get_conn()
        try:
            conn.execute("INSERT INTO users (username, password_hash, totp_secret, role, created_at, "
                         "disabled) VALUES (?, 'x', 'y', ?, ?, 0)", (f"u-{role}", role, now))
            uid = conn.execute("SELECT id FROM users WHERE username = ?", (f"u-{role}",)).fetchone()["id"]
        finally:
            conn.close()
        c = app.app.test_client()
        with c.session_transaction() as s:
            s.update(logged_in=True, username=f"u-{role}", role=role, user_id=uid, last_active=now)
        return c
    return make


def _flashes(c):
    with c.session_transaction() as s:
        return [m for _, m in s.get("_flashes", [])]


def _env_target():
    return next(t for t in bouncers.load_all_targets() if t.kind == "mikrotik_env")


def test_default_name_is_mikrotik(make_client):
    make_client()
    assert _env_target().name == "mikrotik"


def test_rename_applies_and_is_audited(make_client):
    from db import get_conn
    c = make_client()
    r = c.post("/bouncers/env/rename", data={"env_name": "  home-edge  "})
    assert r.status_code == 302
    assert _env_target().name == "home-edge"
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM audit_log WHERE action = 'bouncer.env.rename'").fetchone()
    finally:
        conn.close()
    assert row and json.loads(row["before_json"])["name"] == "mikrotik"
    assert json.loads(row["after_json"])["name"] == "home-edge"
    assert any("Renamed" in m for m in _flashes(c))


def test_targets_page_shows_the_new_name_and_rename_button(make_client):
    c = make_client()
    c.post("/bouncers/env/rename", data={"env_name": "home-edge"})
    html = c.get("/bouncers").get_data(as_text=True)
    assert ">home-edge<" in html
    assert 'name="env_name"' in html


@pytest.mark.parametrize("bad", ["", "   ", "x" * 41, "tab\there"])
def test_rejects_bad_names(make_client, bad):
    c = make_client()
    c.post("/bouncers/env/rename", data={"env_name": bad})
    assert _env_target().name == "mikrotik"
    assert any("1–40 printable" in m for m in _flashes(c))


def test_rejects_a_name_another_target_uses(make_client):
    from db import get_conn
    conn = get_conn()
    try:
        conn.execute("INSERT INTO bouncer_targets (name, kind, config_json, enabled, dry_run, created_at) "
                     "VALUES ('Office', 'mikrotik', '{}', 0, 1, '2026-01-01')")
    finally:
        conn.close()
    c = make_client()
    c.post("/bouncers/env/rename", data={"env_name": "office"})
    assert _env_target().name == "mikrotik"
    assert any("already called" in m for m in _flashes(c))


def test_viewers_cannot_rename(make_client):
    c = make_client("viewer")
    c.post("/bouncers/env/rename", data={"env_name": "nope"})
    assert _env_target().name == "mikrotik"
    assert 'name="env_name"' not in c.get("/bouncers").get_data(as_text=True)
