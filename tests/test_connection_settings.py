"""Roadmap #2 — edit the CrowdSec + MikroTik connection in the browser.

Covers connection.py (validation, the .env writer, cross-worker sync) and the
/settings/connection route: admin-only, test before save, "save anyway",
secrets never echoed or audited, applied without a restart (this worker's
globals, the `local` source row, other workers via sync_from_file, the
poller's local-LAPI state).

Never touches a real .env: PROTEK_ENV_FILE points at a tmp file.
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timezone

import pytest
from dotenv import dotenv_values

import connection

SECRET_KEY_VAL = "bouncerkey-OLD-1234"
SECRET_PW_VAL = "old#pass $word"


@pytest.fixture
def envfile(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text(
        "# Protek .env (test)\n"
        "SECRET_KEY='keep-me'\n"
        "CROWDSEC_LAPI_URL=http://127.0.0.1:8080\n"
        f"CROWDSEC_BOUNCER_KEY={SECRET_KEY_VAL}\n"
        "MT_HOST=192.0.2.1\n"
        "MT_PORT=8728\n"
        "MT_USERNAME=protek\n"
        f"MT_PASSWORD='{SECRET_PW_VAL}'\n"
        "DRY_RUN=true\n"
    )
    p.chmod(0o600)
    monkeypatch.setenv("PROTEK_ENV_FILE", str(p))
    for k, v in {"CROWDSEC_LAPI_URL": "http://127.0.0.1:8080", "CROWDSEC_BOUNCER_KEY": SECRET_KEY_VAL,
                 "MT_HOST": "192.0.2.1", "MT_PORT": "8728", "MT_USE_SSL": "false",
                 "MT_USERNAME": "protek", "MT_PASSWORD": SECRET_PW_VAL}.items():
        monkeypatch.setenv(k, v)
    connection._seen_mtime.clear()
    connection._applied.clear()
    from db import set_setting
    set_setting(connection.SAVED_KEYS_SETTING, "[]")       # tests share a DB
    return p


def _form(**over):
    f = {"lapi_url": "http://127.0.0.1:8080", "lapi_key": "", "mt_host": "192.0.2.1",
         "mt_port": "8728", "mt_username": "protek", "mt_password": ""}
    f.update(over)
    return f


# ── validate ───────────────────────────────────────────────────────────────

def test_blank_secrets_keep_the_current_ones(envfile):
    values, errors = connection.validate(_form())
    assert errors == []
    assert values["CROWDSEC_BOUNCER_KEY"] == SECRET_KEY_VAL
    assert values["MT_PASSWORD"] == SECRET_PW_VAL


@pytest.mark.parametrize("over, msg", [
    ({"lapi_url": "not a url"}, "LAPI URL"),
    ({"lapi_url": "http://host:8080/#x"}, "can't contain"),
    ({"lapi_key": "a'b"}, "bouncer key"),
    ({"lapi_key": "line\nbreak"}, "bouncer key"),
    ({"mt_port": "99999"}, "port"),
    ({"mt_host": "bad host!"}, "Router address"),
    ({"mt_username": ""}, "username is required"),
    ({"mt_username": "has space"}, "username"),
    ({"mt_password": "it's"}, "single quote"),
    # Found in review: these slip past a newline-only check.
    ({"mt_password": "x\u2028SECRET_KEY=pwned"}, "control characters"),
    ({"mt_password": "nul\x00byte"}, "control characters"),
    ({"mt_password": "back\\slash"}, "backslash"),
    ({"lapi_key": "key\\x"}, "bouncer key"),
])
def test_rejects_bad_input(envfile, over, msg):
    _, errors = connection.validate(_form(**over))
    assert any(msg in e for e in errors), errors


def test_password_may_contain_hash_and_dollar(envfile):
    values, errors = connection.validate(_form(mt_password="p#ss $1 ok"))
    assert errors == [] and values["MT_PASSWORD"] == "p#ss $1 ok"


def test_clearing_the_router_clears_its_password(envfile):
    values, errors = connection.validate(_form(mt_host="", mt_username=""))
    assert errors == []
    assert values["MT_HOST"] == "" and values["MT_PASSWORD"] == ""


def test_tls_checkbox_defaults_port_8729(envfile):
    values, _ = connection.validate(_form(mt_port="", mt_use_ssl="1"))
    assert values["MT_PORT"] == "8729" and values["MT_USE_SSL"] == "true"


# ── write_env ──────────────────────────────────────────────────────────────

def test_write_env_keeps_other_lines_and_round_trips(envfile):
    envfile.write_text(envfile.read_text() + "MT_HOST=duplicate\n")
    values, _ = connection.validate(_form(mt_password="n3w#pa$s", lapi_key="NEWKEY"))
    connection.write_env(values)
    text = envfile.read_text()
    assert text.startswith("# Protek .env (test)\n")
    assert "SECRET_KEY='keep-me'" in text and "DRY_RUN=true" in text
    assert text.count("MT_HOST=") == 1                       # duplicate dropped
    parsed = dotenv_values(envfile)
    assert parsed["MT_PASSWORD"] == "n3w#pa$s"
    assert parsed["CROWDSEC_BOUNCER_KEY"] == "NEWKEY"
    assert parsed["MT_USE_SSL"] == "false"                   # appended
    assert stat.S_IMODE(os.stat(envfile).st_mode) == 0o600
    assert not [p for p in envfile.parent.iterdir() if p.name.startswith(".env.")]


# ── sync across workers ────────────────────────────────────────────────────

def _save_externally(envfile, **kv):
    """What another worker's save looks like from here: file + saved_keys."""
    from db import set_setting
    lines = [ln for ln in envfile.read_text().splitlines() if ln.split("=")[0] not in kv]
    lines += [f"{k}='{v}'" for k, v in kv.items()]
    envfile.write_text("\n".join(lines) + "\n")
    st = envfile.stat()
    os.utime(envfile, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    set_setting(connection.SAVED_KEYS_SETTING, json.dumps(sorted(kv)))


def test_other_worker_picks_up_a_save(envfile):
    assert connection.sync_from_file("web") is False          # baseline
    _save_externally(envfile, MT_HOST="198.51.100.7")
    assert connection.sync_from_file("web") is True
    assert os.environ["MT_HOST"] == "198.51.100.7"
    assert connection.sync_from_file("web") is False          # nothing new


def test_saving_worker_still_tells_its_poller(envfile):
    # The poller shares os.environ with the worker that saved, so "env
    # changed?" would miss it; each consumer tracks what it last acted on.
    connection.sync_from_file("poller")
    _save_externally(envfile, CROWDSEC_LAPI_URL="http://10.9.9.9:8080")
    os.environ["CROWDSEC_LAPI_URL"] = "http://10.9.9.9:8080"  # already applied here
    assert connection.sync_from_file("poller") is True


def test_only_browser_saved_keys_override_the_deployment(envfile, monkeypatch):
    # Docker: compose env wins over /data/.env unless the key was saved here.
    monkeypatch.setenv("CROWDSEC_LAPI_URL", "http://host.docker.internal:8080")
    envfile.write_text(envfile.read_text().replace("MT_HOST=192.0.2.1", "MT_HOST='203.0.113.5'"))
    from db import set_setting
    set_setting(connection.SAVED_KEYS_SETTING, json.dumps(["MT_HOST"]))
    connection.sync_from_file("boot")
    assert os.environ["MT_HOST"] == "203.0.113.5"
    assert os.environ["CROWDSEC_LAPI_URL"] == "http://host.docker.internal:8080"


def test_poller_drops_local_lapi_state_on_change(envfile):
    from poller import Poller
    p = Poller(interval_sec=10, dry_run=True, batch_cap=10)
    p._sync_connection()                                       # baseline
    p._bootstrap_done["local"] = True
    p._fail_streak["local"] = 3
    p._machine_client = object()
    _save_externally(envfile, CROWDSEC_BOUNCER_KEY="NEWKEY")
    p._sync_connection()
    assert "local" not in p._bootstrap_done and "local" not in p._fail_streak
    assert p._machine_client is None and p._force_blocking is True


# ── the route ──────────────────────────────────────────────────────────────

@pytest.fixture
def make_client(monkeypatch, tmp_path, envfile):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    import app
    app.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False, SESSION_COOKIE_DOMAIN=None)
    monkeypatch.setitem(app.app.config, "WTF_CSRF_ENABLED", False)

    def make(role):
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


@pytest.fixture
def probes(monkeypatch):
    state = {"lapi": {"ok": True}, "mikrotik": {"ok": True, "name": "edge", "version": "7.16"}}
    monkeypatch.setattr(connection, "probe", lambda values: {k: dict(v) for k, v in state.items()})
    return state


def _flashes(c):
    with c.session_transaction() as s:
        return [m for _, m in s.get("_flashes", [])]


def test_operators_cannot_change_the_connection(make_client, probes, envfile):
    before = envfile.read_text()
    r = make_client("operator").post("/settings/connection", data=_form(mt_host="198.51.100.9"))
    assert r.status_code in (302, 403)
    assert envfile.read_text() == before


def test_admin_saves_and_it_applies_without_restart(make_client, probes, envfile):
    import app
    from db import get_conn
    c = make_client("admin")
    r = c.post("/settings/connection", data=_form(lapi_url="http://10.1.1.1:8080", lapi_key="NEWKEY",
                                                  mt_host="198.51.100.9"))
    assert r.status_code == 302
    parsed = dotenv_values(envfile)
    assert parsed["CROWDSEC_LAPI_URL"] == "http://10.1.1.1:8080"
    assert parsed["MT_HOST"] == "198.51.100.9"
    assert parsed["MT_PASSWORD"] == SECRET_PW_VAL                # kept
    assert os.environ["MT_HOST"] == "198.51.100.9"
    assert app.LAPI_URL == "http://10.1.1.1:8080" and app.LAPI_KEY == "NEWKEY"
    conn = get_conn()
    try:
        row = conn.execute("SELECT url, api_key, backoff_until FROM sources WHERE name='local'").fetchone()
        audit = conn.execute("SELECT * FROM audit_log WHERE action='settings.connection'").fetchall()
    finally:
        conn.close()
    assert (row["url"], row["api_key"], row["backoff_until"]) == ("http://10.1.1.1:8080", "NEWKEY", None)
    assert len(audit) == 1
    blob = json.dumps([dict(a) for a in audit])
    assert "CROWDSEC_LAPI_URL" in blob and "NEWKEY" not in blob and "10.1.1.1" not in blob
    msgs = " ".join(_flashes(c))
    assert "no restart needed" in msgs and "re-sync from the new CrowdSec LAPI" in msgs


def test_failed_test_blocks_the_save(make_client, probes, envfile):
    probes["mikrotik"] = {"ok": False, "error": "invalid user name or password"}
    before = envfile.read_text()
    c = make_client("admin")
    r = c.post("/settings/connection", data=_form(mt_host="198.51.100.9", mt_password="typed-secret"))
    assert r.status_code == 400
    assert envfile.read_text() == before
    page = r.get_data(as_text=True)
    assert 'value="198.51.100.9"' in page          # typed non-secret kept
    assert "typed-secret" not in page              # secret never echoed
    form = page[page.index('id="connection"'):]
    assert "MikroTik: invalid user name or password." in form   # shown in the form
    assert "Not saved." in form


def test_save_anyway(make_client, probes, envfile):
    probes["lapi"] = {"ok": False, "error": "couldn't reach it"}
    c = make_client("admin")
    c.post("/settings/connection", data={**_form(mt_host="198.51.100.9"), "save_anyway": "1"})
    assert dotenv_values(envfile)["MT_HOST"] == "198.51.100.9"


def test_validation_errors_dont_probe(make_client, monkeypatch, envfile):
    called = []
    monkeypatch.setattr(connection, "probe", lambda v: called.append(v))
    r = make_client("admin").post("/settings/connection", data=_form(mt_port="0"))
    assert r.status_code == 400 and called == []


def test_nothing_changed(make_client, probes, envfile):
    c = make_client("admin")
    before = envfile.read_text()
    c.post("/settings/connection", data=_form())
    assert envfile.read_text() == before
    assert any("Nothing changed" in m for m in _flashes(c))


def test_settings_page_never_shows_secrets(make_client, envfile):
    page = make_client("admin").get("/settings").get_data(as_text=True)
    assert 'id="connection"' in page
    assert SECRET_KEY_VAL not in page and SECRET_PW_VAL not in page
    assert SECRET_KEY_VAL[-4:] not in page
    assert "set — leave blank to keep it" in page


def test_operators_see_it_read_only(make_client, envfile):
    page = make_client("operator").get("/settings").get_data(as_text=True)
    assert "Only admins can change these." in page
    assert "Test and save" not in page


def test_unwritable_env_is_refused(make_client, probes, envfile, monkeypatch):
    monkeypatch.setattr(connection, "writable", lambda: (False, "Protek can't write it."))
    before = envfile.read_text()
    c = make_client("admin")
    c.post("/settings/connection", data=_form(mt_host="198.51.100.9"))
    assert envfile.read_text() == before
    assert "Protek can't write it." in _flashes(c)



# ── review fixes ───────────────────────────────────────────────────────────

def test_unicode_line_separator_in_an_untouched_line_survives(envfile):
    # splitlines() would split this comment; a rewrite must not create lines.
    envfile.write_text(envfile.read_text() + "# note\u2028still one line\n")
    connection.write_env({"MT_HOST": "198.51.100.3"})
    assert "# note\u2028still one line" in envfile.read_text()


def test_only_changed_keys_become_browser_owned(envfile):
    from db import get_setting
    values, _ = connection.validate(_form(mt_host="198.51.100.4"))
    changed = connection.changed_keys(values)
    assert changed == ["MT_HOST"]
    connection.save({k: values[k] for k in changed})
    assert json.loads(get_setting(connection.SAVED_KEYS_SETTING)) == ["MT_HOST"]
    assert dotenv_values(envfile)["CROWDSEC_LAPI_URL"] == "http://127.0.0.1:8080"


def test_save_swaps_the_file_in_last(envfile, monkeypatch):
    # Another worker reacts to the new mtime; by then saved_keys and env
    # must already be final, or it would baseline on an empty key list.
    from db import get_setting
    seen = {}
    real = os.replace

    def spy(src, dst):
        seen["saved_keys"] = get_setting(connection.SAVED_KEYS_SETTING)
        seen["env"] = os.environ.get("MT_HOST")
        return real(src, dst)
    monkeypatch.setattr(connection.os, "replace", spy)
    connection.save({"MT_HOST": "198.51.100.5"})
    assert json.loads(seen["saved_keys"]) == ["MT_HOST"] and seen["env"] == "198.51.100.5"


def test_failed_save_leaves_no_temp_file_and_no_change(envfile, monkeypatch):
    before = envfile.read_text()
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(connection.os, "replace", boom)
    with pytest.raises(OSError):
        connection.save({"MT_HOST": "198.51.100.6"})
    assert envfile.read_text() == before
    assert not [p for p in envfile.parent.iterdir() if p.name.startswith(".env.")]


def test_a_bad_value_in_env_never_breaks_sync(envfile):
    from db import set_setting
    set_setting(connection.SAVED_KEYS_SETTING, json.dumps(["MT_PASSWORD"]))
    envfile.write_text(envfile.read_text().replace(f"MT_PASSWORD='{SECRET_PW_VAL}'", "MT_PASSWORD='a\x00b'"))
    connection.sync_from_file("boot")                       # must not raise
    assert os.environ["MT_PASSWORD"] == SECRET_PW_VAL
