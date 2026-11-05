"""Off-box backup copy to Backblaze B2 / S3, set up from the Backup (off-box)
page.

Covers: validate_b2 (Backblaze region from the endpoint, blank key keeps the
current one, bad input), probe_b2 (upload/read-back/delete, friendly errors,
no secrets in messages), backup.run_backup copying a good local bundle
off-box (and staying "ok" when that fails), the off-box restore-test keeping
its own status, the nav "needs attention" signal, and the route: admin-only,
test before save, secrets never echoed or audited, "Stop off-box copies".

No network: boto3 and backup.S3Backend are replaced with in-memory fakes;
PROTEK_ENV_FILE points at a tmp file.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest
from dotenv import dotenv_values

import backup
import connection
import navsignals

SECRET = "K005-app-secret-xyz"


@pytest.fixture
def envfile(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text("SECRET_KEY='keep-me'\nBACKUP_PASSPHRASE='a-long-enough-passphrase'\n")
    monkeypatch.setenv("PROTEK_ENV_FILE", str(p))
    for k in connection.B2_KEYS:
        monkeypatch.delenv(k, raising=False)
    connection._seen_mtime.clear()
    connection._applied.clear()
    from db import set_setting
    set_setting(connection.SAVED_KEYS_SETTING, "[]")
    for k in ("last_at", "last_key", "last_size", "last_error", "last_error_at",
              "last_test_at", "last_test_ok"):
        set_setting(f"backup.offsite.{k}", "")
    return p


def _form(**over):
    f = {"s3_endpoint": "https://s3.us-west-002.backblazeb2.com", "s3_region": "",
         "s3_bucket": "protek-backups", "s3_key": "005abcdef", "s3_secret": SECRET}
    f.update(over)
    return f


# ── validate_b2 ────────────────────────────────────────────────────────────

def test_backblaze_region_comes_from_the_endpoint(envfile):
    values, errors = connection.validate_b2(_form())
    assert errors == []
    assert values["BACKUP_S3_REGION"] == "us-west-002"
    assert values["BACKUP_S3_SECRET"] == SECRET


def test_blank_application_key_keeps_the_current_one(envfile, monkeypatch):
    monkeypatch.setenv("BACKUP_S3_SECRET", "existing-secret")
    values, errors = connection.validate_b2(_form(s3_secret=""))
    assert errors == [] and values["BACKUP_S3_SECRET"] == "existing-secret"


@pytest.mark.parametrize("over, msg", [
    ({"s3_endpoint": "http://s3.example.com"}, "https://"),
    ({"s3_bucket": "x"}, "Bucket name"),
    ({"s3_bucket": "bad bucket"}, "Bucket name"),
    ({"s3_key": ""}, "Key ID"),
    ({"s3_secret": ""}, "application key is required"),
    ({"s3_secret": "has'quote"}, "application key can't"),
    ({"s3_region": "Not A Region!"}, "Region"),
])
def test_rejects_bad_input(envfile, over, msg):
    _, errors = connection.validate_b2(_form(**over))
    assert any(msg in e for e in errors), errors


# ── probe_b2 ───────────────────────────────────────────────────────────────

class FakeS3:
    def __init__(self, fail_code=None):
        self.objects, self.calls, self.fail_code = {}, [], fail_code

    def _maybe_fail(self, op):
        if self.fail_code:
            from botocore.exceptions import ClientError
            raise ClientError({"Error": {"Code": self.fail_code, "Message": "nope"}}, op)

    def put_object(self, Bucket, Key, Body, **kw):
        self._maybe_fail("PutObject")
        self.calls.append(("put", Key))
        self.objects[Key] = Body

    def head_object(self, Bucket, Key):
        self.calls.append(("head", Key))
        return {"ContentLength": len(self.objects[Key])}

    def delete_object(self, Bucket, Key):
        self.calls.append(("delete", Key))
        self.objects.pop(Key, None)


def _patch_boto(monkeypatch, fake):
    import boto3
    monkeypatch.setattr(boto3, "client", lambda *a, **k: fake)


def test_probe_uploads_reads_back_and_deletes(monkeypatch):
    fake = FakeS3()
    _patch_boto(monkeypatch, fake)
    values, _ = connection.validate_b2(_form())
    assert connection.probe_b2(values) == {"ok": True}
    assert [c[0] for c in fake.calls] == ["put", "head", "delete"]
    assert fake.objects == {}                                 # test file cleaned up


@pytest.mark.parametrize("code, says", [
    ("InvalidAccessKeyId", "key ID isn't recognised"),
    ("SignatureDoesNotMatch", "doesn't match the key ID"),
    ("NoSuchBucket", "no bucket called protek-backups"),
    ("AccessDenied", "needs read and write"),
])
def test_probe_explains_failures_without_secrets(monkeypatch, code, says):
    _patch_boto(monkeypatch, FakeS3(fail_code=code))
    values, _ = connection.validate_b2(_form())
    r = connection.probe_b2(values)
    assert r["ok"] is False and says in r["error"] and SECRET not in r["error"]


# ── backup.run_backup: local first, then off-box ──────────────────────────

class FakeBackend:
    name = "s3"
    store: dict = {}
    fail = False

    def __init__(self):
        self.bucket = "protek-backups"
        outer = self

        class _Client:
            def head_object(self, Bucket, Key):
                return {"ContentLength": len(outer.store[Key])}
        self.s3 = _Client()

    def put(self, key, data):
        if FakeBackend.fail:
            raise RuntimeError("endpoint unreachable")
        FakeBackend.store[key] = data
        return f"s3://{self.bucket}/{key}"

    def get(self, key):
        return FakeBackend.store[key]

    def list_keys(self, prefix=""):
        return sorted(k for k in FakeBackend.store if k.startswith(prefix))

    def delete(self, key):
        FakeBackend.store.pop(key, None)


@pytest.fixture
def local_backup(tmp_path, monkeypatch, envfile):
    from db import set_setting
    set_setting("backup.backend", "local")
    set_setting("backup.local_path", str(tmp_path / "bk"))
    monkeypatch.setattr(backup, "build_snapshot_blob", lambda pw: (b"ENCRYPTED-BUNDLE", {"files": []}))
    monkeypatch.setattr(backup, "S3Backend", FakeBackend)
    FakeBackend.store, FakeBackend.fail = {}, False
    for k, v in {"BACKUP_S3_BUCKET": "protek-backups", "BACKUP_S3_KEY": "005abc",
                 "BACKUP_S3_SECRET": SECRET, "BACKUP_PASSPHRASE": "a-long-enough-passphrase"}.items():
        monkeypatch.setenv(k, v)
    return tmp_path / "bk"


def test_good_backup_is_also_copied_off_box(local_backup):
    from db import get_setting
    run = backup.run_backup("daily")
    assert run["status"] == "ok" and run["backend"] == "local"
    assert run["offsite"]["status"] == "ok"
    key = run["offsite"]["dest"].split("protek-backups/")[1]
    assert FakeBackend.store[key] == b"ENCRYPTED-BUNDLE"
    assert (local_backup / key).read_bytes() == b"ENCRYPTED-BUNDLE"   # same key layout
    assert get_setting("backup.offsite.last_size") == str(len(b"ENCRYPTED-BUNDLE"))
    assert (get_setting("backup.offsite.last_error") or "") == ""


def test_off_box_failure_doesnt_fail_the_local_backup(local_backup):
    from db import get_setting
    FakeBackend.fail = True
    run = backup.run_backup("daily")
    assert run["status"] == "ok"
    assert run["offsite"]["status"] == "failed"
    assert "endpoint unreachable" in get_setting("backup.offsite.last_error")
    assert list(local_backup.rglob("*.bin"))


def test_no_bucket_no_off_box_step(local_backup, monkeypatch):
    monkeypatch.delenv("BACKUP_S3_BUCKET")
    run = backup.run_backup("daily")
    assert run["status"] == "ok" and "offsite" not in run


def test_off_box_restore_test_keeps_its_own_status(local_backup, monkeypatch):
    from db import get_setting, set_setting
    set_setting("backup.last_test_ok", "1")
    FakeBackend.store["daily/protek-20260101T000000Z.bin"] = b"not-a-real-bundle"
    r = backup.offsite_restore_test()
    assert r["status"] == "failed"                        # garbage bundle can't decrypt
    assert get_setting("backup.offsite.last_test_ok") == "0"
    assert get_setting("backup.last_test_ok") == "1"      # the local test's status is untouched


def test_off_box_failure_marks_access_and_backup(local_backup):
    from db import set_setting
    set_setting("backup.offsite.last_error", "RuntimeError: endpoint unreachable")
    navsignals.reset_cache()
    assert "admin_backup_auto" in navsignals.signals()["failing"]
    set_setting("backup.offsite.last_error", "")
    navsignals.reset_cache()


# ── the route ──────────────────────────────────────────────────────────────

@pytest.fixture
def make_client(monkeypatch, tmp_path, envfile):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    import app
    if app.poller:
        app.poller.stop()
    app.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False, SESSION_COOKIE_DOMAIN=None)
    monkeypatch.setitem(app.app.config, "WTF_CSRF_ENABLED", False)
    import litestream
    monkeypatch.setattr(litestream, "status", lambda: {})

    def make(role="admin"):
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


def test_admin_saves_after_a_passing_test(make_client, monkeypatch, envfile):
    from db import get_conn, get_setting
    monkeypatch.setattr(connection, "probe_b2", lambda v: {"ok": True})
    c = make_client()
    r = c.post("/admin/backup-automation/offsite", data={**_form(), "action": "save"})
    assert r.status_code == 302
    env = dotenv_values(envfile)
    assert env["BACKUP_S3_BUCKET"] == "protek-backups" and env["BACKUP_S3_REGION"] == "us-west-002"
    assert env["BACKUP_S3_SECRET"] == SECRET and env["SECRET_KEY"] == "keep-me"
    assert os.environ["BACKUP_S3_BUCKET"] == "protek-backups"          # applied, no restart
    assert "BACKUP_S3_SECRET" in json.loads(get_setting(connection.SAVED_KEYS_SETTING))
    conn = get_conn()
    try:
        audit = json.dumps([dict(a) for a in conn.execute(
            "SELECT * FROM audit_log WHERE action = 'backup.offsite'").fetchall()])
    finally:
        conn.close()
    assert "BACKUP_S3_SECRET" in audit and SECRET not in audit
    assert any("Bucket test passed" in m for m in _flashes(c))


def test_failed_test_saves_nothing_and_never_echoes_the_key(make_client, monkeypatch, envfile):
    monkeypatch.setattr(connection, "probe_b2",
                        lambda v: {"ok": False, "error": "the application key doesn't match the key ID"})
    before = envfile.read_text()
    r = make_client().post("/admin/backup-automation/offsite", data={**_form(), "action": "save"})
    assert r.status_code == 400 and envfile.read_text() == before
    page = r.get_data(as_text=True)
    form = page[page.index('id="offsite"'):]
    assert "doesn&#39;t match the key ID" in form or "doesn't match the key ID" in form
    assert 'value="protek-backups"' in form                             # typed fields kept
    assert SECRET not in page


def test_stop_off_box_copies(make_client, monkeypatch, envfile):
    monkeypatch.setattr(connection, "probe_b2", lambda v: {"ok": True})
    c = make_client()
    c.post("/admin/backup-automation/offsite", data={**_form(), "action": "save"})
    c.post("/admin/backup-automation/offsite", data={"action": "remove"})
    assert dotenv_values(envfile)["BACKUP_S3_BUCKET"] == ""
    assert not backup.offsite_configured()
    assert any("Off-box copies stopped" in m for m in _flashes(c))


def test_operators_cannot_set_it_up(make_client, monkeypatch, envfile):
    monkeypatch.setattr(connection, "probe_b2", lambda v: {"ok": True})
    before = envfile.read_text()
    r = make_client("operator").post("/admin/backup-automation/offsite",
                                     data={**_form(), "action": "save"})
    assert r.status_code in (302, 403) and envfile.read_text() == before


def test_page_shows_the_form_and_never_the_key(make_client, monkeypatch, envfile):
    monkeypatch.setenv("BACKUP_S3_SECRET", SECRET)
    monkeypatch.setenv("BACKUP_S3_BUCKET", "protek-backups")
    page = make_client().get("/admin/backup-automation").get_data(as_text=True)
    assert 'id="offsite"' in page and "Off-box copy" in page
    assert "set — leave blank to keep it" in page and SECRET not in page
