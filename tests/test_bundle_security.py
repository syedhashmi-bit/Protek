"""Bundle import — SQL identifier validation (bug-fix regression test).

The earlier `apply_bundle` interpolated column names from the imported
payload directly into the INSERT statement. Even though the route is
admin-only, a malicious or corrupted bundle could craft column names
to break the SQL — e.g. `password_hash) VALUES (999, 'evil')--` would
rewrite the VALUES clause. Identifier validation now rejects any
column name that isn't `[A-Za-z_][A-Za-z0-9_]*`.
"""
from __future__ import annotations

from pathlib import Path

import pytest


def _setup_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def test_ident_re_accepts_normal_columns():
    import bundle
    for c in ["id", "username", "password_hash", "created_at", "_private",
               "X1", "abc_123"]:
        assert bundle._IDENT_RE.match(c), f"{c!r} should be a valid identifier"


def test_ident_re_rejects_injection_attempts():
    import bundle
    for bad in [
        "id; DROP TABLE users",
        "value) VALUES (1, 2)--",
        "name,role",
        "user name",     # space
        "1user",         # starts with digit
        "user-name",     # hyphen
        "user.name",     # dot
        '"users"',       # quotes
        "",              # empty
    ]:
        assert not bundle._IDENT_RE.match(bad), \
            f"{bad!r} must NOT be accepted as an identifier"


def test_apply_bundle_skips_rows_with_bad_column_names(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mocker=None):
    """End-to-end: a payload that includes a row with an injection-style
    column name must be counted as skipped, not inserted. The rest of
    the (clean) rows in the same table should still apply normally."""
    _setup_db(monkeypatch, tmp_path)

    # Build a payload mock directly (skip the encrypt/decrypt step — we're
    # testing apply, not the envelope).
    import bundle as bmod

    # We need to seed something the bundle can actually insert. Use
    # `settings` — a benign single-row table.
    payload = {
        "format_version": 1,
        "exported_at": "2026-05-28T03:00:00+00:00",
        "tables": {
            "settings": [
                # clean row — should be inserted
                {"key": "test.clean", "value": "ok",
                 "updated_at": "2026-05-28T03:00:00+00:00"},
                # malicious row — column name injection attempt
                {"key": "test.evil",
                 "value) VALUES (999, 'pwned', 'now')--": "garbage",
                 "updated_at": "2026-05-28T03:00:00+00:00"},
                # another clean row
                {"key": "test.clean2", "value": "ok2",
                 "updated_at": "2026-05-28T03:00:00+00:00"},
            ]
        }
    }

    # Patch parse_bundle to return our raw payload (avoids needing the
    # right passphrase for an encrypted bundle).
    monkeypatch.setattr(bmod, "parse_bundle", lambda blob, pw: payload)

    result = bmod.import_bundle(b"", "anything", overwrite=False)
    summary = result["summary"]["settings"]

    # Two clean rows applied, one malicious row skipped — total 3 source rows
    assert summary["source_rows"] == 3
    assert summary["skipped"] == 1
    # Inserted count is 2 (the clean rows) — INSERT OR IGNORE returns
    # rowcount=1 for new rows, 0 for collisions
    assert summary["inserted"] == 2

    # Verify the malicious payload did NOT corrupt the table
    from db import get_conn
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT key, value FROM settings WHERE key LIKE 'test.%'"
        ).fetchall()
    finally:
        conn.close()
    keys = {r["key"]: r["value"] for r in rows}
    assert "test.clean" in keys and keys["test.clean"] == "ok"
    assert "test.clean2" in keys and keys["test.clean2"] == "ok2"
    # No row was created with id=999 / value='pwned'
    assert "test.evil" not in keys
