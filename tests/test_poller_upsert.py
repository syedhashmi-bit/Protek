"""2026-10-15 — "lighter database" redesign.

`decisions` used to be keyed UNIQUE(origin_source, lapi_id). CrowdSec issues a
fresh lapi_id on every re-ban of the same IP+scenario, so that key never
deduplicated churn — it inserted a new row forever, which is how the live
table grew to millions of rows and drove the WAL-runaway incidents logged in
MEMORY.md. The fix: key on (origin_source, value, scope, scenario) instead,
so a re-ban upserts the existing row. These tests prove that property holds
across bootstrap and the stream path, which is the only thing that matters —
everything downstream (reconciler, dashboard) just reads a smaller table.
"""
from __future__ import annotations

from pathlib import Path

import pytest


def _setup_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def _mute_siem(monkeypatch: pytest.MonkeyPatch):
    import poller
    monkeypatch.setattr(poller.siem, "ship", lambda *a, **k: None)


class _FakeClient:
    """Minimal stand-in for crowdsec.LAPIClient — only what poller._bootstrap
    / _stream_apply call."""

    def __init__(self, name: str = "local"):
        self.name = name
        self._full: list[dict] = []
        self._new: list[dict] = []
        self._deleted: list[dict] = []

    def decisions(self, scope: str) -> list[dict]:
        return [d for d in self._full if d.get("scope", "Ip") == scope]

    def decisions_stream(self, startup: bool = False) -> dict:
        return {"new": self._new, "deleted": self._deleted}


def _row_count(tmp_path: Path, where: str = "1=1") -> int:
    import sqlite3
    conn = sqlite3.connect(tmp_path / "test.db")
    try:
        return conn.execute(f"SELECT COUNT(*) FROM decisions WHERE {where}").fetchone()[0]
    finally:
        conn.close()


# ── Bootstrap: re-ban (same identity, new lapi_id) upserts, doesn't duplicate ──


def test_bootstrap_rebans_do_not_duplicate_rows(monkeypatch: pytest.MonkeyPatch,
                                                 tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    _mute_siem(monkeypatch)
    import poller
    p = poller.Poller()
    client = _FakeClient()

    client._full = [{"id": 1, "value": "1.2.3.4", "scope": "Ip",
                     "scenario": "crowdsecurity/ssh-bf", "origin": "crowdsec",
                     "duration": "4h", "until": "2026-10-16T00:00:00Z", "type": "ban"}]
    p._bootstrap(client)
    assert _row_count(tmp_path) == 1
    assert _row_count(tmp_path, "deleted_at IS NULL") == 1

    # Re-ban: same IP+scope+scenario, a brand new lapi_id — exactly what
    # CrowdSec does on every re-ban. Must update in place, not insert.
    client._full = [{"id": 999, "value": "1.2.3.4", "scope": "Ip",
                     "scenario": "crowdsecurity/ssh-bf", "origin": "crowdsec",
                     "duration": "4h", "until": "2026-10-16T04:00:00Z", "type": "ban"}]
    p._bootstrap(client)
    assert _row_count(tmp_path) == 1, "re-ban must upsert, not insert a new row"

    import sqlite3
    conn = sqlite3.connect(tmp_path / "test.db")
    try:
        row = conn.execute(
            "SELECT lapi_id, until FROM decisions WHERE value = '1.2.3.4'"
        ).fetchone()
    finally:
        conn.close()
    assert row[0] == 999, "lapi_id must refresh to the latest"
    assert row[1] == "2026-10-16T04:00:00Z", "until must refresh to the latest"


def test_bootstrap_drops_missing_as_tombstone_by_identity(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """A row absent from a fresh full pull gets tombstoned — matched by
    (value, scope, scenario), not by its old lapi_id."""
    _setup_db(monkeypatch, tmp_path)
    _mute_siem(monkeypatch)
    import poller
    p = poller.Poller()
    client = _FakeClient()

    client._full = [
        {"id": 1, "value": "1.1.1.1", "scope": "Ip", "scenario": "s1"},
        {"id": 2, "value": "2.2.2.2", "scope": "Ip", "scenario": "s2"},
    ]
    p._bootstrap(client)
    assert _row_count(tmp_path, "deleted_at IS NULL") == 2

    # 2.2.2.2 ages out; only 1.1.1.1 remains in the fresh pull.
    client._full = [{"id": 1, "value": "1.1.1.1", "scope": "Ip", "scenario": "s1"}]
    p._bootstrap(client)
    assert _row_count(tmp_path, "deleted_at IS NULL") == 1
    assert _row_count(tmp_path) == 2, "tombstone, not delete"


def test_bootstrap_different_scenarios_same_ip_are_distinct_rows(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """The identity key includes scenario — the same IP banned under two
    scenarios simultaneously is still two rows (reconciler.py's own
    GROUP BY value, scope collapses these for the MikroTik push)."""
    _setup_db(monkeypatch, tmp_path)
    _mute_siem(monkeypatch)
    import poller
    p = poller.Poller()
    client = _FakeClient()
    client._full = [
        {"id": 1, "value": "5.5.5.5", "scope": "Ip", "scenario": "crowdsecurity/ssh-bf"},
        {"id": 2, "value": "5.5.5.5", "scope": "Ip", "scenario": "crowdsecurity/http-probing"},
    ]
    p._bootstrap(client)
    assert _row_count(tmp_path) == 2


# ── Stream path: same property, plus delete-by-current-lapi_id ────────────────


def test_stream_new_upserts_existing_identity(monkeypatch: pytest.MonkeyPatch,
                                               tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    _mute_siem(monkeypatch)
    import poller
    p = poller.Poller()
    client = _FakeClient()

    client._new = [{"id": 10, "value": "9.9.9.9", "scope": "Ip", "scenario": "s"}]
    p._stream_apply(client)
    assert _row_count(tmp_path) == 1

    client._new = [{"id": 11, "value": "9.9.9.9", "scope": "Ip", "scenario": "s"}]
    p._stream_apply(client)
    assert _row_count(tmp_path) == 1, "stream re-ban must upsert, not insert"


def test_stream_delete_matches_current_lapi_id_after_reban(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """A 'deleted' message referencing a superseded lapi_id (the LAPI hasn't
    caught up yet) must be a harmless no-op, not tombstone the current row."""
    _setup_db(monkeypatch, tmp_path)
    _mute_siem(monkeypatch)
    import poller
    p = poller.Poller()
    client = _FakeClient()

    client._new = [{"id": 1, "value": "7.7.7.7", "scope": "Ip", "scenario": "s"}]
    p._stream_apply(client)
    client._new = [{"id": 2, "value": "7.7.7.7", "scope": "Ip", "scenario": "s"}]  # reban
    p._stream_apply(client)

    # Stale delete for the superseded id=1 — must not touch the live row.
    client._new = []
    client._deleted = [{"id": 1, "value": "7.7.7.7", "scope": "Ip"}]
    p._stream_apply(client)
    assert _row_count(tmp_path, "deleted_at IS NULL") == 1, \
        "stale delete for a superseded lapi_id must not tombstone the current row"

    # Real delete for the current id=2 — must tombstone.
    client._deleted = [{"id": 2, "value": "7.7.7.7", "scope": "Ip"}]
    p._stream_apply(client)
    assert _row_count(tmp_path, "deleted_at IS NULL") == 0


# ── External/synthetic/ASN insert paths also upsert, not raise ────────────────


def test_synthetic_insert_upserts_on_repeat(monkeypatch: pytest.MonkeyPatch,
                                            tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    import synthetic
    lid1 = synthetic._next_lapi_id()
    synthetic._insert_synth_decision(lid1)
    assert _row_count(tmp_path) == 1

    lid2 = synthetic._next_lapi_id()
    assert lid2 != lid1
    synthetic._insert_synth_decision(lid2)  # same IP+scenario, no purge in between
    assert _row_count(tmp_path) == 1, \
        "a second synthetic run without cleanup must upsert, not crash"
