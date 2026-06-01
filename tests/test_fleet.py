"""Arc 16 phase 96 — /fleet view tests.

The fleet module is independently importable (no Flask dep) so we can
unit-test the data aggregation directly + smoke the route.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def _setup_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


# ── Hourly bucket aggregation ───────────────────────────────────────────────


def test_buckets_empty_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    import fleet
    chart = fleet._hourly_buckets(window_hours=24,
                                    now=datetime.now(timezone.utc))
    assert len(chart["buckets"]) == 24
    assert chart["cycles_total"] == 0
    assert chart["adds_total"] == 0
    assert chart["max_value"] == 0


def test_buckets_roll_into_correct_hour(monkeypatch: pytest.MonkeyPatch,
                                         tmp_path: Path):
    """A sync_event from N hours ago should land in bucket (window-1-N)."""
    _setup_db(monkeypatch, tmp_path)
    now = datetime(2026, 5, 28, 12, 0, 0, tzinfo=timezone.utc)
    one_hour_ago = (now - timedelta(hours=1)).isoformat()
    three_hours_ago = (now - timedelta(hours=3)).isoformat()
    from db import get_conn
    conn = get_conn()
    try:
        for ts, added, removed, errors in [
            (one_hour_ago, 100, 10, 0),
            (one_hour_ago, 50,  5,  1),  # second cycle in same hour
            (three_hours_ago, 200, 0, 0),
        ]:
            conn.execute(
                "INSERT INTO sync_events (started_at, added, removed, errors, "
                "duration_ms, source, dry_run) VALUES (?, ?, ?, ?, 1000, 'auto', 0)",
                (ts, added, removed, errors),
            )
    finally:
        conn.close()

    import fleet
    chart = fleet._hourly_buckets(window_hours=24, now=now)
    # 24 buckets, oldest at index 0, newest at 23
    # one_hour_ago → ago_h=1 → idx = 23 - 1 = 22
    assert chart["buckets"][22]["adds"] == 150
    assert chart["buckets"][22]["removes"] == 15
    assert chart["buckets"][22]["cycles"] == 2
    assert chart["buckets"][22]["errs"] == 1
    # three_hours_ago → idx = 23 - 3 = 20
    assert chart["buckets"][20]["adds"] == 200
    # max_value reflects the busiest bucket (adds + removes)
    assert chart["max_value"] == 200  # bucket 20 has 200+0; bucket 22 has 150+15
    assert chart["cycles_total"] == 3
    assert chart["adds_total"] == 350
    assert chart["errs_total"] == 1


# ── Helpers ─────────────────────────────────────────────────────────────────


def test_human_lag_thresholds():
    import fleet
    assert fleet._human_lag(None) == "—"
    assert fleet._human_lag(30) == "30s"
    assert fleet._human_lag(180) == "3m"
    assert fleet._human_lag(7200) == "2h"
    assert fleet._human_lag(172800) == "2d"


def test_extract_version_tolerant():
    import fleet
    assert fleet._extract_version({"version": "7.15.3"}) == "7.15.3"
    assert fleet._extract_version({"ros_version": "6.49.13"}) == "6.49.13"
    assert fleet._extract_version({"routeros": "long" * 20})[:32] == ("long" * 20)[:32]
    assert fleet._extract_version({}) == ""


def test_truncate():
    import fleet
    assert fleet._truncate("", 10) == ""
    assert fleet._truncate("short", 10) == "short"
    assert fleet._truncate("x" * 100, 20) == "x" * 19 + "…"
    # Newlines normalized to spaces
    assert "\n" not in fleet._truncate("a\nb", 10)


# ── Full build_view via fake bouncer ────────────────────────────────────────


class _StubBouncer:
    """Matches the Bouncer protocol enough for build_view()."""
    def __init__(self, name: str, kind: str, h: dict):
        self.name = name
        self.kind = kind
        self._h = h
    def is_configured(self): return True
    def health(self): return self._h
    def snapshot(self): return []
    def apply(self, *a, **k): return {}


def test_build_view_classifies_status(monkeypatch: pytest.MonkeyPatch,
                                      tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    from db import get_conn
    conn = get_conn()
    try:
        for name, kind, dry, err in [
            ("alpha", "mikrotik", 0, ""),
            ("beta",  "mikrotik", 1, "degraded: timeout 70s @ 2026-05-28"),
            ("gamma", "cloudflare", 0, "API quota exceeded"),
        ]:
            conn.execute(
                "INSERT INTO bouncer_targets "
                "(name, kind, config_json, enabled, dry_run, last_error, created_at) "
                "VALUES (?, ?, '{}', 1, ?, ?, '2026-05-28')",
                (name, kind, dry, err),
            )
    finally:
        conn.close()

    stubs = [
        _StubBouncer("alpha", "mikrotik",   {"ok": True,  "size": 1000, "version": "7.15"}),
        _StubBouncer("beta",  "mikrotik",   {"ok": True,  "size":  500, "version": "7.14"}),
        _StubBouncer("gamma", "cloudflare", {"ok": False, "v4_size": 200, "v6_size": 50,
                                              "error": "API quota exceeded"}),
    ]
    import sys, types
    fake_bouncers = types.ModuleType("bouncers")
    fake_bouncers.load_all_targets = lambda: stubs
    monkeypatch.setitem(sys.modules, "bouncers", fake_bouncers)

    import fleet
    view = fleet.build_view()
    by_name = {r["name"]: r for r in view["rows"]}

    assert by_name["alpha"]["status"] == "online"
    assert by_name["beta"]["status"]  == "degraded"  # last_error starts with degraded:
    assert by_name["gamma"]["status"] == "offline"

    assert by_name["alpha"]["size"] == 1000
    assert by_name["gamma"]["size"] == 250  # v4 + v6 fallback

    assert by_name["alpha"]["version"] == "7.15"
    assert by_name["gamma"]["version"] == ""

    assert view["kpis"]["total"] == 3
    assert view["kpis"]["online"] == 1
    assert view["kpis"]["degraded"] == 1
    assert view["kpis"]["offline"] == 1
    assert view["kpis"]["total_entries"] == 1750
