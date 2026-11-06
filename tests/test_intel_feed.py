"""Public intel feeds: the plain-text endpoint and the whitelist filter both
feeds share. A whitelisted IP can keep an active decision in the DB (reconcile
skips it), so it must be filtered here too or the feed would publish it."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import db
import intel_publish
import scenarios_admin as sa


@pytest.fixture
def feed_db(monkeypatch):
    tmp = Path(tempfile.mkdtemp(prefix="protek-feed-")) / "t.db"
    monkeypatch.setattr(db, "DB_PATH", tmp)
    db.init_db()
    now = datetime.now(timezone.utc)
    conn = db.get_conn()
    for i, (ip, asn) in enumerate([("198.51.100.7", "AS64500"), ("203.0.113.10", ""),
                                   ("192.0.2.5", ""), ("198.51.100.7", "AS64500"),
                                   ("203.0.113.99", "AS64511")]):
        conn.execute(
            "INSERT INTO decisions (origin_source, lapi_id, value, scope, type, scenario, origin,"
            " duration, until, first_seen_at, last_seen_at, deleted_at, asn)"
            " VALUES ('local', ?, ?, 'Ip', 'ban', ?, 'crowdsec', '4h', ?, ?, ?, NULL, ?)",
            (i, ip, f"crowdsecurity/s{i}", (now + timedelta(hours=4)).isoformat(),
             now.isoformat(), now.isoformat(), asn))
    conn.close()
    db.set_setting("intel.publish.enabled", "1")
    sa.add_whitelist("ip", "203.0.113.10", note="home")
    sa.add_whitelist("cidr", "192.0.2.0/28", note="probes")
    sa.add_whitelist("asn", "AS64511", note="partner")
    return tmp


def test_whitelisted_values_never_reach_either_feed(feed_db):
    ips = {e["ip"] for e in intel_publish._feed_entries()}
    assert ips == {"198.51.100.7"}
    assert "203.0.113.10" not in intel_publish.plain_text_feed()


def test_plain_text_is_one_unique_address_per_line(feed_db):
    lines = intel_publish.plain_text_feed().splitlines()
    data = [ln for ln in lines if ln and not ln.startswith("#")]
    assert data == ["198.51.100.7"]
    assert all(ln.startswith("#") for ln in lines[:4])


def test_plain_text_does_not_advance_signed_sequence(feed_db):
    before = db.get_setting("intel.publish.seq")
    intel_publish.plain_text_feed()
    assert db.get_setting("intel.publish.seq") == before


def _add(ip, origin, i):
    now = datetime.now(timezone.utc)
    conn = db.get_conn()
    conn.execute(
        "INSERT INTO decisions (origin_source, lapi_id, value, scope, type, scenario, origin,"
        " duration, until, first_seen_at, last_seen_at, deleted_at)"
        " VALUES ('local', ?, ?, 'Ip', 'ban', ?, ?, '4h', ?, ?, ?, NULL)",
        (1000 + i, ip, f"x/{i}", origin, (now + timedelta(hours=4)).isoformat(),
         now.isoformat(), now.isoformat()))
    conn.close()


def test_third_party_origins_are_never_published(feed_db):
    for i, origin in enumerate(["lists", "CAPI", "cscli-import", "lists:firehol"]):
        _add(f"198.51.100.{100 + i}", origin, i)
    _add("198.51.100.200", "cscli", 9)
    # An operator clearing the default exclude must not let them through.
    db.set_setting("intel.publish.exclude_origins", "nothing-matches")
    ips = {e["ip"] for e in intel_publish._feed_entries()}
    assert ips == {"198.51.100.7", "198.51.100.200", "198.51.100.103"}  # lists:firehol only via the pattern
    db.set_setting("intel.publish.exclude_origins", "lists:")
    ips = {e["ip"] for e in intel_publish._feed_entries()}
    assert ips == {"198.51.100.7", "198.51.100.200"}


def test_lists_colon_pattern_matches_bare_lists_origin():
    assert intel_publish._excluded("lists", ["lists:"])
    assert intel_publish._excluded("lists:firehol", ["lists:"])
    assert not intel_publish._excluded("crowdsec", ["lists:"])


def test_imports_cannot_crowd_out_local_bans(feed_db, monkeypatch):
    for i in range(30):
        _add(f"203.0.113.{100 + i}", "cscli-import", 50 + i)
    real = intel_publish.get_conn

    class Limited:
        def __init__(self):
            self.c = real()
        def execute(self, sql, params=()):
            return self.c.execute(sql.replace("LIMIT 10000", "LIMIT 5"), params)
        def close(self):
            self.c.close()

    monkeypatch.setattr(intel_publish, "get_conn", Limited)
    assert {e["ip"] for e in intel_publish._feed_entries()} == {"198.51.100.7"}
