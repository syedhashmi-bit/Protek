"""hygiene.py — alerts on stale backups and disabled retention."""
from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    sent: list[tuple[str, str]] = []
    fake = types.ModuleType("notifications")
    fake.send = lambda event, message, subject=None, **kw: sent.append((subject, message))
    monkeypatch.setitem(sys.modules, "notifications", fake)
    db.set_setting("retention.enabled", "1")
    db.set_setting("backup.last_daily_at", (NOW - timedelta(hours=2)).isoformat())
    import hygiene
    return db, hygiene, sent


def test_all_healthy_is_silent(env):
    db, hygiene, sent = env
    assert hygiene.check_and_alert(NOW) == {}
    assert sent == []


def test_stale_backup_alerts_once_then_renags_daily(env):
    db, hygiene, sent = env
    db.set_setting("backup.last_daily_at", (NOW - timedelta(days=3)).isoformat())
    assert "backup_stale" in hygiene.check_and_alert(NOW)
    assert len(sent) == 1 and "3.0 days" in sent[0][1]
    hygiene.check_and_alert(NOW + timedelta(hours=1))  # hourly tick: no repeat
    assert len(sent) == 1
    hygiene.check_and_alert(NOW + timedelta(hours=24))  # daily re-nag
    assert len(sent) == 2


def test_recovery_sends_one_message_and_rearms(env):
    db, hygiene, sent = env
    db.set_setting("backup.last_daily_at", (NOW - timedelta(days=3)).isoformat())
    hygiene.check_and_alert(NOW)
    db.set_setting("backup.last_daily_at", NOW.isoformat())
    hygiene.check_and_alert(NOW + timedelta(hours=1))
    assert len(sent) == 2 and "recovered" in sent[1][0]
    hygiene.check_and_alert(NOW + timedelta(hours=2))
    assert len(sent) == 2
    # A fresh outage alerts immediately, not after the re-nag window.
    db.set_setting("backup.last_daily_at", (NOW - timedelta(days=2)).isoformat())
    hygiene.check_and_alert(NOW + timedelta(hours=3))
    assert len(sent) == 3


def test_retention_disabled_and_failed_restore_test(env):
    db, hygiene, sent = env
    db.set_setting("retention.enabled", "0")
    db.set_setting("backup.last_test_ok", "0")
    found = hygiene.check_and_alert(NOW)
    assert set(found) == {"retention_disabled", "backup_unverified"}
    assert len(sent) == 2


def test_never_backed_up_install_is_not_nagged(env):
    db, hygiene, sent = env
    db.set_setting("backup.last_daily_at", "")
    assert hygiene.check_and_alert(NOW) == {}


def test_warnings_lists_current_findings(env):
    db, hygiene, sent = env
    db.set_setting("retention.enabled", "0")
    assert hygiene.warnings() == ["retention_disabled"]
