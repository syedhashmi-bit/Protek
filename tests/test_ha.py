"""Arc 11 phase 65 — active-passive HA tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


def _setup_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def _clear_role_env(monkeypatch):
    monkeypatch.delenv("HA_ROLE", raising=False)


# ── role resolution ───────────────────────────────────────────────────────


def test_role_defaults_to_primary(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    _clear_role_env(monkeypatch)
    import ha
    assert ha.role() == "primary"
    assert ha.is_primary() is True
    assert ha.is_standby() is False


def test_role_from_env_standby(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    monkeypatch.setenv("HA_ROLE", "standby")
    import ha
    assert ha.role() == "standby"
    assert ha.is_standby() is True


def test_db_setting_overrides_env(monkeypatch, tmp_path):
    """Operator promote (via /admin/ha) writes ha.role to settings.
    That overrides the env boot default."""
    _setup_db(monkeypatch, tmp_path)
    monkeypatch.setenv("HA_ROLE", "standby")
    from db import set_setting
    set_setting("ha.role", "primary")
    import ha
    assert ha.role() == "primary"


def test_invalid_db_value_falls_through_to_env(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    monkeypatch.setenv("HA_ROLE", "primary")
    from db import set_setting
    set_setting("ha.role", "garbage")  # not in VALID_ROLES
    import ha
    assert ha.role() == "primary"  # falls back to env


def test_invalid_env_falls_through_to_default(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    monkeypatch.setenv("HA_ROLE", "leader")  # bad value
    import ha
    assert ha.role() == "primary"  # implicit default


# ── promote / demote ──────────────────────────────────────────────────────


def test_promote_sets_role_and_audits(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    monkeypatch.setenv("HA_ROLE", "standby")
    import ha
    assert ha.role() == "standby"
    result = ha.promote(actor="alice", reason="primary outage")
    assert result["old_role"] == "standby"
    assert result["new_role"] == "primary"
    assert ha.role() == "primary"
    # Audit row written
    from db import get_conn
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT action, actor FROM audit_log WHERE action = 'ha.promote'"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0]["actor"] == "alice"


def test_demote_sets_role_and_audits(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    _clear_role_env(monkeypatch)  # default primary
    import ha
    assert ha.role() == "primary"
    result = ha.demote(actor="bob", reason="cutover")
    assert result["old_role"] == "primary"
    assert result["new_role"] == "standby"
    assert ha.role() == "standby"


def test_promote_then_demote_round_trip(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    monkeypatch.setenv("HA_ROLE", "standby")
    import ha
    ha.promote(actor="op", reason="failover")
    assert ha.role() == "primary"
    ha.demote(actor="op", reason="failback")
    assert ha.role() == "standby"
    # Both audit rows present
    from db import get_conn
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT action FROM audit_log WHERE action LIKE 'ha.%' "
            "ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    assert [r["action"] for r in rows] == ["ha.promote", "ha.demote"]


# ── heartbeat freshness ───────────────────────────────────────────────────


def test_heartbeat_lag_none_when_unset(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    import ha
    assert ha.heartbeat_lag_seconds() is None
    assert ha.is_heartbeat_stale() is False  # can't compare to None


def test_heartbeat_lag_computed_from_poller_last_at(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    from db import set_setting
    ten_sec_ago = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    set_setting("poller.last_at", ten_sec_ago)
    import ha
    lag = ha.heartbeat_lag_seconds()
    assert lag is not None
    assert 9 <= lag <= 12  # allow some clock slop


def test_heartbeat_stale_triggers_at_threshold(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    from db import set_setting
    set_setting("ha.heartbeat_stale_sec", "30")
    old = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    set_setting("poller.last_at", old)
    import ha
    assert ha.is_heartbeat_stale() is True


def test_heartbeat_threshold_floor(monkeypatch, tmp_path):
    """Setting threshold below the 15s floor is rejected (the floor
    protects against flap-alerting on a single delayed cycle)."""
    _setup_db(monkeypatch, tmp_path)
    from db import set_setting
    set_setting("ha.heartbeat_stale_sec", "5")
    import ha
    assert ha.heartbeat_stale_threshold_sec() == 15  # floor


# ── summary dict shape ────────────────────────────────────────────────────


def test_summary_includes_all_keys(monkeypatch, tmp_path):
    _setup_db(monkeypatch, tmp_path)
    _clear_role_env(monkeypatch)
    import ha
    s = ha.summary()
    expected_keys = {
        "role", "is_primary", "is_standby", "env_role", "db_override",
        "last_heartbeat_at", "heartbeat_lag_seconds",
        "heartbeat_stale_threshold", "heartbeat_stale",
        "last_role_change_at", "last_role_change_actor",
        "last_role_change_reason", "auto_failover_enabled",
    }
    assert expected_keys.issubset(s.keys())
    assert s["role"] == "primary"
    assert s["is_primary"] is True
    assert s["auto_failover_enabled"] is False  # explicit OFF by default
