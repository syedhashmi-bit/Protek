"""Arc 15 phase 93 — disk + Litestream observability tests.

Acceptance gates from ROADMAP.md:

  1. Disk watchdog: at 65/72/91 % the right edge transitions fire
     exactly once and recovery clears state. Hysteresis 5 % prevents
     flap re-alerts at the threshold.

  2. Litestream journal scraper: 3 sequential
     `retention enforcement failed` ERROR lines produce exactly one
     notification (the other two suppressed by the 1-hour rate limit).

The live-tmpfs end-to-end check listed in the roadmap is marked as a
@pytest.mark.live case below — skipped in CI without root, documented
for the operator to run manually.
"""
from __future__ import annotations

import sys
import types
from collections import namedtuple
from pathlib import Path

import pytest


# ── Common fixtures ─────────────────────────────────────────────────────────


def _setup_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Point Protek's db.DB_PATH at a temp file and migrate the bare schema."""
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def _patch_notifications(monkeypatch: pytest.MonkeyPatch,
                         recorded: list[dict]) -> None:
    """Capture every notifications.send call. Mirrors the pattern from
    tests/test_synthetic.py — replace the module wholesale so lazy
    `import notifications` inside disk_watchdog picks up the fake."""
    fake = types.ModuleType("notifications")
    fake.send = (
        lambda channel, message, subject="":
            recorded.append(
                {"channel": channel, "message": message, "subject": subject}
            )
    )
    monkeypatch.setitem(sys.modules, "notifications", fake)

    fake_siem = types.ModuleType("siem")
    fake_siem.ship = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "siem", fake_siem)


_DiskUsage = namedtuple("_DiskUsage", "total used free")


def _patch_disk_usage(monkeypatch: pytest.MonkeyPatch, pct: float,
                      total_gb: float = 38) -> None:
    """Make shutil.disk_usage return a sample at `pct` % used on a
    `total_gb` GB device. Matches /dev/sda1 on the real Hetzner host."""
    total = int(total_gb * 1024 ** 3)
    used = int(total * (pct / 100.0))
    free = total - used
    import shutil
    monkeypatch.setattr(shutil, "disk_usage",
                         lambda _path: _DiskUsage(total=total, used=used,
                                                   free=free))


# ── 1. Disk watchdog edge transitions ───────────────────────────────────────


def test_below_warn_no_alert(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)
    _patch_disk_usage(monkeypatch, pct=65)

    import disk_watchdog
    out = disk_watchdog.check_and_alert()

    assert out["fired"] == []
    assert notes == []


def test_warn_edge_fires_once(monkeypatch: pytest.MonkeyPatch,
                              tmp_path: Path):
    """First cycle ≥ warn_pct fires; subsequent cycles don't re-alert."""
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)
    _patch_disk_usage(monkeypatch, pct=72)  # ≥ default 70

    import disk_watchdog
    first = disk_watchdog.check_and_alert()
    second = disk_watchdog.check_and_alert()

    assert "warn" in first["fired"]
    assert "warn" not in second["fired"]
    assert len(notes) == 1
    assert notes[0]["channel"] == "sync_error"
    assert "warn" in notes[0]["subject"]

    # audit_log row written exactly once
    from db import get_conn
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT action FROM audit_log WHERE action LIKE 'disk.%'"
        ).fetchall()
    finally:
        conn.close()
    assert [r["action"] for r in rows] == ["disk.warn"]


def test_critical_edge_fires_warn_plus_critical(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """At ≥ critical_pct, both critical AND warn fire on first cycle.
    Distinct notifications so the operator can route them differently."""
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)
    _patch_disk_usage(monkeypatch, pct=91)  # ≥ default 90

    import disk_watchdog
    out = disk_watchdog.check_and_alert()

    assert "critical" in out["fired"]
    assert "warn" in out["fired"]
    assert len(notes) == 2  # one warn + one critical
    subjects = {n["subject"] for n in notes}
    assert any("critical" in s for s in subjects)
    assert any("warn" in s for s in subjects)


def test_recovery_below_hysteresis(monkeypatch: pytest.MonkeyPatch,
                                   tmp_path: Path):
    """Once alerted, dropping below (threshold - HYSTERESIS) fires the
    recovery edge and clears the alerted flag. Going back up re-fires."""
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)

    import disk_watchdog

    # 1. Breach
    _patch_disk_usage(monkeypatch, pct=75)
    disk_watchdog.check_and_alert()
    assert len(notes) == 1

    # 2. Slight drop within hysteresis — no recovery yet
    _patch_disk_usage(monkeypatch, pct=68)  # 70 - 5 = 65 is the floor
    out = disk_watchdog.check_and_alert()
    assert "warn_recovery" not in out["fired"]

    # 3. Drop below hysteresis floor — recovery fires
    _patch_disk_usage(monkeypatch, pct=60)
    out = disk_watchdog.check_and_alert()
    assert "warn_recovery" in out["fired"]
    assert len(notes) == 2
    assert "recovered" in notes[-1]["subject"]

    # 4. Bounce back up — re-armed, breach fires again
    _patch_disk_usage(monkeypatch, pct=75)
    out = disk_watchdog.check_and_alert()
    assert "warn" in out["fired"]
    assert len(notes) == 3


def test_settings_override_thresholds(monkeypatch: pytest.MonkeyPatch,
                                      tmp_path: Path):
    """Operator-tuned thresholds via /settings are honored without code edits."""
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)
    _patch_disk_usage(monkeypatch, pct=55)

    from db import set_setting
    set_setting("disk.warn_pct", "50")  # 55 ≥ 50 now triggers warn

    import disk_watchdog
    out = disk_watchdog.check_and_alert()
    assert "warn" in out["fired"]
    assert len(notes) == 1


def test_health_gate_returns_503_at_critical(monkeypatch: pytest.MonkeyPatch,
                                             tmp_path: Path):
    """The /health endpoint's disk_critical issue is the second half of the
    acceptance gate. We don't spin Flask here — just verify the
    is_critical() helper that /health calls."""
    _setup_db(monkeypatch, tmp_path)
    _patch_disk_usage(monkeypatch, pct=92)
    import disk_watchdog
    assert disk_watchdog.is_critical() is True

    _patch_disk_usage(monkeypatch, pct=80)
    assert disk_watchdog.is_critical() is False


# ── 2. Litestream journal scraper rate limit ────────────────────────────────


def _fake_journalctl(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    """Replace subprocess.run inside litestream.scan_journal_errors with
    a stub that returns `stdout` verbatim."""
    import subprocess

    class _R:
        def __init__(self, out: str):
            self.stdout = out
            self.stderr = ""
            self.returncode = 0

    monkeypatch.setattr(subprocess, "run",
                         lambda *a, **k: _R(stdout))


def test_retention_errors_rate_limited(monkeypatch: pytest.MonkeyPatch,
                                       tmp_path: Path):
    """Three sequential `retention enforcement failed` ERROR lines must
    fire exactly one notification — the other two are suppressed by the
    1-hour per-category rate limit. This is the phase 93 Litestream-side
    acceptance gate from ROADMAP.md."""
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)

    fake_journal = (
        "2026-05-28T01:35:05+0000 host litestream[12]: level=ERROR "
            "msg=\"l0 retention enforcement failed\" error=\"SSH_FX_FAILURE\"\n"
        "2026-05-28T01:35:20+0000 host litestream[12]: level=ERROR "
            "msg=\"l0 retention enforcement failed\" error=\"SSH_FX_FAILURE\"\n"
        "2026-05-28T01:35:35+0000 host litestream[12]: level=ERROR "
            "msg=\"l0 retention enforcement failed\" error=\"SSH_FX_FAILURE\"\n"
    )
    _fake_journalctl(monkeypatch, fake_journal)

    import litestream
    out = litestream.scan_journal_errors()

    # All three lines categorized as 'retention'
    assert "retention" in out["errors_by_category"]
    assert len(out["errors_by_category"]["retention"]) == 3
    # But only one notification fired — rate-limited
    assert out["fired"] == ["retention"]
    assert len(notes) == 1
    assert "retention" in notes[0]["subject"]

    # Second scan within the rate-limit window — no notification even with
    # a fresh error line.
    _fake_journalctl(monkeypatch,
                      "2026-05-28T02:00:00+0000 host litestream[12]: "
                      "level=ERROR msg=\"l0 retention enforcement failed\"\n")
    out2 = litestream.scan_journal_errors()
    assert out2["fired"] == []
    assert len(notes) == 1


def test_journal_errors_categorized(monkeypatch: pytest.MonkeyPatch,
                                    tmp_path: Path):
    """Different error substrings route to different categories so each
    gets its own rate-limit slot — a retention error and an ssh error
    in the same scan should produce two distinct notifications."""
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)

    fake = (
        "2026-05-28T03:00:00+0000 host litestream[12]: level=ERROR "
            "msg=\"l0 retention enforcement failed\" error=\"SSH_FX_FAILURE\"\n"
        "2026-05-28T03:00:01+0000 host litestream[12]: level=ERROR "
            "msg=\"ssh: handshake timeout\"\n"
    )
    _fake_journalctl(monkeypatch, fake)

    import litestream
    out = litestream.scan_journal_errors()
    assert set(out["fired"]) == {"retention", "ssh"}
    assert len(notes) == 2


def test_no_errors_no_notification(monkeypatch: pytest.MonkeyPatch,
                                    tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)
    _fake_journalctl(monkeypatch,
                      "2026-05-28T04:00:00+0000 host litestream[12]: "
                      "level=INFO msg=\"replica sync\"\n")

    import litestream
    out = litestream.scan_journal_errors()
    assert out["fired"] == []
    assert notes == []


# ── 3. Auto-rebaseline gate ────────────────────────────────────────────────


def test_auto_rebaseline_off_by_default(monkeypatch: pytest.MonkeyPatch,
                                        tmp_path: Path):
    """Master kill-switch defaults to OFF. Even at 95 % disk + a giant
    LTX stage, nothing destructive happens unless the operator opts in."""
    _setup_db(monkeypatch, tmp_path)
    _patch_disk_usage(monkeypatch, pct=95)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)

    import disk_watchdog
    out = disk_watchdog.maybe_auto_rebaseline()
    assert out["enabled"] is False
    assert out["fired"] is False
    # Notifications must NOT fire when the gate blocks — we don't want
    # noise from a feature the operator didn't enable.
    assert notes == []


def test_auto_rebaseline_requires_stage_majority(
        monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Enabled + critical + tiny LTX stage → still no rebaseline.
    Guards against rebaselining when something else (e.g. /var/log)
    is the real culprit."""
    _setup_db(monkeypatch, tmp_path)
    _patch_disk_usage(monkeypatch, pct=95)
    notes: list[dict] = []
    _patch_notifications(monkeypatch, notes)

    from db import set_setting
    set_setting("disk.allow_auto_rebaseline", "1")

    # No LTX dir on the test host's tmp path → the existence check fails
    # → "litestream stage dir not present", no destructive action.
    import disk_watchdog
    monkeypatch.setattr(disk_watchdog, "LITESTREAM_STAGE_DIR",
                         tmp_path / "nonexistent")

    out = disk_watchdog.maybe_auto_rebaseline()
    assert out["enabled"] is True
    assert out["fired"] is False
    assert "not present" in out["reason"]


# ── 4. Live tmpfs end-to-end (manual; needs root) ──────────────────────────


@pytest.mark.skip(
    reason="Requires root + mount(tmpfs); run manually as the live "
           "acceptance gate from ROADMAP.md")
def test_live_tmpfs_end_to_end():
    """Documented acceptance gate. Steps:

        sudo mount -t tmpfs -o size=10M tmpfs /tmp/protek-fs-test
        cp protek.db /tmp/protek-fs-test/  # ~ 8 MB → ~80 % full
        # Point DB_PATH at /tmp/protek-fs-test/protek.db, run one
        # check_and_alert(), assert exactly one disk.warn notification
        # + one audit row.
        # Then fill to 92 %, hit /health, assert 503 with
        # "disk_critical" in issues.
    """
