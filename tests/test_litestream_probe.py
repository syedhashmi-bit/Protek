"""Arc 15.5 phase 99 — Litestream destination probe tests.

Mocks subprocess.run + the Litestream YAML config so the probe runs
end-to-end without touching a real SFTP destination.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


# ── Fixtures ───────────────────────────────────────────────────────────────


def _setup_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


def _yml(tmp_path: Path,
         url: str = "sftp://litestream@<vps-b-wg-ip>:22/home/litestream/protek",
         key: str = "/etc/litestream/id_ed25519") -> Path:
    p = tmp_path / "litestream.yml"
    p.write_text(
        "dbs:\n"
        "  - path: /var/www/Protek/protek.db\n"
        "    replica:\n"
        f"      url: {url}\n"
        f"      key-path: {key}\n"
        "      retention: 720h\n"
    )
    return p


@pytest.fixture(autouse=True)
def _notifications_capture(monkeypatch: pytest.MonkeyPatch):
    """Replace notifications + siem with capture stubs across every test
    in this module. Returns the captured list so each test can assert."""
    import sys
    import types as _types
    captured: list[dict] = []
    fake = _types.ModuleType("notifications")
    fake.send = lambda channel, message, subject="": captured.append(
        {"channel": channel, "message": message, "subject": subject}
    )
    monkeypatch.setitem(sys.modules, "notifications", fake)
    fake_siem = _types.ModuleType("siem")
    fake_siem.ship = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "siem", fake_siem)
    return captured


# ── Config parsing ────────────────────────────────────────────────────────


def test_parse_yml_returns_none_when_missing(monkeypatch, tmp_path):
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", tmp_path / "missing.yml")
    assert litestream._parse_litestream_yml() is None


def test_parse_yml_extracts_sftp_destination(monkeypatch, tmp_path):
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))
    cfg = litestream._parse_litestream_yml()
    assert cfg["host"] == "<vps-b-wg-ip>"
    assert cfg["port"] == 22
    assert cfg["user"] == "litestream"
    assert cfg["path"] == "/home/litestream/protek"
    assert cfg["key_path"] == "/etc/litestream/id_ed25519"


def test_parse_yml_handles_default_port(monkeypatch, tmp_path):
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG",
                         _yml(tmp_path, url="sftp://ls@host/path"))
    cfg = litestream._parse_litestream_yml()
    assert cfg["port"] == 22


def test_parse_yml_returns_none_for_s3_replica(monkeypatch, tmp_path):
    import litestream
    p = tmp_path / "litestream.yml"
    p.write_text("dbs:\n  - path: /db\n    replica:\n      url: s3://bucket/key\n")
    monkeypatch.setattr(litestream, "LIVE_CONFIG", p)
    assert litestream._parse_litestream_yml() is None


# ── df parsing ────────────────────────────────────────────────────────────


def test_parse_df_extracts_used_pct():
    import litestream
    df_output = (
        "    Size     Used    Avail   (root)    %Capacity\n"
        "    38G       12G      24G      26G       34%\n"
    )
    parsed = litestream._parse_df_output(df_output)
    assert parsed["used_pct"] == 34.0


def test_parse_df_handles_high_usage():
    import litestream
    parsed = litestream._parse_df_output(
        "Size     Used    Avail   (root)    %Capacity\n"
        "38G      36G      0G       2G        100%\n"
    )
    assert parsed["used_pct"] == 100.0


def test_parse_df_returns_none_for_garbage():
    import litestream
    assert litestream._parse_df_output("totally unrelated output\n") is None


# ── Error categorisation ─────────────────────────────────────────────────


def test_categorize_space_errors():
    import litestream
    cat = litestream._categorize_probe_error
    assert cat("No space left on device", 1) == "space"
    assert cat("Disk quota exceeded", 1) == "space"


def test_categorize_network_errors():
    import litestream
    cat = litestream._categorize_probe_error
    assert cat("ssh: connect to host: Connection refused", 255) == "network"
    assert cat("Connection timed out", 255) == "network"
    assert cat("Host key verification failed", 255) == "network"
    assert cat("", 255) == "network"  # empty stderr on connect failure


def test_categorize_permission():
    import litestream
    cat = litestream._categorize_probe_error
    assert cat("Permission denied (sftp)", 1) == "permission"


def test_categorize_other_falls_through():
    import litestream
    cat = litestream._categorize_probe_error
    assert cat("some random sftp error", 1) == "other"


# ── End-to-end probe ─────────────────────────────────────────────────────


def _patch_sftp(monkeypatch, returncode=0, stdout="", stderr=""):
    """Replace subprocess.run with a stub that returns the given shape."""
    class _R:
        def __init__(self):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())


def test_probe_healthy_destination(monkeypatch, tmp_path,
                                    _notifications_capture):
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))
    _patch_sftp(monkeypatch,
                 stdout=("Size  Used  Avail  (root) %Capacity\n"
                          "38G    12G   24G    26G      34%\n"))
    out = litestream.probe_replica_destination()
    assert out["configured"] is True
    assert out["ok"] is True
    assert out["used_pct"] == 34.0
    assert out["fired"] == []
    assert _notifications_capture == []


def test_probe_warn_threshold_fires_once(monkeypatch, tmp_path,
                                          _notifications_capture):
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))
    _patch_sftp(monkeypatch,
                 stdout=("Size  Used  Avail  (root) %Capacity\n"
                          "38G    27G    9G    11G      75%\n"))

    first = litestream.probe_replica_destination()
    assert first["used_pct"] == 75.0
    assert "space_warn" in first["fired"]
    assert len(_notifications_capture) == 1
    assert "destination" in _notifications_capture[0]["subject"].lower()

    # Second call in the same hour — rate-limited
    second = litestream.probe_replica_destination()
    assert second["fired"] == []
    assert len(_notifications_capture) == 1


def test_probe_critical_threshold(monkeypatch, tmp_path,
                                   _notifications_capture):
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))
    _patch_sftp(monkeypatch,
                 stdout=("Size  Used  Avail  (root) %Capacity\n"
                          "38G    36G    0G     2G      95%\n"))
    out = litestream.probe_replica_destination()
    assert out["used_pct"] == 95.0
    assert "space_critical" in out["fired"]
    assert len(_notifications_capture) == 1
    assert "critical" in _notifications_capture[0]["subject"].lower()


def test_probe_recovery_clears_alert(monkeypatch, tmp_path,
                                     _notifications_capture):
    """Drop below the warn threshold AFTER having alerted — recovery
    fires exactly once and clears the rate-limit key so future re-warns
    can fire again."""
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))

    # 1. Breach
    _patch_sftp(monkeypatch,
                 stdout=("Size  Used  Avail  (root) %Capacity\n"
                          "38G    27G    9G    11G      75%\n"))
    litestream.probe_replica_destination()
    assert len(_notifications_capture) == 1

    # 2. Drop below threshold — recovery
    _patch_sftp(monkeypatch,
                 stdout=("Size  Used  Avail  (root) %Capacity\n"
                          "38G    12G   24G    26G      34%\n"))
    out = litestream.probe_replica_destination()
    assert out["ok"] is True
    assert "space_recovery" in out["fired"]
    assert len(_notifications_capture) == 2
    assert "recovered" in _notifications_capture[1]["subject"].lower()


def test_probe_disabled_by_setting(monkeypatch, tmp_path,
                                    _notifications_capture):
    _setup_db(monkeypatch, tmp_path)
    import litestream
    from db import set_setting
    set_setting("litestream.probe_enabled", "0")
    out = litestream.probe_replica_destination()
    assert out["enabled"] is False
    assert _notifications_capture == []


def test_probe_no_config_returns_unconfigured(monkeypatch, tmp_path,
                                                _notifications_capture):
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", tmp_path / "missing.yml")
    out = litestream.probe_replica_destination()
    assert out["configured"] is False
    assert _notifications_capture == []


def test_probe_network_failure_fires_network_category(monkeypatch, tmp_path,
                                                       _notifications_capture):
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))
    _patch_sftp(monkeypatch, returncode=255,
                 stderr="ssh: connect to host <vps-b-wg-ip>: Connection refused")
    out = litestream.probe_replica_destination()
    assert out["ok"] is False
    assert out["category"] == "network"
    assert "network_warn" in out["fired"]
    assert len(_notifications_capture) == 1


def test_probe_space_failure_via_write(monkeypatch, tmp_path,
                                        _notifications_capture):
    """df succeeded but the write/read/delete round-trip got 'No space
    left on device' — proves the probe catches space pressure even when
    df hasn't tipped to 100% yet (filesystem reserved blocks, quotas)."""
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))

    call_count = {"n": 0}
    def _run(*a, **kw):
        call_count["n"] += 1
        class _R:
            pass
        r = _R()
        if call_count["n"] == 1:  # df call
            r.returncode = 0
            r.stdout = ("Size  Used  Avail  (root) %Capacity\n"
                        "38G    34G    2G     4G      89%\n")
            r.stderr = ""
        else:  # write/read/delete
            r.returncode = 1
            r.stdout = ""
            r.stderr = "Couldn't upload file: No space left on device"
        return r
    monkeypatch.setattr(subprocess, "run", _run)

    out = litestream.probe_replica_destination()
    assert out["ok"] is False
    assert out["category"] == "space"
    assert "space_warn" in out["fired"]


# ── Rate-limit + per-category isolation ──────────────────────────────────


def test_probe_per_category_rate_limits_are_independent(
        monkeypatch, tmp_path, _notifications_capture):
    """A network failure followed (in the same hour) by a space failure
    should produce TWO notifications — they're independent categories."""
    _setup_db(monkeypatch, tmp_path)
    import litestream
    monkeypatch.setattr(litestream, "LIVE_CONFIG", _yml(tmp_path))

    # First: network failure
    _patch_sftp(monkeypatch, returncode=255,
                 stderr="Connection timed out")
    litestream.probe_replica_destination()
    assert len(_notifications_capture) == 1

    # Then: space pressure (different category)
    _patch_sftp(monkeypatch,
                 stdout=("Size  Used  Avail  (root) %Capacity\n"
                          "38G    35G    1G     3G      92%\n"))
    litestream.probe_replica_destination()
    assert len(_notifications_capture) == 2
