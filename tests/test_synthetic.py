"""Arc 11 phase 66 — synthetic ban end-to-end self-test.

Exercises three paths that production can't easily reach when all bouncers
are in dry-run mode:

  1. **Happy path** — bouncer reports success + IP appears in its snapshot
     after the inject reconcile, then disappears after the remove reconcile.
     Status → 'ok', no notification fired.

  2. **Phantom-progress failure** — bouncer's apply() looks fine but the IP
     never lands in its snapshot (the silent-success failure mode this whole
     phase exists to catch). Status → 'failed', notification fired.

  3. **Skipped** — no live bouncers (all dry-run / disabled). Test records
     the skip and updates settings, but does NOT fire a notification (skips
     are not failures).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest


def _setup_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Point Protek's db.DB_PATH at a temp file and create the bare schema
    the synthetic test relies on."""
    import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()


class _StubBouncer:
    """Records inject/remove via the snapshot it returns. Pass `lying=True`
    to simulate phantom-progress (apply succeeds but snapshot never shows
    the IP — the failure mode this phase catches)."""

    def __init__(self, name: str = "stub", lying: bool = False,
                 kind: str = "stub"):
        self.name = name
        self.kind = kind
        self._lying = lying
        self._addresses: set[str] = set()
        self.apply_calls = 0

    def is_configured(self) -> bool:
        return True

    def apply(self, to_add, to_remove_ids):
        # Matches the real Bouncer protocol:
        #   to_add: list[tuple[address, comment]]
        #   to_remove_ids: list[str]  (address-list .id values)
        self.apply_calls += 1
        if not self._lying:
            for addr, _comment in to_add or []:
                self._addresses.add(addr)
            for rid in to_remove_ids or []:
                self._addresses.discard(rid)
        return {"applied_add": len(to_add or []),
                "applied_remove": len(to_remove_ids or []),
                "errors": 0, "push_log": []}

    def snapshot(self):
        # Use the address itself as the .id so the synthetic test can remove
        # by passing it back through apply()'s remove list.
        return [{"address": a, ".id": a} for a in self._addresses]


def _patch_run(monkeypatch: pytest.MonkeyPatch, stubs: list[_StubBouncer],
               recorded_notifications: list[dict]):
    """Wire up `synthetic.run_test()` so it sees `stubs` as the live
    bouncer set. The synthetic test now calls each bouncer's apply()
    directly, so we no longer need a fake reconciler."""
    import synthetic
    monkeypatch.setattr(synthetic, "_live_bouncers", lambda: list(stubs))

    import sys
    fake_notifications = type(sys)("notifications")
    fake_notifications.send = (
        lambda channel, message, subject="":
            recorded_notifications.append(
                {"channel": channel, "message": message, "subject": subject}
            )
    )
    monkeypatch.setitem(sys.modules, "notifications", fake_notifications)

    fake_siem = type(sys)("siem")
    fake_siem.ship = lambda *a, **k: None
    monkeypatch.setitem(sys.modules, "siem", fake_siem)


# ── 1. Happy path ───────────────────────────────────────────────────────────

def test_happy_path_status_ok(monkeypatch: pytest.MonkeyPatch,
                              tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    bouncer = _StubBouncer(name="happy-stub", lying=False)
    _patch_run(monkeypatch, [bouncer], notes)

    import synthetic
    result = synthetic.run_test()

    assert result["status"] == "ok"
    assert result["targets_n"] == 1
    assert result["ok_n"] == 1
    # Two direct pushes (add then remove) → two apply() calls
    assert bouncer.apply_calls == 2
    # No notification fired on success
    assert notes == []


# ── 2. Phantom-progress failure ─────────────────────────────────────────────

def test_phantom_progress_fires_alarm(monkeypatch: pytest.MonkeyPatch,
                                      tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    # `lying=True` means apply() looks successful but the IP never appears
    # in the bouncer's snapshot. This is *exactly* the phantom-progress
    # failure mode phase 66 exists to detect.
    liar = _StubBouncer(name="lying-stub", lying=True)
    _patch_run(monkeypatch, [liar], notes)

    import synthetic
    result = synthetic.run_test()

    assert result["status"] == "failed"
    assert result["targets_n"] == 1
    assert result["ok_n"] == 0
    assert result["results"]["lying-stub"]["add_ok"] is False
    # Notification must fire on failure — this is the acceptance gate.
    assert len(notes) == 1
    assert notes[0]["channel"] == "sync_error"
    assert "lying-stub" in notes[0]["message"]


# ── 3. Skipped — no live bouncers ───────────────────────────────────────────

def test_skipped_when_no_live_bouncers(monkeypatch: pytest.MonkeyPatch,
                                       tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    _patch_run(monkeypatch, [], notes)

    import synthetic
    result = synthetic.run_test()

    assert result["status"] == "skipped"
    assert result["reason"] == "no live bouncers"
    # Skips are not failures — never notify the operator about them
    assert notes == []
    # Settings should still be updated so the dashboard shows the skip
    from db import get_setting
    assert get_setting("synthetic.last_status") == "skipped"
    assert get_setting("synthetic.last_at") is not None


# ── 4. Mixed: one good + one lying = 'partial' ──────────────────────────────

def test_partial_when_one_of_two_lies(monkeypatch: pytest.MonkeyPatch,
                                      tmp_path: Path):
    _setup_db(monkeypatch, tmp_path)
    notes: list[dict] = []
    good = _StubBouncer(name="good", lying=False)
    bad = _StubBouncer(name="bad", lying=True)
    _patch_run(monkeypatch, [good, bad], notes)

    import synthetic
    result = synthetic.run_test()

    assert result["status"] == "partial"
    assert result["targets_n"] == 2
    assert result["ok_n"] == 1
    assert len(notes) == 1
    assert "bad" in notes[0]["message"]
