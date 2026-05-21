"""
synthetic.py — Arc 11 phase 66. Synthetic ban end-to-end self-test.

Every 6 hours we inject a synthetic decision for an IP in TEST-NET-1
(192.0.2.250 — reserved by RFC 5737 for documentation, will never appear
in legitimate traffic), drive a reconcile cycle, and verify the IP is
present in each live bouncer's snapshot. We then remove the synthetic
decision and verify it disappears. The whole loop catches what passive
health checks miss:

  - "Phantom progress": bouncer's apply() returns success but the entry
    never actually landed (silent rule drop, API quirk, race condition).
  - Out-of-band cleanup: someone edited the address-list and our cached
    .id pointers are stale.
  - Reconcile loop quiet failure: the cycle ran, said "0 errors", but
    didn't touch the bouncer we thought it did.

Live = enabled AND not dry-run. Dry-run bouncers are skipped (no point
testing a no-op path). If every bouncer is dry-run or none exist, the
test is a no-op with status='skipped'.

The synthetic decision uses origin_source='synthetic' + a negative lapi_id
(monotonically decreasing) so it never collides with real LAPI ids
(which are positive ints). This way the test row is unambiguous in the
decisions table and easy to clean up if a test crashes mid-run.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from db import get_conn, get_setting, set_setting

log = logging.getLogger("protek.synthetic")

SYNTH_IP = "192.0.2.250"  # TEST-NET-1 (RFC 5737)
SYNTH_ORIGIN = "synthetic"
SYNTH_SCENARIO = "protek/synthetic-self-test"


def _ensure_table() -> None:
    conn = get_conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS synthetic_tests (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at    TEXT NOT NULL,
                completed_at  TEXT DEFAULT NULL,
                ip            TEXT NOT NULL,
                status        TEXT NOT NULL DEFAULT 'running',
                targets_n     INTEGER NOT NULL DEFAULT 0,
                ok_n          INTEGER NOT NULL DEFAULT 0,
                results_json  TEXT NOT NULL DEFAULT '{}',
                duration_ms   INTEGER DEFAULT 0,
                error         TEXT DEFAULT ''
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_synth_started "
                     "ON synthetic_tests (started_at)")
    finally:
        conn.close()


def _next_lapi_id() -> int:
    """Monotonically decreasing negative id for synthetic rows.
    Real LAPI ids are positive; this guarantees no UNIQUE collision."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT MIN(lapi_id) AS mn FROM decisions WHERE origin_source = ?",
            (SYNTH_ORIGIN,),
        ).fetchone()
    finally:
        conn.close()
    mn = row["mn"] if row and row["mn"] is not None else 0
    return min(mn, 0) - 1


def _live_bouncers() -> list[Any]:
    """Enabled AND not dry-run targets."""
    import bouncers as bmod
    import os
    out = []
    for b in bmod.load_all_targets():
        # Legacy MT respects DRY_RUN env var. New targets carry dry_run per row;
        # bouncers.load_all_targets() doesn't pass that flag along — we re-read
        # it here from bouncer_targets.
        if b.kind == "mikrotik_env":
            env_dry = (os.environ.get("DRY_RUN", "true") or "true").strip().lower()
            if env_dry in ("1", "true", "yes"):
                continue
            out.append(b)
            continue
        # DB-driven targets
        try:
            conn = get_conn()
            try:
                row = conn.execute(
                    "SELECT dry_run FROM bouncer_targets WHERE name = ?",
                    (b.name,),
                ).fetchone()
            finally:
                conn.close()
            if row and not int(row["dry_run"] or 0):
                out.append(b)
        except Exception:  # noqa: BLE001
            continue
    return out


def _insert_synth_decision(lapi_id: int) -> int:
    now = datetime.now(timezone.utc)
    until = (now + timedelta(minutes=15)).isoformat()
    conn = get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO decisions
                (origin_source, lapi_id, value, scope, type, scenario, origin,
                 duration, until, first_seen_at, last_seen_at)
            VALUES (?, ?, ?, 'Ip', 'ban', ?, ?, '15m', ?, ?, ?)
            """,
            (SYNTH_ORIGIN, lapi_id, SYNTH_IP, SYNTH_SCENARIO, SYNTH_ORIGIN,
             until, now.isoformat(), now.isoformat()),
        )
        return cur.lastrowid
    finally:
        conn.close()


def _soft_delete_synth(lapi_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE decisions SET deleted_at = ? "
            "WHERE origin_source = ? AND lapi_id = ?",
            (now, SYNTH_ORIGIN, lapi_id),
        )
    finally:
        conn.close()


def _hard_purge_synth(lapi_id: int) -> None:
    """Remove the synth row completely after the test so it doesn't pollute
    the dashboard or the decisions table."""
    conn = get_conn()
    try:
        conn.execute(
            "DELETE FROM decisions WHERE origin_source = ? AND lapi_id = ?",
            (SYNTH_ORIGIN, lapi_id),
        )
    finally:
        conn.close()


def _ip_in_snapshot(b: Any) -> bool:
    try:
        entries = b.snapshot()
    except Exception as e:  # noqa: BLE001
        log.debug("snapshot failed for %s: %s", b.name, e)
        return False
    for e in entries:
        addr = e.get("address") or e.get("value") or e.get("ip") or ""
        # Normalize /32 vs bare-IP
        if addr.split("/")[0] == SYNTH_IP:
            return True
    return False


def _record_start() -> int:
    _ensure_table()
    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO synthetic_tests (started_at, ip, status) "
            "VALUES (?, ?, 'running')",
            (datetime.now(timezone.utc).isoformat(), SYNTH_IP),
        )
        return cur.lastrowid
    finally:
        conn.close()


def _record_finish(tid: int, status: str, *, results: dict[str, Any],
                   duration_ms: int, error: str = "",
                   targets_n: int = 0, ok_n: int = 0) -> None:
    conn = get_conn()
    try:
        conn.execute(
            """
            UPDATE synthetic_tests
               SET completed_at = ?, status = ?, results_json = ?,
                   duration_ms = ?, error = ?, targets_n = ?, ok_n = ?
             WHERE id = ?
            """,
            (datetime.now(timezone.utc).isoformat(), status,
             json.dumps(results)[:8000], int(duration_ms or 0),
             error[:400], int(targets_n), int(ok_n), tid),
        )
    finally:
        conn.close()


def run_test() -> dict[str, Any]:
    """Inject synth decision → reconcile → verify presence → cleanup →
    reconcile → verify absence. Returns the test row dict."""
    import reconciler  # local import to dodge cycles
    tid = _record_start()
    t0 = time.monotonic()
    lapi_id = _next_lapi_id()
    results: dict[str, Any] = {}
    targets_n = ok_n = 0
    error = ""
    status = "skipped"
    try:
        live = _live_bouncers()
        if not live:
            _record_finish(tid, "skipped", results={},
                           duration_ms=int((time.monotonic() - t0) * 1000),
                           error="no live (enabled + non-dry-run) bouncers")
            return {"id": tid, "status": "skipped",
                    "reason": "no live bouncers"}

        # Phase 1: add. Insert decision → reconcile → check each target.
        _insert_synth_decision(lapi_id)
        try:
            reconciler.run_once(source="synthetic", dry_run=False)
        except Exception as e:  # noqa: BLE001
            log.warning("synthetic add reconcile failed: %s", e)
        time.sleep(1.0)  # let TCP/router finish if push was async-ish

        for b in live:
            present = _ip_in_snapshot(b)
            results[b.name] = {"add_ok": present, "kind": b.kind,
                               "remove_ok": False}

        # Phase 2: remove. Soft-delete → reconcile → check absent.
        _soft_delete_synth(lapi_id)
        try:
            reconciler.run_once(source="synthetic-cleanup", dry_run=False)
        except Exception as e:  # noqa: BLE001
            log.warning("synthetic remove reconcile failed: %s", e)
        time.sleep(1.0)

        for b in live:
            absent = not _ip_in_snapshot(b)
            if b.name in results:
                results[b.name]["remove_ok"] = absent

        # Tally
        targets_n = len(live)
        ok_n = sum(1 for r in results.values()
                   if r.get("add_ok") and r.get("remove_ok"))
        if ok_n == targets_n:
            status = "ok"
        elif ok_n == 0:
            status = "failed"
        else:
            status = "partial"
    except Exception as e:  # noqa: BLE001
        error = str(e)
        status = "failed"
        log.exception("synthetic test crashed: %s", e)
    finally:
        # Always clean up the synth row regardless of outcome — no orphans
        # in the decisions table.
        try:
            _hard_purge_synth(lapi_id)
        except Exception as e:  # noqa: BLE001
            log.warning("synthetic purge failed: %s", e)

    duration_ms = int((time.monotonic() - t0) * 1000)
    _record_finish(tid, status, results=results, duration_ms=duration_ms,
                   error=error, targets_n=targets_n, ok_n=ok_n)
    set_setting("synthetic.last_at", datetime.now(timezone.utc).isoformat())
    set_setting("synthetic.last_status", status)

    if status in ("failed", "partial"):
        try:
            import notifications
            bad = [n for n, r in results.items()
                   if not (r.get("add_ok") and r.get("remove_ok"))]
            notifications.send(
                "sync_error",
                f"Synthetic ban test {status}: {ok_n}/{targets_n} bouncers ok. "
                f"Failed: {', '.join(bad) or '(none)'}",
                subject=f"[Protek] Synthetic self-test {status}",
            )
        except Exception:  # noqa: BLE001
            pass
        try:
            import siem
            siem.ship("synthetic.test.failed",
                      {"status": status, "targets_n": targets_n,
                       "ok_n": ok_n, "results": results}, severity=3)
        except Exception:  # noqa: BLE001
            pass
    else:
        try:
            import siem
            siem.ship("synthetic.test.ok",
                      {"targets_n": targets_n, "duration_ms": duration_ms},
                      severity=6)
        except Exception:  # noqa: BLE001
            pass

    return {"id": tid, "status": status, "targets_n": targets_n,
            "ok_n": ok_n, "results": results, "duration_ms": duration_ms,
            "error": error}


def maybe_run_scheduled() -> None:
    """Cheap to call every cycle. Internally no-ops until ≥6h since last."""
    if (get_setting("synthetic.enabled") or "0") != "1":
        return
    last = get_setting("synthetic.last_at")
    if last:
        try:
            d = datetime.fromisoformat(last.replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - d) < timedelta(hours=6):
                return
        except Exception:  # noqa: BLE001
            pass
    run_test()


def list_runs(limit: int = 30) -> list[dict[str, Any]]:
    _ensure_table()
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM synthetic_tests ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["results"] = json.loads(d.get("results_json") or "{}")
            except Exception:  # noqa: BLE001
                d["results"] = {}
            out.append(d)
        return out
    finally:
        conn.close()


def status() -> dict[str, Any]:
    _ensure_table()
    return {
        "enabled": (get_setting("synthetic.enabled") or "0") == "1",
        "ip": SYNTH_IP,
        "last_at": get_setting("synthetic.last_at"),
        "last_status": get_setting("synthetic.last_status") or "",
    }
