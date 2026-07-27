"""retention.py — bound the append-only tables so the DB stops growing forever.

2026-07-26 post-mortem. The root disk filled and took every app on the host
with it. The proximate cause was a 53 GB WAL, but the thing feeding it was
`decisions`: 6.68M rows, of which 6.61M (99%) were soft-deleted tombstones,
across only 184k distinct IPs. `mt_pushes` had 3.25M rows. Neither table had
any retention at all.

**Why a row cap and not a time window.** The obvious fix is "delete tombstones
older than N days". Measured on live data that barely helps: the tombstones
only reached back 34 days, and just 748k of 6.61M were older than 7 days. The
volume is churn (~800k rows/day as CrowdSec re-issues a fresh `lapi_id` for
every re-ban, and `UNIQUE(origin_source, lapi_id)` makes each one a new row),
not history. A time window leaves the table unbounded whenever churn spikes —
which is exactly when the disk is at risk. A row cap bounds it deterministically
no matter what the rate does. It is also already the house pattern here:
siem_journal caps at 10k rows, disk_samples at 1440.

**Deleting is itself a disk risk.** Removing 6M rows in one transaction would
write a multi-gigabyte WAL — the very failure this module exists to prevent.
So the work is batched, each batch is its own autocommit transaction (db.py
uses isolation_level=None), and each run is bounded by a wall-clock budget.
Large backlogs therefore drain over several runs instead of one huge spike.

Note: deleting rows returns pages to SQLite's freelist, which stops the file
growing but does not shrink it. Reclaiming the file size needs a VACUUM, which
needs ~2x the DB size in free space and locks the DB — an explicit operator
decision, deliberately not automated here.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from db import get_conn, get_setting

log = logging.getLogger("protek.retention")

# Keep the newest N rows. decisions: tombstones only — active decisions are
# never touched regardless of count.
DEFAULT_DECISIONS_TOMBSTONE_CAP = 500_000
DEFAULT_MT_PUSHES_CAP = 500_000

DEFAULT_BATCH = 5_000
DEFAULT_MAX_SECONDS = 15


def _setting_int(key: str, default: int) -> int:
    raw = get_setting(key)
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return default


def _cutoff_id(conn, table: str, cap: int, where: str = "1=1") -> int | None:
    """id of the newest row that is still beyond the cap (delete <= this)."""
    row = conn.execute(
        f"SELECT id FROM {table} WHERE {where} ORDER BY id DESC LIMIT 1 OFFSET ?",
        (cap,),
    ).fetchone()
    return row["id"] if row else None


def _drain(conn, sql: str, params: tuple, deadline: float, batch: int) -> int:
    """Run a batched DELETE until nothing is left or the budget expires."""
    removed = 0
    while time.monotonic() < deadline:
        cur = conn.execute(sql, params + (batch,))
        if not cur.rowcount:
            break
        removed += cur.rowcount
    return removed


def prune(max_seconds: int | None = None, batch: int | None = None) -> dict[str, Any]:
    """Enforce the row caps. Idempotent, batched, time-bounded. Never raises."""
    if (get_setting("retention.enabled") or "1") != "1":
        return {"status": "disabled", "decisions": 0, "mt_pushes": 0}

    budget = max_seconds if max_seconds is not None else _setting_int(
        "retention.max_seconds", DEFAULT_MAX_SECONDS)
    size = batch if batch is not None else _setting_int(
        "retention.batch_size", DEFAULT_BATCH)
    dec_cap = _setting_int("retention.decisions_tombstone_cap",
                           DEFAULT_DECISIONS_TOMBSTONE_CAP)
    mt_cap = _setting_int("retention.mt_pushes_cap", DEFAULT_MT_PUSHES_CAP)

    out: dict[str, Any] = {"status": "ok", "decisions": 0, "mt_pushes": 0,
                           "truncated": False}
    deadline = time.monotonic() + budget
    conn = get_conn()
    try:
        # --- decisions: soft-deleted rows only, newest dec_cap retained ---
        cutoff = _cutoff_id(conn, "decisions", dec_cap,
                            "deleted_at IS NOT NULL")
        if cutoff is not None:
            out["decisions"] = _drain(
                conn,
                # A pending approval may still point at a tombstoned decision;
                # decision_id has no FK so nothing would stop us orphaning it.
                "DELETE FROM decisions WHERE id IN ("
                "  SELECT id FROM decisions"
                "  WHERE deleted_at IS NOT NULL AND id <= ?"
                "    AND id NOT IN ("
                "      SELECT decision_id FROM approval_queue"
                "      WHERE status = 'pending' AND decision_id IS NOT NULL)"
                "  ORDER BY id LIMIT ?)",
                (cutoff,), deadline, size)

        # --- mt_pushes: pure push log, newest mt_cap retained ---
        cutoff = _cutoff_id(conn, "mt_pushes", mt_cap)
        if cutoff is not None:
            out["mt_pushes"] = _drain(
                conn,
                "DELETE FROM mt_pushes WHERE id IN ("
                "  SELECT id FROM mt_pushes WHERE id <= ?"
                "  ORDER BY id LIMIT ?)",
                (cutoff,), deadline, size)

        out["truncated"] = time.monotonic() >= deadline
    except Exception as e:  # noqa: BLE001 — never break the caller
        log.warning("retention sweep failed: %s", e)
        out["status"] = "error"
        out["error"] = str(e)[:200]
    finally:
        conn.close()

    if out["decisions"] or out["mt_pushes"]:
        log.info("retention: pruned %s decisions, %s mt_pushes%s",
                 out["decisions"], out["mt_pushes"],
                 " (budget hit; more remains)" if out["truncated"] else "")
    return out


def status() -> dict[str, Any]:
    """Current row counts vs caps — for /perf and operator sanity checks."""
    conn = get_conn()
    try:
        active = conn.execute(
            "SELECT count(*) c FROM decisions WHERE deleted_at IS NULL").fetchone()["c"]
        tombs = conn.execute(
            "SELECT count(*) c FROM decisions WHERE deleted_at IS NOT NULL").fetchone()["c"]
        pushes = conn.execute("SELECT count(*) c FROM mt_pushes").fetchone()["c"]
    finally:
        conn.close()
    return {
        "decisions_active": active,
        "decisions_tombstones": tombs,
        "decisions_tombstone_cap": _setting_int(
            "retention.decisions_tombstone_cap", DEFAULT_DECISIONS_TOMBSTONE_CAP),
        "mt_pushes": pushes,
        "mt_pushes_cap": _setting_int("retention.mt_pushes_cap",
                                      DEFAULT_MT_PUSHES_CAP),
        "enabled": (get_setting("retention.enabled") or "1") == "1",
    }


if __name__ == "__main__":  # manual drain: venv/bin/python retention.py
    import json
    import sys

    from dotenv import load_dotenv
    load_dotenv("/var/www/Protek/.env")

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    print("before:", json.dumps(status(), indent=2))
    print(json.dumps(prune(max_seconds=budget), indent=2))
    print("after: ", json.dumps(status(), indent=2))
