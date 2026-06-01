"""
perf.py — Arc 6 phase 36. Performance helpers.

We don't keep separate stage timings yet (LAPI fetch vs MT snapshot vs diff
compute vs push are all aggregated into the single `sync_events.duration_ms`
field). What we DO have, plenty of:

  - sync_events: one row per reconcile cycle with duration + outcome.
  - mt_pushes:   one row per per-bouncer op with success flag + error.
  - settings.poller.last_at: end-of-cycle stamp.

So this module computes p50/p95/p99 over `sync_events.duration_ms` for the
last N hours, surfaces the slowest recent cycles, and breaks down errors
by bouncer (parsed from the `error` column where mt_pushes stores
"bouncer_name · message").

Stage-level timing is a future addition — when phase-4 live writes land,
we'll add `lapi_ms`, `snapshot_ms`, `diff_ms`, `push_ms` columns to
sync_events and update this module to surface them. Until then, the
single duration is the only honest signal we have.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from db import get_conn


def _percentile(sorted_values: list[int], p: float) -> int:
    if not sorted_values:
        return 0
    idx = max(0, min(len(sorted_values) - 1,
                     int(round((p / 100) * (len(sorted_values) - 1)))))
    return sorted_values[idx]


def cycle_stats(hours: int = 24) -> dict[str, Any]:
    """p50/p95/p99 + counts over the last `hours` hours."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT duration_ms, errors FROM sync_events WHERE started_at >= ?",
            (since,),
        ).fetchall()
    finally:
        conn.close()
    durs = sorted(int(r["duration_ms"] or 0) for r in rows)
    errs = sum(1 for r in rows if (r["errors"] or 0) > 0)
    return {
        "hours": hours,
        "count": len(rows),
        "errors": errs,
        "p50_ms": _percentile(durs, 50),
        "p95_ms": _percentile(durs, 95),
        "p99_ms": _percentile(durs, 99),
        "max_ms": durs[-1] if durs else 0,
        "min_ms": durs[0] if durs else 0,
        "avg_ms": int(sum(durs) / len(durs)) if durs else 0,
    }


def slow_cycles(limit: int = 20) -> list[dict[str, Any]]:
    """N slowest cycles ever (by duration)."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, started_at, duration_ms, added, removed, errors, notes, dry_run "
            "FROM sync_events ORDER BY duration_ms DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def recent_cycles(limit: int = 60) -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, started_at, duration_ms, added, removed, errors, notes, dry_run, "
            "lapi_fetch_ms, snapshot_ms, diff_ms, apply_ms "
            "FROM sync_events ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def stage_timings(hours: int = 24) -> dict[str, Any]:
    """Average + p95 per stage over the last `hours` hours. Stages were only
    instrumented in phase 55, so old rows have zeros — exclude them (any row
    where all four stages are zero) so the average isn't dragged down."""
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT lapi_fetch_ms, snapshot_ms, diff_ms, apply_ms, duration_ms "
            "FROM sync_events WHERE started_at >= ? "
            "AND (lapi_fetch_ms + snapshot_ms + diff_ms + apply_ms) > 0",
            (since,),
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        return {"hours": hours, "samples": 0, "stages": []}
    stages = ["lapi_fetch_ms", "snapshot_ms", "diff_ms", "apply_ms"]
    out = []
    for s in stages:
        vals = sorted(int(r[s] or 0) for r in rows)
        avg = sum(vals) // len(vals) if vals else 0
        p95 = _percentile(vals, 95)
        out.append({"stage": s, "avg_ms": avg, "p95_ms": p95, "max_ms": vals[-1] if vals else 0})
    # Compute share-of-total for the visual bar
    total_avg = sum(s["avg_ms"] for s in out) or 1
    for s in out:
        s["share_pct"] = round(s["avg_ms"] * 100 / total_avg, 1)
    return {"hours": hours, "samples": len(rows), "stages": out, "total_avg_ms": total_avg}


def stage_breakdown() -> dict[str, Any]:
    """Until per-stage timing columns exist, we surface the next-best signal:
    average cycle duration grouped by whether the cycle had errors."""
    conn = get_conn()
    try:
        ok = conn.execute(
            "SELECT AVG(duration_ms) AS d, COUNT(*) AS n FROM sync_events "
            "WHERE errors = 0 AND started_at >= datetime('now', '-1 day')"
        ).fetchone()
        bad = conn.execute(
            "SELECT AVG(duration_ms) AS d, COUNT(*) AS n FROM sync_events "
            "WHERE errors > 0 AND started_at >= datetime('now', '-1 day')"
        ).fetchone()
    finally:
        conn.close()
    return {
        "ok_avg_ms": int(ok["d"] or 0),
        "ok_count": int(ok["n"] or 0),
        "err_avg_ms": int(bad["d"] or 0),
        "err_count": int(bad["n"] or 0),
    }
