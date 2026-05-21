"""
slo.py — Arc 6 phase 37. Service Level Objectives tracking.

What we measure now (sources we already have without adding instrumentation):
  - sync_cycle_success: cycles with errors=0 ÷ total cycles
  - sync_cycle_duration: duration_ms percentile
  - source_health: per-source last_ok signal over the window

What we don't measure yet (deferred until instrumented):
  - decision_to_ban_latency: needs LAPI-receive-time vs MT-acknowledge-time
    columns on every decision. Phase 4 live writes will give us the MT side;
    the LAPI side requires a header dump on every stream pull.
  - dashboard_load: a Flask before_request/after_request middleware would
    record per-route timings. Cheap to add later — for now /perf surfaces
    sync cycle metrics directly.

Burn rate = (error_rate_observed / error_rate_budget). When > 1 we're
consuming the error budget faster than the window allows; when > 14.4 the
"fast burn" alerting threshold (per Google SRE workbook) fires.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from db import get_conn

# SLO catalogue. Targets are conservative defaults; operators can override
# via settings keys like `slo.sync_success.target` etc. in a later phase.
SLOS: list[dict[str, Any]] = [
    {
        "key": "sync_success",
        "title": "Reconcile cycle success rate",
        "description": "Share of reconcile cycles that complete without recorded errors.",
        "target": 0.999,  # 99.9%
        "unit": "ratio",
    },
    {
        "key": "sync_duration",
        "title": "Reconcile cycle duration",
        "description": "p95 reconcile cycle duration ≤ 5 seconds.",
        "target_ms": 5000,
        "unit": "ms_p95",
    },
    {
        "key": "poll_freshness",
        "title": "Poll freshness",
        "description": "Inter-cycle gap p95 ≤ 30s — proves the poller isn't wedged.",
        "target_ms": 30000,
        "unit": "ms_p95_gap",
    },
]


def _percentile(values: list[int], p: float) -> int:
    if not values:
        return 0
    s = sorted(values)
    idx = max(0, min(len(s) - 1, int(round((p / 100) * (len(s) - 1)))))
    return s[idx]


def evaluate(window_hours: int = 24) -> list[dict[str, Any]]:
    """Compute compliance + burn rate per SLO over a sliding window."""
    since = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT started_at, duration_ms, errors FROM sync_events "
            "WHERE started_at >= ? ORDER BY started_at",
            (since,),
        ).fetchall()
    finally:
        conn.close()
    results: list[dict[str, Any]] = []

    # sync_success
    total = len(rows)
    bad = sum(1 for r in rows if (r["errors"] or 0) > 0)
    good = total - bad
    success_rate = (good / total) if total else 1.0
    budget = 1 - SLOS[0]["target"]            # e.g. 0.001 = 0.1%
    observed = 1 - success_rate
    burn = (observed / budget) if budget > 0 else 0.0
    results.append({
        **SLOS[0],
        "value": success_rate,
        "value_str": f"{success_rate*100:.3f}%",
        "target_str": f"{SLOS[0]['target']*100:.1f}%",
        "compliant": success_rate >= SLOS[0]["target"],
        "burn_rate": burn,
        "burn_alert": burn >= 14.4,  # SRE workbook fast-burn threshold
        "samples": total,
    })

    # sync_duration p95
    durs = [int(r["duration_ms"] or 0) for r in rows]
    p95 = _percentile(durs, 95)
    target_ms = SLOS[1]["target_ms"]
    compliant = p95 <= target_ms
    # Burn for a duration SLO is fuzzier; report observed/target ratio above 1.0
    burn = (p95 / target_ms) if target_ms else 0
    results.append({
        **SLOS[1],
        "value": p95,
        "value_str": f"{p95} ms",
        "target_str": f"≤ {target_ms} ms",
        "compliant": compliant,
        "burn_rate": burn,
        "burn_alert": p95 > target_ms * 2,
        "samples": total,
    })

    # poll_freshness — gaps between successive cycle started_at
    gaps: list[int] = []
    prev = None
    for r in rows:
        try:
            t = datetime.fromisoformat(r["started_at"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        if prev is not None:
            gaps.append(int((t - prev).total_seconds() * 1000))
        prev = t
    gap_p95 = _percentile(gaps, 95)
    target_ms = SLOS[2]["target_ms"]
    compliant = gap_p95 <= target_ms
    burn = (gap_p95 / target_ms) if target_ms else 0
    results.append({
        **SLOS[2],
        "value": gap_p95,
        "value_str": f"{gap_p95} ms",
        "target_str": f"≤ {target_ms} ms",
        "compliant": compliant,
        "burn_rate": burn,
        "burn_alert": gap_p95 > target_ms * 2,
        "samples": max(0, total - 1),
    })

    return results


def summary(window_hours: int = 24) -> dict[str, Any]:
    s = evaluate(window_hours)
    return {
        "window_hours": window_hours,
        "all_ok": all(r["compliant"] for r in s),
        "any_burning": any(r["burn_alert"] for r in s),
        "slos": s,
    }
