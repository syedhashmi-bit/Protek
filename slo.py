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


def _slo_target(key: str, default_value: Any, *, ms: bool = False) -> Any:
    """Per-SLO target override via settings. Operators tune the baked-in
    defaults via `slo.<key>.target` (ratio) or `slo.<key>.target_ms` (ms)
    without code edits — useful because realistic targets depend on
    deployment shape (community blocklists make cycles take longer)."""
    from db import get_setting
    raw = get_setting(f"slo.{key}.target_ms" if ms else f"slo.{key}.target")
    if not raw:
        return default_value
    try:
        return int(raw) if ms else float(raw)
    except (TypeError, ValueError):
        return default_value


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
    target = _slo_target("sync_success", SLOS[0]["target"])
    budget = 1 - target            # e.g. 0.001 = 0.1%
    observed = 1 - success_rate
    burn = (observed / budget) if budget > 0 else 0.0
    results.append({
        **SLOS[0],
        "target": target,
        "value": success_rate,
        "value_str": f"{success_rate*100:.3f}%",
        "target_str": f"{target*100:.1f}%",
        "compliant": success_rate >= target,
        "burn_rate": burn,
        "burn_alert": burn >= 14.4,  # SRE workbook fast-burn threshold
        "samples": total,
    })

    # sync_duration p95
    durs = [int(r["duration_ms"] or 0) for r in rows]
    p95 = _percentile(durs, 95)
    target_ms = _slo_target("sync_duration", SLOS[1]["target_ms"], ms=True)
    compliant = p95 <= target_ms
    burn = (p95 / target_ms) if target_ms else 0
    results.append({
        **SLOS[1],
        "target_ms": target_ms,
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
    target_ms = _slo_target("poll_freshness", SLOS[2]["target_ms"], ms=True)
    compliant = gap_p95 <= target_ms
    burn = (gap_p95 / target_ms) if target_ms else 0
    results.append({
        **SLOS[2],
        "target_ms": target_ms,
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


# ── Phase 91 — sustained-breach detection + alerting ──────────────────────

DEFAULT_GRACE_MIN = 5  # SLO breach must persist this long before alerting


def alert_if_breached(window_hours: int = 24,
                      grace_min: int | None = None) -> dict[str, Any]:
    """Phase 91 — called periodically (by the poller) to fire notifications
    on sustained SLO breaches. Returns a dict describing what was checked
    and what was alerted on this call.

    Algorithm per SLO:
      - Each time the SLO is non-compliant, we record breach_started_at
        in the settings table. If it's already set we leave it alone
        (the breach is ongoing).
      - When the breach has persisted ≥ grace_min, we fire the alert
        once (edge-triggered) and mark the SLO as 'alerted'. Subsequent
        non-compliant samples don't re-alert.
      - When the SLO returns to compliant, we clear breach_started_at
        and (if previously alerted) fire a recovery alert.

    Grace window avoids single-cycle-flap alerts. Default 5 minutes
    matches the phase-91 spec; tunable via settings key
    `slo.grace_min` or the `grace_min` kwarg.
    """
    from datetime import datetime, timezone
    from db import get_setting, set_setting

    if grace_min is None:
        try:
            grace_min = int(get_setting("slo.grace_min") or DEFAULT_GRACE_MIN)
        except (TypeError, ValueError):
            grace_min = DEFAULT_GRACE_MIN

    # Master kill-switch — default OFF. The shipped SLO targets are
    # conservative defaults (5s cycle, 30s poll-freshness) that don't match
    # all real deployment shapes (community blocklists take longer to
    # reconcile). Operator enables this after tuning the targets via
    # `slo.<key>.target_ms` settings.
    alerts_enabled = (get_setting("slo.alerts_enabled") or "0") == "1"

    now = datetime.now(timezone.utc)
    out: dict[str, Any] = {"checked_at": now.isoformat(),
                            "grace_min": grace_min,
                            "alerts_enabled": alerts_enabled,
                            "alerts_fired": [], "recoveries_fired": []}
    if not alerts_enabled:
        # Still evaluate so /perf reflects current state, but don't fire
        # notifications. The breach_started_at clock also stays idle so
        # toggling alerts on later doesn't immediately fire an alert
        # based on accumulated past breaches.
        return out
    rows = evaluate(window_hours)

    # Lazy import: avoid circular import via app.py at module load
    try:
        import notifications as nmod
    except Exception:  # noqa: BLE001
        nmod = None
    try:
        import siem as siem_mod
    except Exception:  # noqa: BLE001
        siem_mod = None

    for r in rows:
        key = r["key"]
        compliant = r["compliant"]
        breach_started = get_setting(f"slo.{key}.breach_started_at")
        alerted = (get_setting(f"slo.{key}.alerted") or "0") == "1"

        if not compliant:
            if not breach_started:
                # First non-compliant sample for this SLO — start the clock.
                set_setting(f"slo.{key}.breach_started_at", now.isoformat())
                continue
            try:
                started = datetime.fromisoformat(breach_started.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                set_setting(f"slo.{key}.breach_started_at", now.isoformat())
                continue
            mins = (now - started).total_seconds() / 60.0
            if mins >= grace_min and not alerted:
                msg = (f"SLO `{key}` ({r['title']}) breached for {mins:.1f} min — "
                       f"observed {r['value_str']}, target {r['target_str']}, "
                       f"burn rate {r['burn_rate']:.1f}x.")
                if nmod:
                    try:
                        nmod.send("sync_error", msg,
                                  subject=f"[SLO] {key} breach sustained")
                    except Exception:  # noqa: BLE001
                        pass
                if siem_mod:
                    try:
                        siem_mod.ship("slo.breach", {
                            "key": key, "title": r["title"],
                            "value": r["value_str"], "target": r["target_str"],
                            "burn_rate": r["burn_rate"],
                            "sustained_min": round(mins, 1),
                        }, severity=3)
                    except Exception:  # noqa: BLE001
                        pass
                set_setting(f"slo.{key}.alerted", "1")
                out["alerts_fired"].append(key)
        else:
            # Compliant now — clear the clock; fire recovery if we'd alerted.
            if alerted:
                msg = (f"SLO `{key}` ({r['title']}) recovered — "
                       f"now at {r['value_str']} (target {r['target_str']}).")
                if nmod:
                    try:
                        nmod.send("sync_error", msg,
                                  subject=f"[SLO] {key} recovered")
                    except Exception:  # noqa: BLE001
                        pass
                if siem_mod:
                    try:
                        siem_mod.ship("slo.recovery", {
                            "key": key, "value": r["value_str"],
                        }, severity=6)
                    except Exception:  # noqa: BLE001
                        pass
                out["recoveries_fired"].append(key)
            if breach_started:
                set_setting(f"slo.{key}.breach_started_at", "")
            if alerted:
                set_setting(f"slo.{key}.alerted", "0")

    return out
