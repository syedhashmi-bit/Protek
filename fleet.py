"""
fleet.py — Arc 16 phase 96. At-a-glance overview of all bouncer targets.

The /bouncers page is the detail/edit surface — one expanded row per
target with edit/promote/remove buttons. /fleet is its sibling: a
dense overview that scales when the operator runs 5-10 MikroTiks +
Cloudflare + an iptables host across the fleet. It surfaces three
questions at a glance:

  1. Which targets are healthy / degraded / down right now?
  2. How is throughput trending over the last 24h?
  3. Which targets are largest / freshest / slowest?

Implementation notes:
  - Per-target status comes from a live `t.health()` probe (same as
    /bouncers). Bounded latency per render: number of bouncers × MT
    API connect time, usually <1s total for 5 MTs.
  - 24h chart data comes from `sync_events` rolled up into 24 hourly
    buckets. Cheap query — uses the `started_at` index.
  - Sortable columns are pure client-side JS on the rendered table;
    no separate sort routes needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from db import get_conn


def build_view() -> dict[str, Any]:
    """Assemble everything the /fleet template needs in one call so
    the route function stays trivial."""
    import bouncers as bmod
    targets = bmod.load_all_targets()

    conn = get_conn()
    try:
        # Per-target DB row (last_sync_at + last_error + dry_run)
        db_rows = {r["name"]: dict(r) for r in conn.execute(
            "SELECT * FROM bouncer_targets ORDER BY id"
        ).fetchall()}
    finally:
        conn.close()

    rows: list[dict[str, Any]] = []
    online = degraded = errors_n = 0
    total_entries = 0
    now = datetime.now(timezone.utc)
    for t in targets:
        try:
            h = t.health()
        except Exception as e:  # noqa: BLE001
            h = {"ok": False, "error": str(e)[:200]}
        ok = bool(h.get("ok"))
        db_row = db_rows.get(t.name) or {}
        last_error = db_row.get("last_error", "") or ""
        is_degraded = bool(last_error.startswith("degraded:"))

        if ok and not is_degraded:
            online += 1
            status = "online"
        elif is_degraded:
            degraded += 1
            status = "degraded"
        else:
            errors_n += 1
            status = "offline"

        # Size: same shape the existing /bouncers page handles — some
        # adapters report a single `size`, others split into v4 + v6.
        size = h.get("size")
        if size is None and "v4_size" in h:
            size = (h.get("v4_size") or 0) + (h.get("v6_size") or 0)
        if isinstance(size, int):
            total_entries += size

        lag_s = _seconds_since(db_row.get("last_sync_at"), now)
        rows.append({
            "id":            db_row.get("id") or 0,
            "name":          t.name,
            "kind":          t.kind,
            "status":        status,
            "ok":            ok,
            "size":          size,
            "dry_run":       bool(db_row.get("dry_run", 1)),
            "lag_s":         lag_s,
            "lag_str":       _human_lag(lag_s),
            "version":       _extract_version(h),
            "last_error":    last_error,
            "error_short":   _truncate(last_error, 60),
            "removable":     bool(db_row),
        })

    # 24h hourly buckets for the global throughput chart
    chart = _hourly_buckets(window_hours=24, now=now)

    kpis = {
        "total":         len(rows),
        "online":        online,
        "degraded":      degraded,
        "offline":       errors_n,
        "total_entries": total_entries,
        "cycles_24h":    chart["cycles_total"],
        "adds_24h":      chart["adds_total"],
        "errs_24h":      chart["errs_total"],
    }

    return {
        "rows":   rows,
        "kpis":   kpis,
        "chart":  chart,
    }


def _seconds_since(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return int((now - t).total_seconds())


def _human_lag(s: int | None) -> str:
    """Compact lag display for table cells. Matches the visual rhythm
    of the existing rel_time() helper in app.py without depending on it
    (this module is independently importable from tests)."""
    if s is None:
        return "—"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    return f"{s // 86400}d"


def _extract_version(h: dict[str, Any]) -> str:
    """RouterOS version when the adapter surfaces it via health().
    Different adapter kinds report this in different shapes; tolerant
    parsing so a missing field doesn't break the row."""
    for key in ("version", "ros_version", "routeros"):
        v = h.get(key)
        if v:
            return str(v)[:32]
    return ""


def _truncate(s: str, n: int) -> str:
    if not s:
        return ""
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _hourly_buckets(window_hours: int, now: datetime) -> dict[str, Any]:
    """24 hourly buckets over the last `window_hours`. Each bucket
    carries adds + removes + errors + cycle count. The chart in the
    template renders the `adds` series as a green bar and `errs` as a
    red mark on top."""
    since = now - timedelta(hours=window_hours)
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT started_at, added, removed, errors "
            "FROM sync_events WHERE started_at >= ? ORDER BY started_at",
            (since.isoformat(),),
        ).fetchall()
    finally:
        conn.close()

    buckets = [{"adds": 0, "removes": 0, "errs": 0, "cycles": 0,
                 "label": ""} for _ in range(window_hours)]
    for r in rows:
        try:
            t = datetime.fromisoformat(r["started_at"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        # Negative number of hours ago, clamped into [0, window-1]
        ago_h = int((now - t).total_seconds() // 3600)
        if 0 <= ago_h < window_hours:
            idx = (window_hours - 1) - ago_h  # oldest left, newest right
            buckets[idx]["adds"] += int(r["added"] or 0)
            buckets[idx]["removes"] += int(r["removed"] or 0)
            buckets[idx]["errs"] += 1 if (r["errors"] or 0) > 0 else 0
            buckets[idx]["cycles"] += 1

    # Label each bucket with its hour-of-day (newest = current hour)
    for i, b in enumerate(buckets):
        ago = (window_hours - 1) - i
        t = now - timedelta(hours=ago)
        b["label"] = t.strftime("%H:00")

    adds_max = max((b["adds"] + b["removes"] for b in buckets), default=0)
    return {
        "buckets":      buckets,
        "max_value":    adds_max,
        "cycles_total": sum(b["cycles"] for b in buckets),
        "adds_total":   sum(b["adds"] for b in buckets),
        "removes_total": sum(b["removes"] for b in buckets),
        "errs_total":   sum(b["errs"] for b in buckets),
    }
