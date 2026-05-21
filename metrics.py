"""
metrics.py — Prometheus text-format exporter for Protek.

We hand-roll the exposition format instead of pulling in `prometheus_client`
because:
  - all of our metrics are snapshots read from SQLite / the settings table,
    not in-process counters that need atomic increment;
  - text format is dead simple (one line per series, see the official spec at
    https://prometheus.io/docs/instrumenting/exposition_formats/).

Wired into Flask via /metrics in app.py. Auth: either bearer token in the
`METRICS_TOKEN` env var, or unauthenticated localhost-only when the token
isn't set (the typical "prometheus on the same box" deployment).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from db import get_conn, get_setting

log = logging.getLogger("protek.metrics")


def _esc(label_value: str) -> str:
    """Escape a label value per Prometheus exposition format."""
    return (
        str(label_value or "")
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def _line(name: str, value: float | int, labels: dict[str, str] | None = None) -> str:
    if labels:
        label_str = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
        return f"{name}{{{label_str}}} {value}"
    return f"{name} {value}"


def render() -> str:
    """Return a Prometheus text-format payload (one big string)."""
    lines: list[str] = []

    def emit(help_text: str, metric_type: str, name: str,
             samples: list[tuple[float | int, dict[str, str] | None]]) -> None:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {metric_type}")
        for value, labels in samples:
            lines.append(_line(name, value, labels))

    # ── Build info (constant — useful for join-on-info patterns) ────────────
    emit(
        "Build / phase info; value is always 1.",
        "gauge",
        "protek_build_info",
        [(1, {"version": "1.0.0", "phase": "50", "service": "protek"})],
    )

    # ── Poller state ────────────────────────────────────────────────────────
    last_at = get_setting("poller.last_at") or ""
    last_at_ts = 0.0
    if last_at:
        try:
            last_at_ts = datetime.fromisoformat(
                last_at.replace("Z", "+00:00")
            ).timestamp()
        except (ValueError, AttributeError):
            last_at_ts = 0.0
    now_ts = datetime.now(timezone.utc).timestamp()
    lag = max(0.0, now_ts - last_at_ts) if last_at_ts else 0.0

    emit(
        "Unix timestamp of the last completed poller cycle.",
        "gauge", "protek_poller_last_at_seconds",
        [(last_at_ts, None)],
    )
    emit(
        "Seconds since the last completed poller cycle.",
        "gauge", "protek_poller_lag_seconds",
        [(lag, None)],
    )
    emit(
        "1 if the most recent cycle succeeded, 0 otherwise.",
        "gauge", "protek_poller_last_ok",
        [(1 if (get_setting("poller.last_ok") == "1") else 0, None)],
    )
    emit(
        "Configured poller interval (seconds).",
        "gauge", "protek_poller_interval_seconds",
        [(int(get_setting("poller.interval") or "10"), None)],
    )
    emit(
        "Total completed poller cycles since process start.",
        "counter", "protek_poller_cycles_total",
        [(int(get_setting("poller.cycles") or "0"), None)],
    )

    # ── Reconcile state ─────────────────────────────────────────────────────
    duration_ms = int(get_setting("reconcile.last_duration_ms") or "0")
    emit(
        "Most recent reconcile cycle duration (seconds).",
        "gauge", "protek_reconcile_duration_seconds",
        [(duration_ms / 1000.0, None)],
    )
    emit(
        "Pending adds at end of last reconcile cycle.",
        "gauge", "protek_reconcile_to_add",
        [(int(get_setting("reconcile.last_to_add") or "0"), None)],
    )
    emit(
        "Pending removes at end of last reconcile cycle.",
        "gauge", "protek_reconcile_to_remove",
        [(int(get_setting("reconcile.last_to_remove") or "0"), None)],
    )
    emit(
        "Errors in the last reconcile cycle.",
        "gauge", "protek_reconcile_errors",
        [(int(get_setting("reconcile.last_errors") or "0"), None)],
    )
    emit(
        "Dry-run flag (1 = no MT writes).",
        "gauge", "protek_dry_run",
        [(1 if get_setting("reconcile.last_dry_run") == "1" else 0, None)],
    )

    # ── Decisions / sources / bouncers (live DB queries) ────────────────────
    conn = get_conn()
    try:
        active_total = conn.execute(
            "SELECT COUNT(DISTINCT value) AS n FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()["n"]
        emit(
            "Distinct IPs currently banned across all sources.",
            "gauge", "protek_active_decisions",
            [(int(active_total), None)],
        )

        # By origin (crowdsec / cscli / lists:firehol_* / console)
        per_origin = conn.execute(
            """
            SELECT COALESCE(origin, '') AS origin, COUNT(DISTINCT value) AS n
            FROM decisions
            WHERE deleted_at IS NULL
            GROUP BY origin
            """
        ).fetchall()
        emit(
            "Distinct active IPs per decision origin.",
            "gauge", "protek_active_decisions_by_origin",
            [(int(r["n"]), {"origin": r["origin"] or "unknown"}) for r in per_origin],
        )

        # By source (federation)
        per_source = conn.execute(
            """
            SELECT origin_source, COUNT(DISTINCT value) AS n
            FROM decisions
            WHERE deleted_at IS NULL
            GROUP BY origin_source
            """
        ).fetchall()
        emit(
            "Distinct active IPs contributed by each federated source.",
            "gauge", "protek_active_decisions_by_source",
            [(int(r["n"]), {"source": r["origin_source"] or "unknown"}) for r in per_source],
        )

        # Source health rows (federation)
        src_rows = conn.execute(
            """
            SELECT name, url, enabled, paused, backoff_until, last_pull_at, last_pull_n
            FROM sources
            """
        ).fetchall()
        samples: list[tuple[int, dict[str, str]]] = []
        for r in src_rows:
            healthy = 0
            if r["enabled"] and not r["paused"]:
                bu = r["backoff_until"] or ""
                in_backoff = False
                if bu:
                    try:
                        in_backoff = datetime.fromisoformat(
                            bu.replace("Z", "+00:00")
                        ) > datetime.now(timezone.utc)
                    except (ValueError, AttributeError):
                        in_backoff = False
                healthy = 0 if in_backoff else 1
            samples.append((healthy, {"name": r["name"] or "", "url": r["url"] or ""}))
        emit(
            "1 if a source is enabled, unpaused, and not currently in backoff.",
            "gauge", "protek_source_health",
            samples,
        )
        emit(
            "Total decisions returned by each source on its last pull.",
            "gauge", "protek_source_last_pull_n",
            [(int(r["last_pull_n"] or 0),
              {"name": r["name"] or ""}) for r in src_rows],
        )

        # Sync events — total + errors (lifetime)
        sync_total = conn.execute(
            "SELECT COUNT(*) AS n FROM sync_events"
        ).fetchone()["n"]
        sync_err_rows = conn.execute(
            "SELECT COUNT(*) AS n FROM sync_events WHERE errors > 0"
        ).fetchone()["n"]
        emit(
            "Lifetime count of reconcile cycles persisted to sync_events.",
            "counter", "protek_sync_events_total",
            [(int(sync_total), None)],
        )
        emit(
            "Lifetime count of reconcile cycles that recorded one or more errors.",
            "counter", "protek_sync_error_cycles_total",
            [(int(sync_err_rows), None)],
        )

        # Push errors per bouncer (mt_pushes is the push log)
        push_rows = conn.execute(
            """
            SELECT COALESCE(error, '') AS bouncer_tag, COUNT(*) AS n
            FROM mt_pushes
            WHERE success = 0
            GROUP BY error
            LIMIT 20
            """
        ).fetchall()
        push_total = conn.execute(
            "SELECT COUNT(*) AS n FROM mt_pushes WHERE success = 0"
        ).fetchone()["n"]
        emit(
            "Lifetime count of failed per-entry bouncer pushes.",
            "counter", "protek_push_errors_total",
            [(int(push_total), None)],
        )

        # Bouncer targets configured
        bt_rows = conn.execute(
            "SELECT kind, COUNT(*) AS n FROM bouncer_targets WHERE enabled = 1 GROUP BY kind"
        ).fetchall()
        emit(
            "Enabled bouncer targets by kind.",
            "gauge", "protek_bouncer_targets",
            [(int(r["n"]), {"kind": r["kind"] or "unknown"}) for r in bt_rows],
        )

        # Whitelist rules + approval queue depth
        wl_n = conn.execute(
            "SELECT COUNT(*) AS n FROM whitelist "
            "WHERE expires_at IS NULL OR expires_at > datetime('now')"
        ).fetchone()["n"]
        ap_n = conn.execute(
            "SELECT COUNT(*) AS n FROM approval_queue WHERE status = 'pending'"
        ).fetchone()["n"]
        emit(
            "Active (non-expired) whitelist rules.",
            "gauge", "protek_whitelist_rules",
            [(int(wl_n), None)],
        )
        emit(
            "Decisions awaiting human approval in semi-auto mode.",
            "gauge", "protek_approval_pending",
            [(int(ap_n), None)],
        )

        # Login audit lifetime totals — schema stores `success` (0/1).
        login_rows = conn.execute(
            "SELECT success, COUNT(*) AS n FROM login_audit GROUP BY success"
        ).fetchall()
        emit(
            "Lifetime login attempts by result.",
            "counter", "protek_login_attempts_total",
            [(int(r["n"]),
              {"result": "ok" if r["success"] else "fail"}) for r in login_rows],
        )

        # Intelligence caches — size + recency
        geo_n = conn.execute("SELECT COUNT(*) AS n FROM geo_cache").fetchone()["n"]
        cti_n = conn.execute("SELECT COUNT(*) AS n FROM cti_cache").fetchone()["n"]
        emit(
            "Rows in geo_cache (IP → country/ASN).",
            "gauge", "protek_geo_cache_rows",
            [(int(geo_n), None)],
        )
        emit(
            "Rows in cti_cache (CrowdSec CTI smoke lookups).",
            "gauge", "protek_cti_cache_rows",
            [(int(cti_n), None)],
        )
    finally:
        conn.close()

    # Final newline — Prometheus requires it.
    lines.append("")
    return "\n".join(lines)
