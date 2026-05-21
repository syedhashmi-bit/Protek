"""
reconciler.py — orchestrates the reconcile.py diff against MikroTik.

Phase 3 contract:
- compute_and_log(dry_run=True) only computes the diff and writes sync_events
  + mt_pushes rows. Never calls MT add/remove. Pure observability.
- Phase 4 will flip the dry_run kwarg to False (when the operator has
  verified the behavior) and actually call into mikrotik.add_entry /
  remove_entry.

Idempotency: the reconcile.py pure function ensures double-application is a
no-op. The reconciler refreshes the MT snapshot every cycle so it never
trusts a stale local cache.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from db import get_conn
from mikrotik import MikroTik, address_list_name, entry_id
from reconcile import OWNER_PREFIX, ReconcileDiff, reconcile
import bouncers as bouncers_mod

log = logging.getLogger("protek.reconciler")


def run_once(source: str = "auto", dry_run: bool = True, batch_cap: int = 200) -> dict[str, Any]:
    """One reconcile cycle across all bouncers.

    Steps:
      1. Pull desired decisions from the DB (whitelist + approval queue applied).
      2. For each enabled bouncer: snapshot → diff → apply (if not dry-run).
      3. Aggregate counts and persist sync_events + mt_pushes.
    """
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    note_bits: list[str] = []
    error_count = 0

    desired = _desired_from_db()
    all_bouncers = bouncers_mod.load_all_targets()

    if not all_bouncers:
        note_bits.append("no_bouncers_configured")
        # Still compute a virtual diff vs empty so the dashboard shows queue size.
        diff = reconcile(desired, [])
        total_add = len(diff.to_add)
        total_remove = 0
        unchanged = 0
    else:
        total_add = 0
        total_remove = 0
        unchanged = 0
        per_bouncer_push: list[dict[str, Any]] = []

        for b in all_bouncers:
            try:
                current = b.snapshot() if b.is_configured() else []
            except Exception as e:  # noqa: BLE001
                current = []
                error_count += 1
                note_bits.append(f"{b.name}_snapshot_failed: {e}")

            diff = reconcile(desired, current)
            total_add += len(diff.to_add)
            total_remove += len(diff.to_remove)
            unchanged += diff.unchanged

            if not dry_run and b.is_configured() and diff.changes:
                to_add = diff.to_add[:batch_cap]
                remaining = max(0, batch_cap - len(to_add))
                to_remove = diff.to_remove[:remaining]
                try:
                    res = b.apply(to_add, to_remove)
                    error_count += res.get("errors", 0)
                    per_bouncer_push.append({"name": b.name, **res})
                    # Per-op rows persisted below
                except Exception as e:  # noqa: BLE001
                    error_count += 1
                    note_bits.append(f"{b.name}_apply_failed: {e}")

            if (len(diff.to_add) + len(diff.to_remove)) > batch_cap:
                note_bits.append(f"{b.name}_batch_capped: {batch_cap}")

    duration_ms = int((time.monotonic() - t0) * 1000)

    conn = get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO sync_events
                (started_at, duration_ms, added, removed, unchanged, errors, source, dry_run, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (started.isoformat(), duration_ms, total_add, total_remove,
             unchanged, error_count, source, 1 if dry_run else 0,
             "; ".join(note_bits)),
        )
        sync_id = cur.lastrowid

        if dry_run:
            # Per-bouncer summary into mt_pushes (sampled to batch_cap to avoid spam)
            for b in all_bouncers:
                _, sampled_adds = (None, [])
                conn.execute(
                    "INSERT INTO mt_pushes (sync_event_id, ip, action, success, error) "
                    "VALUES (?, ?, 'note', 1, ?)",
                    (sync_id, b.name, f"dry-run · {b.kind}"),
                )
        else:
            for pb in per_bouncer_push:
                for p in pb.get("push_log", []):
                    conn.execute(
                        "INSERT INTO mt_pushes (sync_event_id, ip, action, success, error) VALUES (?, ?, ?, ?, ?)",
                        (sync_id, p["ip"], p["action"], 1 if p["success"] else 0,
                         f"{pb['name']} · {p.get('error', '')}"),
                    )
    finally:
        conn.close()

    return {
        "sync_event_id": sync_id,
        "started_at": started.isoformat(),
        "duration_ms": duration_ms,
        "to_add": total_add,
        "to_remove": total_remove,
        "unchanged": unchanged,
        "foreign_kept": 0,
        "dry_run": dry_run,
        "errors": error_count,
        "notes": "; ".join(note_bits),
        "bouncer_count": len(all_bouncers),
    }


def _desired_from_db() -> list[dict[str, Any]]:
    """Build the desired-decisions list from the local mirror table.

    Federation: when phase-10 confidence_threshold > 1, only IPs seen by
    that many sources qualify for MikroTik push. The decision row is still
    picked from any source (first-wins) — the threshold gates inclusion.
    """
    from db import get_setting
    try:
        threshold = max(1, int(get_setting("federation.confidence_threshold") or "1"))
    except (ValueError, TypeError):
        threshold = 1

    # Dedup at the SQL level — community blocklists produce many rows per IP
    # (same value, different lapi_id/scenario), but the reconcile diff only
    # needs one entry per (value, scope). MIN(lapi_id) picks a stable
    # representative so the comment we write to the address-list is
    # deterministic across cycles.
    conn = get_conn()
    try:
        if threshold <= 1:
            rows = conn.execute(
                """
                SELECT value, scope,
                       MIN(scenario)      AS scenario,
                       MIN(origin)        AS origin,
                       MIN(origin_source) AS origin_source,
                       MIN(lapi_id)       AS lapi_id
                FROM decisions
                WHERE deleted_at IS NULL
                GROUP BY value, scope
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT d.value, d.scope,
                       MIN(d.scenario)      AS scenario,
                       MIN(d.origin)        AS origin,
                       MIN(d.origin_source) AS origin_source,
                       MIN(d.lapi_id)       AS lapi_id
                FROM decisions d
                WHERE d.deleted_at IS NULL
                  AND d.value IN (
                      SELECT ip FROM ip_sources
                      WHERE last_seen_at > datetime('now', '-7 days')
                      GROUP BY ip HAVING COUNT(DISTINCT source_name) >= ?
                  )
                GROUP BY d.value, d.scope
                """,
                (threshold,),
            ).fetchall()
    finally:
        conn.close()
    desired = [
        {
            "value": r["value"],
            "scope": r["scope"],
            "scenario": r["scenario"],
            "origin": r["origin"],
            "origin_source": r["origin_source"],
            "lapi_id": r["lapi_id"],
        }
        for r in rows
    ]
    try:
        import scenarios_admin as sa
    except ImportError:
        return desired

    if not desired:
        return desired

    # Pre-fetch whitelist + geo enrichment in ONE pass each — without this the
    # reconciler hits the DB once per decision (was 90s on 111k rows).
    whitelist_rules = sa.list_whitelist(include_expired=False)
    ips = [d["value"] for d in desired if d.get("value")]
    asn_map: dict[str, str] = {}
    country_map: dict[str, str] = {}
    if ips:
        conn = get_conn()
        try:
            placeholders = ",".join("?" * len(ips))
            for r in conn.execute(
                f"SELECT ip, asn, country_code FROM geo_cache WHERE ip IN ({placeholders})", ips
            ).fetchall():
                if r["asn"]:
                    asn_map[r["ip"]] = r["asn"]
                if r["country_code"]:
                    country_map[r["ip"]] = r["country_code"]
        finally:
            conn.close()

    out = []
    for d in desired:
        val = d.get("value", "")
        match = sa.matches_whitelist(
            val,
            asn=asn_map.get(val, ""),
            country=country_map.get(val, ""),
            rules=whitelist_rules,
        )
        if match:
            sa.record_whitelist_hit(val, match["id"], scenario=d.get("scenario", ""))
            continue
        out.append(d)

    # Approval queue: if semi-auto mode, drop decisions whose IP isn't approved.
    if sa.approval_required():
        conn = get_conn()
        try:
            approved_ips = {
                r["ip"] for r in conn.execute(
                    "SELECT ip FROM approval_queue WHERE status = 'approved'"
                ).fetchall()
            }
            # Pre-fetch the latest queue status for every candidate IP in one
            # query — used to know which ones already have a pending/rejected
            # row so we don't re-queue them.
            seen_status: dict[str, str] = {}
            if out:
                placeholders = ",".join("?" * len(out))
                rows = conn.execute(
                    f"""
                    SELECT ip, status
                    FROM approval_queue
                    WHERE id IN (
                        SELECT MAX(id) FROM approval_queue
                        WHERE ip IN ({placeholders})
                        GROUP BY ip
                    )
                    """,
                    [d["value"] for d in out],
                ).fetchall()
                for r in rows:
                    seen_status[r["ip"]] = r["status"]
        finally:
            conn.close()
        for d in out:
            if d["value"] in approved_ips or d["value"] in seen_status:
                continue
            sa.queue_decision(d["value"], d.get("scope", "Ip"),
                              d.get("scenario", ""), d.get("origin", ""),
                              d.get("origin_source", ""), d.get("lapi_id"))
        out = [d for d in out if d["value"] in approved_ips]
    return out


def _apply_legacy_unused(mt: MikroTik, list_name: str, diff: ReconcileDiff, batch_cap: int):
    """Phase-4 write path. Returns (applied_add, applied_remove, push_log, errors).

    Defensive design:
    - Add errors that look like "already have such entry" are treated as
      successful idempotent operations, not errors.
    - All other errors are captured per-op and logged in mt_pushes.
    """
    applied_add = 0
    applied_remove = 0
    push_log: list[dict[str, Any]] = []
    errors = 0

    mt.connect()
    try:
        res = mt._api.get_resource("/ip/firewall/address-list")  # noqa: SLF001
        # Adds first — usually the bigger batch on initial sync.
        for addr, comment in diff.to_add[:batch_cap]:
            try:
                res.add(list=list_name, address=addr, comment=comment)
                applied_add += 1
                push_log.append({"ip": addr, "action": "add", "success": True})
            except Exception as e:  # noqa: BLE001
                msg = str(e).lower()
                if "already have such entry" in msg or "duplicate" in msg or "already exists" in msg:
                    applied_add += 1
                    push_log.append({"ip": addr, "action": "add", "success": True, "error": "idempotent (already exists)"})
                else:
                    errors += 1
                    push_log.append({"ip": addr, "action": "add", "success": False, "error": str(e)[:300]})
        # Removes — only ones whose owner comment we wrote.
        remaining = max(0, batch_cap - len(diff.to_add))
        for mt_id in diff.to_remove[:remaining]:
            try:
                res.remove(id=mt_id)
                applied_remove += 1
                push_log.append({"ip": mt_id, "action": "remove", "success": True})
            except Exception as e:  # noqa: BLE001
                msg = str(e).lower()
                if "no such item" in msg or "not found" in msg:
                    applied_remove += 1
                    push_log.append({"ip": mt_id, "action": "remove", "success": True, "error": "idempotent (already gone)"})
                else:
                    errors += 1
                    push_log.append({"ip": mt_id, "action": "remove", "success": False, "error": str(e)[:300]})
    finally:
        mt.disconnect()

    return applied_add, applied_remove, push_log, errors
