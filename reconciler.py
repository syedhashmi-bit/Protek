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
from mikrotik import MikroTik
from reconcile import ReconcileDiff, reconcile
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

    # Per-stage timing (phase 55) — accumulated across bouncers where
    # applicable. lapi_fetch_ms covers _desired_from_db (the SQL pull +
    # whitelist match). snapshot_ms + apply_ms are summed across bouncers
    # so the bar-chart breakdown shows the dominant downstream.
    t_lapi = time.monotonic()
    desired = _desired_from_db()
    lapi_fetch_ms = int((time.monotonic() - t_lapi) * 1000)
    snapshot_ms = 0
    diff_ms = 0
    apply_ms = 0

    all_bouncers = bouncers_mod.load_all_targets()

    if not all_bouncers:
        note_bits.append("no_bouncers_configured")
        # Still compute a virtual diff vs empty so the dashboard shows queue size.
        t_diff = time.monotonic()
        diff = reconcile(desired, [])
        diff_ms += int((time.monotonic() - t_diff) * 1000)
        total_add = len(diff.to_add)
        total_remove = 0
        unchanged = 0
    else:
        # Phase 89 — per-bouncer work runs in parallel so a slow bouncer
        # doesn't block faster ones from starting. Cap workers at 4 — bouncers
        # do meaningful network work (MT API, CF API, etc.), so more than
        # this on a single VPS is rarely useful.
        #
        # Earlier this used `fut.result(timeout=N)` to mark slow bouncers
        # degraded, but ThreadPoolExecutor.__exit__ calls shutdown(wait=True)
        # — so the cycle wall time is the slowest future regardless, and the
        # only effect of the timeout was to discard the slow bouncer's push
        # log + counts while the writes still landed on the target. That gave
        # the operator a silent-failure pattern: real router writes with no
        # mt_pushes rows and inflated `unchanged` collapse in the cycle log.
        #
        # Now we wait for every future to complete and derive the `degraded`
        # signal from per-bouncer wall time after the fact. The badge still
        # surfaces slow bouncers but no work is dropped.
        from concurrent.futures import ThreadPoolExecutor

        total_add = 0
        total_remove = 0
        unchanged = 0
        per_bouncer_push: list[dict[str, Any]] = []

        max_workers = min(4, max(1, len(all_bouncers)))
        per_bouncer_slow_s = float(
            (__import__("db").get_setting("reconcile.per_bouncer_timeout_s")
             or "60")
        )

        mt_list_count = 0
        mt_count_valid = False
        with ThreadPoolExecutor(max_workers=max_workers,
                                 thread_name_prefix="bouncer-apply") as ex:
            futures = {
                ex.submit(_run_one_bouncer, b, desired, dry_run, batch_cap): b
                for b in all_bouncers
            }
            for fut, b in futures.items():
                try:
                    r = fut.result()
                except Exception as e:  # noqa: BLE001
                    error_count += 1
                    note_bits.append(f"{b.name}_apply_failed: {e}")
                    continue
                # Owned address-list size, summed across MikroTik bouncers, so
                # the dashboard can show the count without live-fetching the router.
                if str(r.get("kind", "")).startswith("mikrotik") and r["snapshot_ok"]:
                    mt_list_count += r["snapshot_n"]
                    mt_count_valid = True
                snapshot_ms += r["snapshot_ms"]
                diff_ms     += r["diff_ms"]
                apply_ms    += r["apply_ms"]
                total_add   += r["to_add_n"]
                total_remove += r["to_remove_n"]
                unchanged   += r["unchanged_n"]
                error_count += r["errors"]
                note_bits.extend(r["notes"])
                if r["push_log"]:
                    per_bouncer_push.append({"name": b.name, "push_log": r["push_log"]})
                # Mark degraded if this bouncer is consistently slow — the
                # signal still helps the operator notice the slow target;
                # the threshold is the same knob as the legacy timeout.
                b_wall_ms = r["snapshot_ms"] + r["apply_ms"]
                if b_wall_ms > per_bouncer_slow_s * 1000:
                    _mark_bouncer_degraded(
                        b.name,
                        f"slow {b_wall_ms/1000:.0f}s (snapshot+apply) "
                        f"@ {datetime.now(timezone.utc).isoformat()}",
                    )
                elif r["ok"] and not r["errors"]:
                    _clear_bouncer_degraded(b.name)

    duration_ms = int((time.monotonic() - t0) * 1000)

    conn = get_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO sync_events
                (started_at, duration_ms, added, removed, unchanged, errors, source, dry_run, notes,
                 lapi_fetch_ms, snapshot_ms, diff_ms, apply_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (started.isoformat(), duration_ms, total_add, total_remove,
             unchanged, error_count, source, 1 if dry_run else 0,
             "; ".join(note_bits),
             lapi_fetch_ms, snapshot_ms, diff_ms, apply_ms),
        )
        sync_id = cur.lastrowid

        if dry_run:
            # Per-bouncer summary into mt_pushes (sampled to batch_cap to avoid spam)
            for b in all_bouncers:
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
        "lapi_fetch_ms": lapi_fetch_ms,
        "snapshot_ms": snapshot_ms,
        "diff_ms": diff_ms,
        "apply_ms": apply_ms,
        "to_add": total_add,
        "to_remove": total_remove,
        "unchanged": unchanged,
        "foreign_kept": 0,
        "dry_run": dry_run,
        "errors": error_count,
        "notes": "; ".join(note_bits),
        "bouncer_count": len(all_bouncers),
        "mt_list_count": mt_list_count,
        "mt_count_valid": mt_count_valid,
    }


def _run_one_bouncer(b, desired: list[dict[str, Any]],
                     dry_run: bool, batch_cap: int) -> dict[str, Any]:
    """Phase 89 — extracted per-bouncer body so we can run it in a thread
    with a per-bouncer timeout. Returns a dict the caller folds into the
    cycle totals. Never raises (catches its own exceptions); the future
    layer above only sees TimeoutError when the timeout actually fires.
    """
    out: dict[str, Any] = {
        "name": b.name, "kind": getattr(b, "kind", ""),
        "snapshot_ms": 0, "diff_ms": 0, "apply_ms": 0,
        "to_add_n": 0, "to_remove_n": 0, "unchanged_n": 0,
        "snapshot_n": 0, "snapshot_ok": False,
        "errors": 0, "notes": [], "push_log": [], "ok": True,
    }
    t_snap = time.monotonic()
    try:
        if b.is_configured():
            current = b.snapshot()
            out["snapshot_ok"] = True  # configured + snapshot returned cleanly
        else:
            current = []
    except Exception as e:  # noqa: BLE001
        current = []
        out["errors"] += 1
        out["ok"] = False
        out["notes"].append(f"{b.name}_snapshot_failed: {e}")
    out["snapshot_ms"] = int((time.monotonic() - t_snap) * 1000)
    # Owned-list size, captured for free here so the web tier never has to
    # re-fetch the full address-list just to display a count (see app.py
    # _cached_mt_count / poller mt.last_list_count).
    out["snapshot_n"] = len(current)

    desired_for_b = _filter_desired_for_bouncer(b, desired)
    if len(desired_for_b) < len(desired):
        out["notes"].append(
            f"{b.name}_filtered: {len(desired_for_b)}/{len(desired)}"
        )

    t_diff = time.monotonic()
    diff = reconcile(desired_for_b, current)
    out["diff_ms"] = int((time.monotonic() - t_diff) * 1000)
    out["to_add_n"] = len(diff.to_add)
    out["to_remove_n"] = len(diff.to_remove)
    out["unchanged_n"] = diff.unchanged

    b_dry = dry_run or _bouncer_is_dry(b)
    if not b_dry and b.is_configured() and diff.changes:
        to_add = diff.to_add[:batch_cap]
        remaining = max(0, batch_cap - len(to_add))
        to_remove = diff.to_remove[:remaining]
        t_apply = time.monotonic()
        try:
            res = b.apply(to_add, to_remove)
            out["errors"] += res.get("errors", 0)
            out["push_log"] = res.get("push_log", [])
        except Exception as e:  # noqa: BLE001
            out["errors"] += 1
            out["ok"] = False
            out["notes"].append(f"{b.name}_apply_failed: {e}")
        out["apply_ms"] = int((time.monotonic() - t_apply) * 1000)

    if (len(diff.to_add) + len(diff.to_remove)) > batch_cap:
        out["notes"].append(f"{b.name}_batch_capped: {batch_cap}")

    return out


def _mark_bouncer_degraded(name: str, reason: str) -> None:
    """Write a `degraded: <reason>` marker to bouncer_targets.last_error
    so /bouncers can show a badge. Best-effort — silent on failure."""
    try:
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE bouncer_targets SET last_error = ? WHERE name = ?",
                (f"degraded: {reason}", name),
            )
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass


def _clear_bouncer_degraded(name: str) -> None:
    """Clear the degraded marker on a successful cycle. Only clears rows
    whose error currently starts with 'degraded:' so we don't blow away
    a real adapter-side error message."""
    try:
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE bouncer_targets SET last_error = '' "
                "WHERE name = ? AND last_error LIKE 'degraded:%'",
                (name,),
            )
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass


def _bouncer_is_dry(bouncer) -> bool:
    """Check the per-bouncer dry_run flag. Legacy mikrotik_env follows the
    cycle-level dry_run only (already enforced at the caller); DB-driven
    targets carry a `dry_run` column on their bouncer_targets row.

    Failing closed: any error reading the row treats the bouncer as live
    (not dry) — the cycle-level dry_run is still in front of this, so the
    worst case is we honor the cycle's intent. The opposite (failing dry)
    would silently drop pushes from a working live target if the row
    lookup raced with a /bouncers edit, which is a bigger surprise.
    """
    if getattr(bouncer, "kind", "") == "mikrotik_env":
        return False
    name = getattr(bouncer, "name", "")
    if not name:
        return False
    try:
        conn = get_conn()
        try:
            row = conn.execute(
                "SELECT dry_run FROM bouncer_targets WHERE name = ?",
                (name,),
            ).fetchone()
        finally:
            conn.close()
        return bool(row and int(row["dry_run"] or 0))
    except Exception:  # noqa: BLE001
        return False


def _filter_desired_for_bouncer(bouncer, desired: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply per-bouncer subset filtering before computing the diff.

    Config keys (read from `bouncer_targets.config_json` for DB targets, or
    from a per-bouncer optional attribute for env-managed ones — env MT
    leaves all defaults so behavior is unchanged):

      origins         list[str] of fnmatch globs; if non-empty, decision's
                      `origin` must match at least one (e.g. ["crowdsec",
                      "lists:firehol_greensnow"])
      exclude_origins list[str] of fnmatch globs; if non-empty, exclude any
                      decision whose origin matches one (e.g. ["lists:*"]
                      drops the entire CAPI community-list firehose)
      max_entries     int; cap total push size. Prioritized by lapi_id DESC
                      (newest first), so the cap keeps the freshest bans
                      and drops the oldest.
      source_filter   str CSV or list[str] of federation source names; if
                      non-empty, only push decisions whose `origin_source`
                      matches one of these. Use case: `edge-mt` gets the
                      full federated set, `office-mt` gets only `local`
                      so it doesn't carry community blocklists. (phase 97)
      scenario_filter str regex (re.search); if non-empty, only push
                      decisions whose `scenario` matches. Use case:
                      narrow an internal MT to `http-.*` only. (phase 97)

    Returns a NEW list — never mutates the caller's `desired`.
    """
    import fnmatch as _fn

    # Pull config off the bouncer object. DB-driven bouncers receive their
    # full config_json kwargs in __init__; we stash filter keys on the
    # instance only if they were passed.
    origins_inc = getattr(bouncer, "origins", None) or []
    origins_exc = getattr(bouncer, "exclude_origins", None) or []
    max_entries = getattr(bouncer, "max_entries", None)
    min_reputation = getattr(bouncer, "min_reputation", None)
    source_filter = getattr(bouncer, "source_filter", None)
    scenario_filter = getattr(bouncer, "scenario_filter", None)
    if not (origins_inc or origins_exc or max_entries or min_reputation
            or source_filter or scenario_filter):
        return desired

    def _origin_ok(o: str) -> bool:
        if origins_exc and any(_fn.fnmatchcase(o, p) for p in origins_exc):
            return False
        if origins_inc and not any(_fn.fnmatchcase(o, p) for p in origins_inc):
            return False
        return True

    out = [d for d in desired if _origin_ok(d.get("origin") or "")]

    # Phase 97 — source_filter (which federation LAPIs feed this MT).
    if source_filter:
        if isinstance(source_filter, str):
            allowed_sources = {s.strip() for s in source_filter.split(",") if s.strip()}
        else:
            allowed_sources = {s.strip() for s in source_filter if isinstance(s, str) and s.strip()}
        if allowed_sources:
            out = [d for d in out
                   if (d.get("origin_source") or "") in allowed_sources]

    # Phase 97 — scenario_filter (regex against decision.scenario).
    if scenario_filter:
        import re as _re
        try:
            pat = _re.compile(scenario_filter)
            out = [d for d in out if pat.search(d.get("scenario") or "")]
        except _re.error:
            # Invalid regex — log and skip filtering rather than crash the
            # reconcile loop. Operator sees the un-filtered set; the bad
            # regex is visible on /bouncers/edit.
            log.warning("bouncer %s: invalid scenario_filter %r — ignoring",
                         getattr(bouncer, "name", "?"), scenario_filter)

    if min_reputation:
        try:
            import reputation
            qualifying = reputation.bulk_compute_for_min(int(min_reputation))
            out = [d for d in out if d.get("value") in qualifying]
        except Exception:  # noqa: BLE001
            pass  # never block reconcile on reputation failure

    if max_entries and len(out) > max_entries:
        # Sort by lapi_id DESC as a proxy for "most recently registered" —
        # higher lapi_id = newer in CrowdSec's monotonic sequence. Keep the
        # newest `max_entries` and drop the rest.
        out.sort(key=lambda d: int(d.get("lapi_id") or 0), reverse=True)
        out = out[:max_entries]
    return out


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
            # Chunk the IN(...) bind so we never exceed SQLite's
            # SQLITE_LIMIT_VARIABLE_NUMBER (32766) when the active decision
            # set is large (FireHOL/CAPI lists routinely push past it).
            for i in range(0, len(ips), 900):
                chunk = ips[i : i + 900]
                placeholders = ",".join("?" * len(chunk))
                for r in conn.execute(
                    f"SELECT ip, asn, country_code FROM geo_cache WHERE ip IN ({placeholders})",
                    chunk,
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
                # Chunk to stay under SQLite's variable limit (see geo_cache
                # query above). MAX(id) GROUP BY ip is per-ip, so batching by
                # ip preserves semantics — each chunk returns the latest status
                # for the ips it contains.
                out_ips = [d["value"] for d in out]
                for i in range(0, len(out_ips), 900):
                    chunk = out_ips[i : i + 900]
                    placeholders = ",".join("?" * len(chunk))
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
                        chunk,
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
