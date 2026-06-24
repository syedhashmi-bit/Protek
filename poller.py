"""
poller.py — multi-source LAPI poller (Arc 2 federation-ready).

Each tick iterates over every enabled+unpaused row in the `sources` table.
For each source: bootstrap on first cycle, stream deltas thereafter. The
LAPI's stream cursor is per-API-key, so each source maintains its own
position automatically — we just keep a per-source `bootstrap_done` flag
in process memory.

After every successful per-source pull we update `sources.last_pull_*` so
the federation page shows fresh stats. Per-source failures are isolated:
one bad source doesn't kill the whole cycle.

Exponential backoff (phase 9): after N consecutive failures we set
`sources.backoff_until` and skip the source until then. On recovery, we
clear backoff and emit a `lapi_down` recovery event.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import os

import notifications
import siem
from crowdsec import LAPIClient, LAPIError, MachineClient
from db import get_conn, set_setting
from federation import (Source, list_sources, record_pull, set_backoff,
                        seed_local_source)
from reconciler import run_once as reconcile_once

log = logging.getLogger("protek.poller")


class Poller:
    """Multi-source LAPI poller + reconcile driver.

    Configuration knobs (per-instance, settable from /settings):
        interval     — seconds between cycles
        dry_run      — whether the reconciler is in dry mode
        batch_cap    — max MT ops per reconcile cycle
    """

    def __init__(self, interval_sec: int = 10, dry_run: bool = True, batch_cap: int = 200):
        self.interval = max(2, int(interval_sec))
        self.dry_run = dry_run
        self.batch_cap = max(1, int(batch_cap))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

        # Per-source state (keyed by source name)
        self._bootstrap_done: dict[str, bool] = {}
        self._fail_streak: dict[str, int] = {}
        self._prev_lapi_ok: dict[str, bool] = {}

        # Aggregate state
        self._prev_active = 0
        self.last_cycle_at: str | None = None
        self.last_cycle_ok: bool = False
        self.last_error: str = ""
        self.last_active_count: int = 0
        self.cycles: int = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        seed_local_source()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="protek-poller", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ── core loop ───────────────────────────────────────────────────────────
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001
                log.exception("poller cycle crashed: %s", e)
                self.last_cycle_ok = False
                self.last_error = str(e)
            self._stop.wait(self.interval)

    def tick(self) -> None:
        started = datetime.now(timezone.utc)
        # Re-read runtime knobs from the settings table so toggles applied via
        # /settings or a direct set_setting() take effect on the next cycle,
        # not just on full process restart. .env values were the boot defaults;
        # the settings table is the runtime source of truth.
        from db import get_setting as _gs
        v = _gs("settings.dry_run")
        if v in ("0", "1"):
            self.dry_run = (v == "1")
        try:
            iv = int(_gs("settings.sync_interval_sec") or "0")
            if iv >= 2:
                self.interval = iv
        except (TypeError, ValueError):
            pass
        try:
            bc = int(_gs("settings.batch_cap") or "0")
            if bc >= 1:
                self.batch_cap = bc
        except (TypeError, ValueError):
            pass

        sources = list_sources()
        if not sources:
            self.last_cycle_ok = False
            self.last_error = "no sources configured"
            self.last_cycle_at = started.isoformat()
            return

        # Phase 88 — parallel source fetch. With N federated sources the
        # original serial loop blocked the reconcile loop on its slowest
        # source. ThreadPoolExecutor with bounded concurrency lets healthy
        # sources finish at network-latency speed instead of waiting on
        # the laggards. Cap workers at 8 so we don't open hundreds of
        # parallel HTTP connections if someone wires up an absurd
        # federation count.
        from concurrent.futures import ThreadPoolExecutor

        active = [s for s in sources if not s.paused and not _in_backoff(s)]
        any_active_source = any(not s.paused for s in sources)
        per_source_results: list[dict[str, Any]] = []
        if active:
            max_workers = min(8, len(active))
            with ThreadPoolExecutor(max_workers=max_workers,
                                     thread_name_prefix="fed-pull") as ex:
                per_source_results = list(ex.map(self._pull_source, active))
        any_ok = any(r["ok"] for r in per_source_results)

        # Aggregate counts
        self.last_active_count = _count_active()
        self.last_cycle_ok = any_ok or not any_active_source
        self.last_error = "" if any_ok else (per_source_results[-1]["error"] if per_source_results else "no sources active")
        self.cycles += 1

        # Reconcile (writes the diff across all sources to MT)
        try:
            result = reconcile_once(source="auto", dry_run=self.dry_run, batch_cap=self.batch_cap)
            set_setting("reconcile.last_at", result["started_at"])
            set_setting("reconcile.last_duration_ms", str(result["duration_ms"]))
            set_setting("reconcile.last_to_add", str(result["to_add"]))
            set_setting("reconcile.last_to_remove", str(result["to_remove"]))
            set_setting("reconcile.last_unchanged", str(result["unchanged"]))
            set_setting("reconcile.last_errors", str(result["errors"]))
            set_setting("reconcile.last_dry_run", "1" if result["dry_run"] else "0")
            set_setting("reconcile.last_notes", result.get("notes", ""))
            # Cache the owned MT address-list size so the web tier can show the
            # count without re-fetching the whole list per pageview (the cause of
            # the slow dashboard). Only persist when an MT bouncer snapshotted
            # cleanly, so a transient snapshot failure doesn't clobber it with 0.
            if result.get("mt_count_valid"):
                set_setting("mt.last_list_count", str(result["mt_list_count"]))
                set_setting("mt.last_list_count_at", datetime.now(timezone.utc).isoformat())

            # Notifications
            try:
                threshold = notifications.get_threshold("sync_threshold", 50)
                if result["to_add"] >= threshold:
                    notifications.send(
                        "sync_threshold",
                        f"Reconcile cycle proposed {result['to_add']} adds / "
                        f"{result['to_remove']} removes (threshold {threshold}). "
                        f"Mode: {'DRY-RUN' if result['dry_run'] else 'LIVE'}.",
                        subject="Sync threshold exceeded",
                    )
                if result["errors"] > 0:
                    notifications.send(
                        "sync_error",
                        f"Reconcile cycle reported {result['errors']} errors. "
                        f"Notes: {result.get('notes', '')}",
                        subject="Sync errors",
                    )
                    siem.ship("sync.error", {
                        "errors": result["errors"],
                        "to_add": result["to_add"],
                        "to_remove": result["to_remove"],
                        "notes": result.get("notes", ""),
                        "duration_ms": result.get("duration_ms"),
                    })
                delta = self.last_active_count - self._prev_active
                if delta > 0 and self._prev_active > 0:
                    notifications.send(
                        "new_ban",
                        f"{delta} new decision(s) landed. Total active: {self.last_active_count}.",
                        subject="New ban(s)",
                    )
                self._prev_active = self.last_active_count
            except Exception as e:  # noqa: BLE001
                log.debug("notification trigger swallowed: %s", e)
        except Exception as e:  # noqa: BLE001
            log.warning("reconcile cycle failed: %s", e)

        # Stamp poller.last_at AFTER reconcile so /health's staleness check
        # measures completed cycles, not just "pull started" — otherwise a
        # long reconcile (large diff or slow MT) flips /health to 503 while
        # the loop is still doing useful work.
        self.last_cycle_at = datetime.now(timezone.utc).isoformat()
        set_setting("poller.last_at", self.last_cycle_at)
        set_setting("poller.last_ok", "1" if self.last_cycle_ok else "0")
        set_setting("poller.last_error", self.last_error)
        set_setting("poller.cycles", str(self.cycles))
        set_setting("poller.active_total", str(self.last_active_count))
        set_setting("poller.interval", str(self.interval))
        set_setting("poller.source_count", str(len(sources)))

        # MT health snapshot is needed by both /health and the alerting rules
        # (mt_unreachable_2m). Run it here so it shares the poller-thread MT
        # connection budget rather than spawning per-page connect/disconnect.
        try:
            from mikrotik import MikroTik
            mt = MikroTik()
            if mt.is_configured():
                h = mt.health()
                set_setting("mt.last_status", "up" if h.get("ok") else "down")
                set_setting("mt.last_check_at", datetime.now(timezone.utc).isoformat())
                if not h.get("ok"):
                    set_setting("mt.last_error", str(h.get("error", ""))[:300])
                else:
                    set_setting("mt.last_error", "")
            else:
                set_setting("mt.last_status", "off")
        except Exception as e:  # noqa: BLE001
            log.debug("mt health snapshot swallowed: %s", e)
            set_setting("mt.last_status", "unknown")

        # Composite alerting (phase 38) — evaluates every cycle, deduped via
        # alert_states. Notifications fire only on transition.
        try:
            import alerting
            alerting.tick()
        except Exception as e:  # noqa: BLE001
            log.warning("alerting tick failed: %s", e)

        # Alerts mirror — every 6 cycles (~60s) pull recent /v1/alerts via
        # machine credential and upsert into the local `alerts` table. Gated
        # on machine creds being set (LAPI rejects /v1/alerts with bouncer
        # keys by design — see SKILL.md).
        if self.cycles % 6 == 0:
            try:
                self._mirror_alerts()
            except Exception as e:  # noqa: BLE001
                log.debug("alerts mirror swallowed: %s", e)

        # Daily digest — internally no-ops until the calendar day changes,
        # so this is cheap to call every cycle.
        try:
            import digest
            digest.maybe_fire_daily()
        except Exception as e:  # noqa: BLE001
            log.debug("digest swallowed: %s", e)

        # ASN auto-ban detector (phase 57) — every 6 cycles (~60s in
        # steady state). Cheap aggregation query; results queue in
        # asn_escalations for operator review on /intel.
        if self.cycles % 6 == 0:
            try:
                import asn_detector
                asn_detector.evaluate()
            except Exception as e:  # noqa: BLE001
                log.debug("asn_detector swallowed: %s", e)

        # Bulk intel refresh (phases 59 + 60) — Tor exit list + Spamhaus
        # DROP/EDROP. Internally no-ops until ≥20h since last refresh,
        # so this is cheap to call every cycle.
        try:
            import intel_providers
            intel_providers.maybe_refresh_bulk()
        except Exception as e:  # noqa: BLE001
            log.debug("intel_providers bulk swallowed: %s", e)

        # Honeypot target refresh (phase 61) — every 12 cycles (~2 min).
        # No-op when honeypot.enabled=0.
        if self.cycles % 12 == 0:
            try:
                import honeypot
                honeypot.refresh_targets()
            except Exception as e:  # noqa: BLE001
                log.debug("honeypot refresh swallowed: %s", e)

        # Off-box backup automation (phase 63) — checks once an hour whether a
        # daily/monthly/restore-test run is due. Cheap to call every cycle
        # because it short-circuits inside on the last-run timestamps.
        # 360 cycles ≈ 1 h at the default 10s interval.
        if self.cycles % 360 == 0:
            try:
                import backup
                backup.maybe_run_scheduled()
            except Exception as e:  # noqa: BLE001
                log.debug("backup scheduler swallowed: %s", e)

        # Synthetic ban self-test (phase 66) — verifies the full pipeline
        # (LAPI → reconcile → bouncer snapshot) every 6 hours.
        if self.cycles % 2160 == 0:
            try:
                import synthetic
                synthetic.maybe_run_scheduled()
            except Exception as e:  # noqa: BLE001
                log.debug("synthetic scheduler swallowed: %s", e)

        # Protek peer aggregation (phase 76) — pull each enabled peer's
        # tile summary every 6 cycles (~60s). No-op when no peers configured.
        if self.cycles % 6 == 0:
            try:
                import peers
                peers.maybe_run_scheduled()
            except Exception as e:  # noqa: BLE001
                log.debug("peers scheduler swallowed: %s", e)

        # DR drill reminder (phase 92) — if no successful drill in the last
        # 90 days, fire a single notification per quarter (re-armed once a
        # fresh drill completes). Cheap check: once per hour (every 360
        # cycles at 10s interval). Gated by dr_drill.reminder_enabled — off
        # by default so we don't surprise the operator.
        if self.cycles % 360 == 0:
            try:
                # NB: `get_setting` is not imported at module scope in this
                # file — early phase-92 shipped this block referencing it as
                # if it were, but the NameError was silently caught by the
                # outer except (so the reminder has never actually fired in
                # production since it shipped). Using `_gs` from the alias at
                # the top of tick() makes the block live again.
                if (_gs("dr_drill.reminder_enabled") or "0") == "1":
                    # `audit_log.created_at` was historically called `ts` in
                    # an earlier draft; the live schema uses `created_at`.
                    # SELECT against the wrong column would silently return
                    # NULL forever, defeating the reminder even after the
                    # get_setting NameError was fixed.
                    from db import get_conn
                    conn = get_conn()
                    try:
                        row = conn.execute(
                            "SELECT MAX(created_at) AS last FROM audit_log "
                            "WHERE action = 'dr.drill.completed'"
                        ).fetchone()
                    finally:
                        conn.close()
                    last_iso = row["last"] if row else None
                    days_since = 999
                    if last_iso:
                        try:
                            t = datetime.fromisoformat(
                                last_iso.replace("Z", "+00:00")
                            )
                            days_since = (datetime.now(timezone.utc) - t).days
                        except (ValueError, AttributeError):
                            pass
                    last_alerted_at = _gs("dr_drill.last_reminder_at") or ""
                    if days_since >= 90 and last_alerted_at != (last_iso or ""):
                        try:
                            notifications.send(
                                "sync_error",
                                f"DR drill overdue — {days_since} days since last "
                                f"successful drill. Run via /admin/dr-drill.",
                                subject="[Protek] DR drill overdue",
                            )
                        except Exception:  # noqa: BLE001
                            pass
                        # Re-arm on the next completion (last_iso changes)
                        set_setting("dr_drill.last_reminder_at", last_iso or "fired")
            except Exception as e:  # noqa: BLE001
                log.debug("dr drill reminder swallowed: %s", e)

        # SLO enforcement (phase 91) — periodically check whether any SLO
        # has been breached for >= grace_min. First sustained breach fires
        # a notification + SIEM event; recovery fires a second notification.
        # Edge-triggered via slo.<key>.{breach_started_at,alerted} state in
        # the settings table — no flap alerts. Every 12 cycles ≈ 2 min.
        if self.cycles % 12 == 0:
            try:
                import slo
                slo.alert_if_breached(window_hours=24)
            except Exception as e:  # noqa: BLE001
                log.debug("SLO check swallowed: %s", e)

        # WAL checkpoint (phase 64 follow-up) — Litestream v0.5 holds a WAL
        # reader continuously, which blocks SQLite's auto-checkpoint. Without
        # an explicit PASSIVE checkpoint the WAL grows unbounded (observed
        # 25 GB in ~8 h on 2026-05-25, filled the disk). PASSIVE doesn't
        # block writers or interfere with Litestream's replication — it just
        # merges whatever frames it can. Every 6 cycles ≈ 1 min.
        if self.cycles % 6 == 0:
            try:
                from db import get_conn
                conn = get_conn()
                try:
                    conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
                finally:
                    conn.close()
            except Exception as e:  # noqa: BLE001
                log.debug("wal checkpoint swallowed: %s", e)

        # Phase 93 — disk watchdog. Two ENOSPC incidents (2026-05-25 WAL,
        # 2026-05-28 Litestream LTX stage) both kept /health green while
        # SQLite went read-only underneath. Sample + edge-triggered warn/
        # critical notification, mirroring the SLO breach pattern.
        # Cadence is configurable; default every 6 cycles ≈ 60s.
        try:
            disk_every = int(_gs("disk.check_every_cycles") or "6")
        except (TypeError, ValueError):
            disk_every = 6
        if disk_every >= 1 and self.cycles % disk_every == 0:
            try:
                import disk_watchdog
                disk_watchdog.check_and_alert()
            except Exception as e:  # noqa: BLE001
                log.debug("disk watchdog swallowed: %s", e)

        # Phase 93 — litestream journal scraper. Errors like
        # `level=ERROR retention enforcement failed` are invisible to
        # systemctl is-active + /metrics; surface them as notifications.
        # Cheap (one short journalctl call); every 30 cycles ≈ 5 min.
        if self.cycles % 30 == 0:
            try:
                import litestream as _ls
                _ls.scan_journal_errors()
            except Exception as e:  # noqa: BLE001
                log.debug("litestream journal scrape swallowed: %s", e)

        # Phase 99 — SFTP destination probe. The 2026-05-28 ENOSPC #3
        # incident proved that destination disk pressure breaks
        # replication ~30 hours before the daemon's own SSH_FX_FAILURE
        # errors start appearing in the journal. This probe runs `df`
        # + a write/read/delete round-trip over the same SFTP channel
        # so destination disk-pressure surfaces in real time.
        # Cadence tunable via `litestream.probe_every_cycles`
        # (default 30 cycles ≈ 5 min, matching journal scrape).
        try:
            probe_every = int(_gs("litestream.probe_every_cycles") or "30")
        except (TypeError, ValueError):
            probe_every = 30
        if probe_every >= 1 and self.cycles % probe_every == 0:
            try:
                import litestream as _ls
                _ls.probe_replica_destination()
            except Exception as e:  # noqa: BLE001
                log.debug("litestream destination probe swallowed: %s", e)

        # Phase 93 — optional auto-rebaseline at critical. Master-gated
        # off by default; only acts when usage ≥ critical AND the local
        # LTX stage dominates /var/www/Protek/. Hourly check (360
        # cycles ≈ 1h) so we never thrash even if accidentally enabled.
        if self.cycles % 360 == 0:
            try:
                import disk_watchdog
                disk_watchdog.maybe_auto_rebaseline()
            except Exception as e:  # noqa: BLE001
                log.debug("auto-rebaseline check swallowed: %s", e)

    def _envstr(self, name: str) -> str:
        return (os.environ.get(name, "") or "").split("#", 1)[0].strip()

    def _mirror_alerts(self) -> None:
        login = self._envstr("CROWDSEC_MACHINE_LOGIN")
        password = self._envstr("CROWDSEC_MACHINE_PASSWORD")
        if not (login and password):
            return
        url = self._envstr("CROWDSEC_LAPI_URL") or "http://127.0.0.1:8080"
        # Reuse the same MachineClient across cycles so the JWT stays warm.
        if not hasattr(self, "_machine_client") or self._machine_client is None:
            self._machine_client = MachineClient(url, login, password)
        # `since=1h` keeps the query bounded — we just need fresh stuff to
        # upsert; older alerts already live in the local table.
        try:
            alerts = self._machine_client.alerts(since="1h", limit=200)
        except LAPIError as e:
            log.warning("alerts mirror: %s", e)
            self._machine_client = None  # force re-login next cycle
            return
        if not alerts:
            return
        conn = get_conn()
        try:
            for a in alerts:
                src = a.get("source") or {}
                lapi_id = a.get("id")
                if lapi_id is None:
                    continue
                conn.execute(
                    """
                    INSERT INTO alerts
                        (origin_source, lapi_id, machine_id, scenario, source_ip,
                         source_asn, source_country, events_count, created_at, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(origin_source, lapi_id) DO UPDATE SET
                        scenario       = excluded.scenario,
                        source_ip      = excluded.source_ip,
                        source_asn     = excluded.source_asn,
                        source_country = excluded.source_country,
                        events_count   = excluded.events_count
                    """,
                    (
                        "local",
                        int(lapi_id),
                        str(a.get("machine_id") or ""),
                        str(a.get("scenario") or ""),
                        str(src.get("ip") or src.get("value") or ""),
                        str(src.get("as_number") or src.get("asn") or ""),
                        str(src.get("cn") or src.get("country") or ""),
                        int(a.get("events_count") or 0),
                        str(a.get("created_at") or ""),
                        __import__("json").dumps(a, default=str)[:8000],
                    ),
                )
        finally:
            conn.close()
        log.info("alerts mirror: upserted %d", len(alerts))

    # ── per-source pull ─────────────────────────────────────────────────────
    def _pull_source(self, src: Source) -> dict[str, Any]:
        # Phase 88 — wall-clock time per source. Reported back via record_pull
        # so /federation can surface "this source took 4.5s" before it
        # noticeably bogs the global cycle.
        t0 = time.monotonic()
        client = LAPIClient(url=src.url, api_key=src.api_key, name=src.name)
        result: dict[str, Any] = {"name": src.name, "ok": False, "error": "",
                                   "count": 0, "duration_ms": 0}
        try:
            if not self._bootstrap_done.get(src.name):
                count = self._bootstrap(client)
                self._bootstrap_done[src.name] = True
            else:
                count = self._stream_apply(client)
            result["ok"] = True
            result["count"] = count
            result["duration_ms"] = int((time.monotonic() - t0) * 1000)
            record_pull(src.id, count, error="", duration_ms=result["duration_ms"])
            self._fail_streak[src.name] = 0
            # Edge-triggered recovery notification
            if not self._prev_lapi_ok.get(src.name, True):
                notifications.send(
                    "lapi_down",
                    f"Source `{src.name}` recovered ({src.url}).",
                    subject=f"Source recovered: {src.name}",
                )
                siem.ship("source.up", {"source": src.name, "url": src.url})
            self._prev_lapi_ok[src.name] = True
            # Clear backoff once we succeed
            set_backoff(src.id, None)
        except LAPIError as e:
            err = str(e)
            result["error"] = err
            result["duration_ms"] = int((time.monotonic() - t0) * 1000)
            record_pull(src.id, 0, error=err, duration_ms=result["duration_ms"])
            streak = self._fail_streak.get(src.name, 0) + 1
            self._fail_streak[src.name] = streak
            # Exponential backoff: 2^streak minutes, capped at 30
            backoff_min = min(30, 2 ** max(0, streak - 1))
            until = datetime.now(timezone.utc) + timedelta(minutes=backoff_min)
            set_backoff(src.id, until.isoformat())
            # Edge-triggered notification only on transition
            if self._prev_lapi_ok.get(src.name, True):
                notifications.send(
                    "lapi_down",
                    f"Source `{src.name}` failed: {err}. Backing off {backoff_min} min.",
                    subject=f"Source down: {src.name}",
                )
                siem.ship("source.down", {
                    "source": src.name, "url": src.url,
                    "error": err, "backoff_min": backoff_min,
                })
            self._prev_lapi_ok[src.name] = False
            log.warning("source %s failed: %s (streak=%d, backoff=%dmin)", src.name, err, streak, backoff_min)
        except Exception as e:  # noqa: BLE001
            err = str(e)
            result["error"] = err
            result["duration_ms"] = int((time.monotonic() - t0) * 1000)
            record_pull(src.id, 0, error=err, duration_ms=result["duration_ms"])
            log.exception("source %s crashed: %s", src.name, err)
        return result

    def _bootstrap(self, client: LAPIClient) -> int:
        now = datetime.now(timezone.utc).isoformat()
        decisions = client.decisions(scope="Ip") + client.decisions(scope="Range")
        log.info("bootstrap: pulled %d decisions from %s", len(decisions), client.name)
        seen_keys: set[tuple[str, int]] = set()
        conn = get_conn()
        try:
            for d in decisions:
                key = (client.name, int(d["id"]))
                seen_keys.add(key)
                _upsert_decision(conn, client.name, d, now)
            rows = conn.execute(
                "SELECT origin_source, lapi_id FROM decisions "
                "WHERE origin_source = ? AND deleted_at IS NULL",
                (client.name,),
            ).fetchall()
            for src_name, lid in ((r[0], r[1]) for r in rows):
                if (src_name, lid) not in seen_keys:
                    conn.execute(
                        "UPDATE decisions SET deleted_at = ? "
                        "WHERE origin_source = ? AND lapi_id = ?",
                        (now, src_name, lid),
                    )
            # Phase-10: per-IP source tracking — every distinct IP now seen by this source.
            for d in decisions:
                val = (d.get("value") or "").strip()
                if val:
                    conn.execute(
                        """INSERT INTO ip_sources (ip, source_name, last_seen_at)
                           VALUES (?, ?, ?)
                           ON CONFLICT(ip, source_name) DO UPDATE SET last_seen_at = excluded.last_seen_at""",
                        (val, client.name, now),
                    )
        finally:
            conn.close()
        return len(decisions)

    def _stream_apply(self, client: LAPIClient) -> int:
        delta = client.decisions_stream(startup=False)
        new = delta.get("new") or []
        deleted = delta.get("deleted") or []
        if not new and not deleted:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        conn = get_conn()
        try:
            for d in new:
                _upsert_decision(conn, client.name, d, now)
                val = (d.get("value") or "").strip()
                if val:
                    conn.execute(
                        """INSERT INTO ip_sources (ip, source_name, last_seen_at)
                           VALUES (?, ?, ?)
                           ON CONFLICT(ip, source_name) DO UPDATE SET last_seen_at = excluded.last_seen_at""",
                        (val, client.name, now),
                    )
            for d in deleted:
                lid = d.get("id")
                if lid is None:
                    continue
                conn.execute(
                    "UPDATE decisions SET deleted_at = ? "
                    "WHERE origin_source = ? AND lapi_id = ? AND deleted_at IS NULL",
                    (now, client.name, int(lid)),
                )
        finally:
            conn.close()
        log.debug("stream %s: +%d -%d", client.name, len(new), len(deleted))

        # SIEM: ship per-decision events from the stream delta only — the
        # bootstrap cycle re-seeds the local table with every active
        # decision (could be 20k+); shipping those would just be noise to
        # a downstream SIEM.
        for d in new:
            siem.ship("decision.created", {
                "ip": d.get("value"),
                "scope": d.get("scope"),
                "scenario": d.get("scenario"),
                "origin": d.get("origin"),
                "source": client.name,
                "lapi_id": d.get("id"),
                "until": d.get("until"),
                "duration": d.get("duration"),
            })
        for d in deleted:
            siem.ship("decision.deleted", {
                "ip": d.get("value"),
                "source": client.name,
                "lapi_id": d.get("id"),
            })
        return len(new) + len(deleted)


# ── helpers ─────────────────────────────────────────────────────────────────

def _in_backoff(src: Source) -> bool:
    if not src.backoff_until:
        return False
    try:
        until = datetime.fromisoformat(src.backoff_until.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False
    return until > datetime.now(timezone.utc)


def _upsert_decision(conn, origin_source: str, d: dict[str, Any], now: str) -> None:
    conn.execute(
        """
        INSERT INTO decisions
            (origin_source, lapi_id, value, scope, type, scenario, origin, duration, until,
             first_seen_at, last_seen_at, deleted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(origin_source, lapi_id) DO UPDATE SET
            value      = excluded.value,
            scope      = excluded.scope,
            type       = excluded.type,
            scenario   = excluded.scenario,
            origin     = excluded.origin,
            duration   = excluded.duration,
            until      = excluded.until,
            last_seen_at = excluded.last_seen_at,
            deleted_at = NULL
        """,
        (
            origin_source,
            int(d["id"]),
            str(d.get("value") or ""),
            str(d.get("scope") or "Ip"),
            str(d.get("type") or "ban"),
            str(d.get("scenario") or ""),
            str(d.get("origin") or ""),
            str(d.get("duration") or ""),
            d.get("until"),
            now,
            now,
        ),
    )


def _count_active() -> int:
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(DISTINCT value) AS n FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()
        return int(row["n"]) if row else 0
    finally:
        conn.close()
