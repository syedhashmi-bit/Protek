#!/usr/bin/env python3
"""migrate_decisions_current_state.py — one-time schema migration, 2026-10-15.

Why this exists
----------------
`decisions` was UNIQUE(origin_source, lapi_id). CrowdSec issues a fresh
lapi_id on every re-ban of the same IP+scenario, so that constraint never
deduplicated churn — every re-ban inserted a new row, forever. That is the
root cause behind the repeated WAL-runaway/disk-full incidents logged in
MEMORY.md (2026-05-25, 2026-05-28, 2026-07-26, 2026-10-15): the reconciler's
`_desired_from_db()` had to GROUP BY over millions of historical rows every
~10s cycle, holding a read snapshot open long enough that WAL checkpoints
could never complete.

The code-side fix (db.py, poller.py, app.py, synthetic.py, asn_detector.py)
changes the key to (origin_source, value, scope, scenario) and upserts on
conflict, so going forward a re-ban updates its existing row instead of
appending. This script performs the one-time data migration the live,
already-populated database needs to catch up to that: it rebuilds
`decisions` keeping only the current-state row per identity, discarding the
all-time historical churn.

This is a deliberate, operator-approved trade-off (2026-10-15): per-IP ban
history beyond "what's active right now" is not preserved in this table
after migration (SIEM already mirrors every decision.created/deleted event
in real time for anyone who needs history — see siem.py). The one UI
surface that reads multiple historical rows per IP, `intel.enrichment_for_ip`
("scenarios" list, up to 50 rows), will show far fewer entries after this —
that is expected, not a regression to chase.

Policy
------
For each (origin_source, value, scope, scenario) group:
  * If at least one row is live (deleted_at IS NULL), keep exactly one —
    the live row with the highest id (most recently touched).
  * If no row is live, the identity isn't currently active — drop the
    whole group. No tombstones survive migration.

Safety
------
  * Refuses to run while anything else holds the DB open, unless it is
    managing the service itself (same convention as drain_tombstones.py).
  * `--dry-run` reports before/after row counts and touches nothing.
  * Builds the new table alongside the old one (`decisions_new`) and only
    swaps names after the copy succeeds and an integrity check passes —
    the original `decisions` is never dropped until its replacement is
    verified.
  * Warns (does not block) if any `approval_queue` row with status='pending'
    references a `decision_id` — those ids are not preserved across this
    rebuild (same pre-existing limitation `drain_tombstones.py` documents
    for its own delete pass; there is no FK, so nothing enforces this).
  * Restores the service on any exit path.

Usage
-----
    python3 scripts/migrate_decisions_current_state.py --dry-run
    python3 scripts/migrate_decisions_current_state.py --yes
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import time

DEFAULT_DB = "/var/www/Protek/protek.db"
SERVICE = "protek"

NEW_SCHEMA = """
CREATE TABLE decisions_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    origin_source   TEXT    NOT NULL DEFAULT 'local',
    lapi_id         INTEGER NOT NULL,
    value           TEXT    NOT NULL,
    scope           TEXT    NOT NULL DEFAULT 'Ip',
    type            TEXT    NOT NULL DEFAULT 'ban',
    scenario        TEXT    DEFAULT '',
    origin          TEXT    DEFAULT '',
    duration        TEXT    DEFAULT '',
    until           TEXT    DEFAULT NULL,
    first_seen_at   TEXT    NOT NULL,
    last_seen_at    TEXT    NOT NULL,
    deleted_at      TEXT    DEFAULT NULL,
    UNIQUE (origin_source, value, scope, scenario)
)
"""

COPY_SURVIVORS = """
INSERT INTO decisions_new
    (origin_source, lapi_id, value, scope, type, scenario, origin,
     duration, until, first_seen_at, last_seen_at, deleted_at)
SELECT origin_source, lapi_id, value, scope, type, scenario, origin,
       duration, until, first_seen_at, last_seen_at, deleted_at
FROM decisions d
WHERE d.deleted_at IS NULL
  AND d.id = (
      SELECT MAX(id) FROM decisions d2
      WHERE d2.origin_source = d.origin_source AND d2.value = d.value
        AND d2.scope = d.scope AND d2.scenario = d.scenario
        AND d2.deleted_at IS NULL
  )
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_decisions_active ON decisions (deleted_at, value)",
    "CREATE INDEX IF NOT EXISTS idx_decisions_value  ON decisions (value)",
    "CREATE INDEX IF NOT EXISTS idx_decisions_scenario ON decisions (scenario)",
    "CREATE INDEX IF NOT EXISTS idx_decisions_live_scenario "
    "ON decisions (scenario) WHERE deleted_at IS NULL",
    "CREATE INDEX IF NOT EXISTS idx_decisions_live_origin "
    "ON decisions (origin_source) WHERE deleted_at IS NULL",
    "CREATE INDEX IF NOT EXISTS idx_decisions_lastseen_value "
    "ON decisions (last_seen_at, value)",
    "CREATE INDEX IF NOT EXISTS idx_decisions_lastseen_scenario "
    "ON decisions (last_seen_at, scenario)",
]


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def gb(n: float) -> str:
    return f"{n / 1024**3:.2f} GB"


def db_bytes(db: str) -> int:
    total = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            total += os.path.getsize(db + suffix)
        except OSError:
            pass
    return total


def free_gb(path: str) -> float:
    return shutil.disk_usage(os.path.dirname(path) or "/").free / 1024**3


def service_active() -> bool:
    r = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE], check=False)
    return r.returncode == 0


def service(action: str) -> None:
    log(f"systemctl {action} {SERVICE}")
    subprocess.run(["systemctl", action, SERVICE], check=True)


def db_is_held(db: str) -> bool:
    r = subprocess.run(["fuser", db], capture_output=True, check=False)
    return bool(r.stdout.strip())


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--service-control", action=argparse.BooleanOptionalAction,
                   default=True, help="stop protek for the migration and restart after")
    p.add_argument("--drop-old", action="store_true",
                   help="drop decisions_old after a verified swap (default: keep it "
                        "renamed as decisions_old for manual rollback — costs disk "
                        "until you drop it yourself with "
                        "`sqlite3 protek.db 'DROP TABLE decisions_old; VACUUM;'`)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = p.parse_args()

    if not os.path.exists(args.db):
        log(f"no such database: {args.db}")
        return 1

    size_before = db_bytes(args.db)
    log(f"database  : {args.db}")
    log(f"size      : {gb(size_before)}")
    log(f"free space: {free_gb(args.db):.1f} GB")

    ro = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    try:
        total = ro.execute("SELECT COUNT(*) FROM decisions").fetchone()[0]
        live = ro.execute(
            "SELECT COUNT(*) FROM decisions WHERE deleted_at IS NULL").fetchone()[0]
        survivors = ro.execute(
            "SELECT COUNT(*) FROM ("
            "  SELECT origin_source, value, scope, scenario FROM decisions"
            "  WHERE deleted_at IS NULL"
            "  GROUP BY origin_source, value, scope, scenario)"
        ).fetchone()[0]
        pending_refs = ro.execute(
            "SELECT COUNT(*) FROM approval_queue "
            "WHERE status = 'pending' AND decision_id IS NOT NULL"
        ).fetchone()[0]
    finally:
        ro.close()

    log(f"decisions : {total:,} total rows, {live:,} live")
    log(f"after     : {survivors:,} rows survive (one per current-state identity)")
    log(f"reduction : {total - survivors:,} rows removed "
        f"({(1 - survivors / total) * 100:.1f}% if total else 0)" if total else "n/a")
    if pending_refs:
        log(f"!! {pending_refs} pending approval_queue row(s) reference a decision_id "
            f"that will not survive this rebuild (no FK enforces this; same "
            f"pre-existing limitation as drain_tombstones.py). Not blocking.")

    if args.dry_run:
        log("dry run — nothing modified")
        return 0

    if not args.yes:
        print()
        reply = input("Proceed? This stops protek and rebuilds decisions. [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            log("aborted")
            return 1

    restart_needed = False
    if args.service_control and service_active():
        service("stop")
        restart_needed = True

    try:
        if db_is_held(args.db):
            log("!! another process still holds the database — refusing to run")
            log("   find it with: fuser -v " + args.db)
            return 1

        conn = sqlite3.connect(args.db, timeout=120.0, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout = 120000")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DROP TABLE IF EXISTS decisions_new")
            conn.execute(NEW_SCHEMA)
            conn.execute(COPY_SURVIVORS)
            new_count = conn.execute("SELECT COUNT(*) FROM decisions_new").fetchone()[0]
            conn.execute("COMMIT")
            log(f"copied {new_count:,} survivor rows into decisions_new")

            check = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                log(f"!! integrity_check on decisions_new failed: {check}")
                log("   decisions_new left in place for inspection; original "
                    "decisions table untouched.")
                return 1

            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ALTER TABLE decisions RENAME TO decisions_old")
            conn.execute("ALTER TABLE decisions_new RENAME TO decisions")
            for stmt in INDEXES:
                conn.execute(stmt)
            if args.drop_old:
                conn.execute("DROP TABLE decisions_old")
            conn.execute("COMMIT")
            log("swapped decisions_new -> decisions" +
                (", old table dropped" if args.drop_old
                 else ", old table kept as decisions_old (15.7M rows — "
                      "drop it yourself once you're confident: "
                      "sqlite3 protek.db 'DROP TABLE decisions_old; VACUUM;')"))

            check = conn.execute("PRAGMA integrity_check").fetchone()[0]
            log(f"post-swap integrity_check: {check}")

            if args.drop_old:
                size_pre_vacuum = os.path.getsize(args.db)
                need = size_pre_vacuum * 1.2 / 1024**3
                avail = free_gb(args.db)
                if avail < need:
                    log(f"skipping VACUUM — needs ~{need:.1f} GB free, have {avail:.1f} GB")
                else:
                    log(f"VACUUM (needs ~{need:.1f} GB, have {avail:.1f} GB)…")
                    conn.execute("VACUUM")
                    log("VACUUM done")
            else:
                log("skipping VACUUM — decisions_old is still present, nothing to reclaim yet")

            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    finally:
        if restart_needed:
            try:
                subprocess.run(["systemctl", "reset-failed", SERVICE], check=False)
                service("start")
            except Exception as e:  # noqa: BLE001
                log(f"!! could not restart {SERVICE}: {e}")
                log(f"   start it by hand: systemctl start {SERVICE}")

    size_after = db_bytes(args.db)
    log(f"size: {gb(size_before)} -> {gb(size_after)} "
        f"(reclaimed {gb(max(0, size_before - size_after))})")
    log(f"free space now: {free_gb(args.db):.1f} GB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
