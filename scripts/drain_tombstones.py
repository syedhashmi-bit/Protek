#!/usr/bin/env python3
"""drain_tombstones.py — reclaim a tombstone backlog too large for retention.py.

Why this exists
---------------
2026-09-01. A restart forced a fresh LAPI bootstrap, which corrected a month of
mirror drift and tombstoned ~6.5M stale `decisions` rows in one go. Retention
started draining them in-process and the WAL went from 4.1 GB to 20.9 GB in
3.5 minutes — twice, and once to 31 GB before that. Free space fell from 37 GB
to 20 GB in a single pass.

The mechanism is not write volume on its own. SQLite can only truncate the WAL
when no reader holds an older snapshot, and the reconciler's `_desired_from_db()`
scans millions of rows for minutes at a time, so a snapshot is almost always
open. Retention supplies the volume, the long reader blocks the release, and the
WAL grows without bound. Either one alone is harmless. This is the same failure
class as the 2026-07-26 post-mortem (53 GB WAL filled the root disk and took
every app on the host down with it).

Draining with the service stopped removes the blocker entirely: no readers, so
a checkpoint after every batch always succeeds and the WAL never leaves a few MB.

Policy
------
Mirrors `retention.prune()` exactly so this does not diverge from what the app
would eventually do on its own:
  * `decisions` — only rows with `deleted_at IS NOT NULL`. Live decisions are
    never touched, regardless of count.
  * The newest `--keep` tombstones are retained (default 500_000, matching
    retention.DEFAULT_DECISIONS_TOMBSTONE_CAP).
  * Rows referenced by a *pending* `approval_queue` entry are skipped —
    `decision_id` has no FK, so nothing else would stop us orphaning one.
  * `mt_pushes` — newest `--mt-keep` retained (default 500_000).

Safety
------
  * Refuses to run while anything else holds the DB open, unless it is managing
    the service itself.
  * Restores the service on any exit path, including Ctrl-C and exceptions.
  * Aborts if free space falls below `--min-free-gb` at any batch boundary.
  * `--dry-run` reports what it would delete and touches nothing.

Usage
-----
    python3 scripts/drain_tombstones.py --dry-run
    python3 scripts/drain_tombstones.py --yes
    python3 scripts/drain_tombstones.py --yes --no-vacuum
"""
from __future__ import annotations

import argparse
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

DEFAULT_DB = "/var/www/Protek/protek.db"
DEFAULT_KEEP = 500_000          # retention.DEFAULT_DECISIONS_TOMBSTONE_CAP
DEFAULT_MT_KEEP = 500_000       # retention.DEFAULT_MT_PUSHES_CAP
DEFAULT_BATCH = 50_000
DEFAULT_MIN_FREE_GB = 5
SERVICE = "protek"

_interrupted = False


def _on_sigint(signum, frame):  # noqa: ARG001
    """Stop at the next batch boundary rather than mid-transaction."""
    global _interrupted
    _interrupted = True
    log("interrupt received — finishing current batch, then stopping cleanly")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def gb(n: float) -> str:
    return f"{n / 1024**3:.2f} GB"


def free_gb(path: str) -> float:
    return shutil.disk_usage(os.path.dirname(path) or "/").free / 1024**3


def db_bytes(db: str) -> int:
    total = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            total += os.path.getsize(db + suffix)
        except OSError:
            pass
    return total


def service_active() -> bool:
    r = subprocess.run(["systemctl", "is-active", "--quiet", SERVICE], check=False)
    return r.returncode == 0


def service(action: str) -> None:
    log(f"systemctl {action} {SERVICE}")
    subprocess.run(["systemctl", action, SERVICE], check=True)


def db_is_held(db: str) -> bool:
    """True if another process has the DB open. `fuser` is quiet when free."""
    r = subprocess.run(["fuser", db], capture_output=True, check=False)
    return bool(r.stdout.strip())


def cutoff_id(conn, table: str, cap: int, where: str = "1=1") -> int | None:
    """id of the newest row still beyond the cap — delete rows with id <= this.

    Same query retention._cutoff_id uses, so both agree on the boundary.
    """
    row = conn.execute(
        f"SELECT id FROM {table} WHERE {where} ORDER BY id DESC LIMIT 1 OFFSET ?",
        (cap,),
    ).fetchone()
    return row[0] if row else None


DECISIONS_DELETE = (
    "DELETE FROM decisions WHERE id IN ("
    "  SELECT id FROM decisions"
    "  WHERE deleted_at IS NOT NULL AND id <= ?"
    "    AND id NOT IN ("
    "      SELECT decision_id FROM approval_queue"
    "      WHERE status = 'pending' AND decision_id IS NOT NULL)"
    "  ORDER BY id LIMIT ?)"
)

MT_PUSHES_DELETE = (
    "DELETE FROM mt_pushes WHERE id IN ("
    "  SELECT id FROM mt_pushes WHERE id <= ?"
    "  ORDER BY id LIMIT ?)"
)


def drain(conn, db: str, label: str, sql: str, cutoff: int,
          batch: int, min_free: float) -> int:
    """Delete in batches, truncating the WAL after each one.

    The checkpoint is the whole point: with no readers it always succeeds, so
    the WAL is reset to zero every batch instead of growing without bound.
    """
    removed = 0
    started = time.monotonic()
    while not _interrupted:
        cur = conn.execute(sql, (cutoff, batch))
        n = cur.rowcount
        if not n:
            break
        removed += n

        # Fold this batch's frames back into the DB and reset the WAL to 0.
        busy, total, checkpointed = conn.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)"
        ).fetchone()
        if busy:
            # Should be impossible with the service stopped; means something
            # else opened the DB mid-run. Stop rather than let the WAL grow.
            log(f"  !! checkpoint blocked (busy={busy}, {total} pages) — stopping")
            break

        avail = free_gb(db)
        if avail < min_free:
            log(f"  !! free space {avail:.1f} GB below floor {min_free} GB — stopping")
            break

        rate = removed / max(time.monotonic() - started, 0.001)
        log(f"  {label}: {removed:,} deleted  ({rate:,.0f} rows/s, "
            f"wal={gb(os.path.getsize(db + '-wal')) if os.path.exists(db + '-wal') else '0'}, "
            f"free={avail:.1f} GB)")
    return removed


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--keep", type=int, default=DEFAULT_KEEP,
                   help="newest N decision tombstones to retain")
    p.add_argument("--mt-keep", type=int, default=DEFAULT_MT_KEEP,
                   help="newest N mt_pushes rows to retain")
    p.add_argument("--batch", type=int, default=DEFAULT_BATCH)
    p.add_argument("--min-free-gb", type=float, default=DEFAULT_MIN_FREE_GB,
                   help="abort if free space drops below this at a batch boundary")
    p.add_argument("--vacuum", action=argparse.BooleanOptionalAction, default=True,
                   help="VACUUM afterwards to return freed pages to the filesystem")
    p.add_argument("--service-control", action=argparse.BooleanOptionalAction,
                   default=True, help="stop protek for the drain and restart after")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    args = p.parse_args()

    if not os.path.exists(args.db):
        log(f"no such database: {args.db}")
        return 1

    signal.signal(signal.SIGINT, _on_sigint)
    signal.signal(signal.SIGTERM, _on_sigint)

    size_before = db_bytes(args.db)
    log(f"database  : {args.db}")
    log(f"size      : {gb(size_before)}")
    log(f"free space: {free_gb(args.db):.1f} GB")

    # --- survey (read-only, safe while the service runs) --------------------
    ro = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    try:
        live = ro.execute(
            "SELECT COUNT(*) FROM decisions WHERE deleted_at IS NULL").fetchone()[0]
        tombs = ro.execute(
            "SELECT COUNT(*) FROM decisions WHERE deleted_at IS NOT NULL").fetchone()[0]
        pushes = ro.execute("SELECT COUNT(*) FROM mt_pushes").fetchone()[0]
    finally:
        ro.close()

    log(f"decisions : {live:,} live (never touched), {tombs:,} tombstones")
    log(f"mt_pushes : {pushes:,} rows")
    log(f"policy    : keep newest {args.keep:,} tombstones, {args.mt_keep:,} mt_pushes")
    log(f"estimate  : ~{max(0, tombs - args.keep):,} decisions + "
        f"~{max(0, pushes - args.mt_keep):,} mt_pushes to delete")

    if args.dry_run:
        log("dry run — nothing modified")
        return 0

    if not args.yes:
        print()
        reply = input("Proceed? This stops protek and deletes rows. [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            log("aborted")
            return 1

    # --- stop the service ---------------------------------------------------
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
            # Not journal_mode: setting it needs an exclusive lock and is what
            # makes worker boot fragile (see db.py get_conn). The DB is already
            # in WAL; leave it alone.
            conn.execute("PRAGMA synchronous = NORMAL")

            t0 = time.monotonic()

            log("draining decision tombstones…")
            cut = cutoff_id(conn, "decisions", args.keep, "deleted_at IS NOT NULL")
            if cut is None:
                log("  nothing beyond the cap")
                dec_removed = 0
            else:
                dec_removed = drain(conn, args.db, "decisions", DECISIONS_DELETE,
                                    cut, args.batch, args.min_free_gb)

            log("draining mt_pushes…")
            cut = cutoff_id(conn, "mt_pushes", args.mt_keep)
            if cut is None:
                log("  nothing beyond the cap")
                mt_removed = 0
            else:
                mt_removed = drain(conn, args.db, "mt_pushes", MT_PUSHES_DELETE,
                                   cut, args.batch, args.min_free_gb)

            log(f"deleted {dec_removed:,} decisions + {mt_removed:,} mt_pushes "
                f"in {time.monotonic() - t0:.0f}s")

            # --- VACUUM ---------------------------------------------------
            # Deleting returns pages to SQLite's freelist, which stops the file
            # growing but does not shrink it. VACUUM rewrites the file, and
            # needs room for a full second copy while it does.
            if args.vacuum and not _interrupted:
                need = os.path.getsize(args.db) * 1.2 / 1024**3
                avail = free_gb(args.db)
                if avail < need:
                    log(f"skipping VACUUM — needs ~{need:.1f} GB free, have {avail:.1f} GB")
                else:
                    log(f"VACUUM (needs ~{need:.1f} GB, have {avail:.1f} GB) — this takes a while…")
                    conn.execute("VACUUM")
                    log("VACUUM done")
            elif _interrupted:
                log("skipping VACUUM — interrupted")

            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            conn.close()
    finally:
        # Always put the service back, whatever happened above.
        if restart_needed:
            try:
                # The unit may be sitting in `failed` with its restart counter
                # spent; reset-failed makes `start` reliable.
                subprocess.run(["systemctl", "reset-failed", SERVICE], check=False)
                service("start")
            except Exception as e:  # noqa: BLE001
                log(f"!! could not restart {SERVICE}: {e}")
                log(f"   start it by hand: systemctl start {SERVICE}")

    size_after = db_bytes(args.db)
    log(f"size: {gb(size_before)} -> {gb(size_after)} "
        f"(reclaimed {gb(max(0, size_before - size_after))})")
    log(f"free space now: {free_gb(args.db):.1f} GB")
    log("")
    log("re-enable retention when you are happy with the result:")
    log(f"""  sqlite3 {args.db} "INSERT INTO settings (key,value,updated_at) """
        f"""VALUES ('retention.enabled','1',datetime('now')) ON CONFLICT(key) """
        f"""DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at;" """)
    return 0


if __name__ == "__main__":
    sys.exit(main())
