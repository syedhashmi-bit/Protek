"""init_db() must survive several gunicorn workers cold-booting at once.

2026-10-15: two of three workers crashed with "duplicate column name: asn" —
the PRAGMA-check-then-ALTER migration is check-then-act, so concurrent
workers could both see the column missing. init_db() now holds a flock.
"""
from __future__ import annotations

import multiprocessing as mp
import sqlite3
from pathlib import Path


def _worker(db_path: str, barrier, results) -> None:
    import db
    db.DB_PATH = Path(db_path)
    barrier.wait()  # release every worker into init_db() together
    try:
        db.init_db()
        results.put("ok")
    except Exception as e:  # noqa: BLE001
        results.put(f"{type(e).__name__}: {e}")


def test_concurrent_cold_boot_init_db(tmp_path):
    db_path = str(tmp_path / "race.db")
    ctx = mp.get_context("fork")
    n = 6
    barrier = ctx.Barrier(n)
    results = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(db_path, barrier, results))
             for _ in range(n)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    outcomes = [results.get(timeout=5) for _ in range(n)]
    assert outcomes == ["ok"] * n, outcomes

    cols = {r[1] for r in sqlite3.connect(db_path).execute(
        "PRAGMA table_info(decisions)")}
    assert "asn" in cols
