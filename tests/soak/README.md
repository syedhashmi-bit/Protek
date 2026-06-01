# Soak harness — Arc 15 phase 90

A long-running test that drives a staging Protek instance with synthetic load
and asserts that resource usage stays bounded (RSS, open file descriptors,
SQLite WAL size, sync_event accumulation rate, error rate). The phase-90
acceptance target is a **72-hour soak with zero alerts** + statistically flat
RSS growth after the first hour.

## What it does

Three coroutines, one process:

1. **Load injector** — POSTs synthetic decisions to
   `/api/external/decisions` at a configurable rate (default 1000/min).
   Each decision has a random RFC-5737 / RFC-3849 IP so we don't spuriously
   ban real attackers. Decisions auto-expire after 5 minutes, so the active
   set stays bounded even at high injection rate.

2. **Metric sampler** — every 30 seconds, reads:
   - Protek process RSS (`/proc/<pid>/status` `VmRSS`)
   - Open file descriptors (`/proc/<pid>/fd` count)
   - SQLite WAL size (`stat protek.db-wal`)
   - sync_events row count + last cycle duration
   - mt_pushes error rate (errors per cycle, 5-min rolling)

3. **Threshold asserter** — at every sample, checks the thresholds passed on
   the CLI. On first violation, writes a structured failure record to the
   log and exits non-zero. (Designed for nightly CI on a small VPS — fail
   fast, alert loudly.)

Output is a single CSV at `tests/soak/soak-<starttime>.csv` so post-hoc
analysis (R, Python, sqlite3) can compute growth slopes.

## Running

```bash
# Smoke test — 5 minutes, very gentle load, just verify the harness works.
python tests/soak/run_soak.py \
    --duration-hours 0.083 \
    --inject-rate-per-min 60 \
    --target-url http://127.0.0.1:8090 \
    --api-token <bearer-token-from-/admin/tokens>

# Full phase-90 acceptance — 72 hours, production-like load.
python tests/soak/run_soak.py \
    --duration-hours 72 \
    --inject-rate-per-min 1000 \
    --target-url http://protek-staging.internal \
    --api-token <bearer> \
    --threshold-rss-growth-mb-per-hour 5 \
    --threshold-fds-max 500 \
    --threshold-wal-max-mb 100 \
    --threshold-error-rate-per-cycle 5
```

## Thresholds

The harness fails fast on any of:

| Flag | Default | What it catches |
|---|---|---|
| `--threshold-rss-growth-mb-per-hour` | 5  | Memory leak (>5 MB/h is a leak, not just warmup) |
| `--threshold-fds-max`               | 500 | FD leak (open sockets / files climbing) |
| `--threshold-wal-max-mb`            | 100 | WAL-truncate timer broken |
| `--threshold-error-rate-per-cycle`  | 5   | Reconcile errors creeping in |
| `--threshold-busy-events`           | 0   | SQLite lock contention |

Each threshold has the form "if last-15-min average violates, fail." Single-
sample spikes are ignored; sustained violations fail the run.

## Not a replacement for

This is a regression / leak detector for the steady-state hot loop. It is
NOT:

- A functional test (use `pytest tests/` for that)
- A correctness verifier (use phase-66 synthetic test for that)
- A performance benchmark (use `docs/perf-baseline.md` workflow for that)

## CI integration

Designed to drop into a nightly cron on a small VPS. Exit code 0 = clean,
non-zero = a threshold tripped. Operator wires the alert path themselves
(GitHub Actions slack notification, email-on-fail, etc.).
