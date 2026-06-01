# Performance Baseline

Reference numbers for a healthy Protek deployment. Compare your `/perf` and
`/metrics` output against these.

## Test environment

- Hetzner cloud `cax21` (ARM64, 4 vCPU, 8 GB RAM, Ubuntu 24.04)
- Ubuntu 24.04, Python 3.12, SQLite 3.45 (WAL mode)
- CrowdSec v1.7.7, ~19k active decisions (mostly CAPI feeds + local SSH brute-force)
- Single MikroTik RouterOS 7.22.1 target on port 8728 plaintext, ~50ms RTT
- 3 gunicorn workers, 10s reconcile interval

## Steady-state (after initial sync drained)

| Metric                                | Expected      | Where to read it          |
|---------------------------------------|---------------|---------------------------|
| Reconcile cycle duration              | < 1s p95      | `/perf` or `protek_reconcile_duration_seconds` |
| Poll lag (cycle-to-cycle)             | 10–14s p95    | `/perf` poll_freshness SLO |
| `to_add` per cycle (delta)            | 0–20          | `/api/v1/sync/status`     |
| Sync success rate                     | ≥ 99.9%       | `/perf` sync_success SLO  |
| Active SQLite WAL size                | < 5 MB        | `du -sh protek.db-wal`    |
| Resident memory (poller-owner worker) | 150–250 MB    | `ps aux | grep gunicorn`  |
| `/health` response time               | < 50ms        | `time curl /health`       |
| `/api/v1/decisions?limit=200` time    | < 100ms       | `time protekctl decisions ls --limit 200` |

## Initial sync (first deploy or fresh router)

The first ~95 cycles after flipping `dry_run=false` are dominated by serial MT
push (200 entries/cycle over a single API socket). Expect:

- Cycle duration 30–60s during this window
- `to_add` decreasing by ~200 per cycle
- ~16-60 minutes total wall-time to drain ~19k decisions, depending on router latency
- `/perf` SLO p95 will look bad during this window (sync_duration breach is expected);
  the SLO recovers as the 24h window slides past

## Hot-path optimizations baked in

- `_desired_from_db` uses `GROUP BY value, scope` + `MIN(lapi_id)` to dedup at SQL.
  Without this, community blocklists yield N×K rows where K is the number of distinct
  scenarios each IP matches (~5x amplification on a busy LAPI).
- Whitelist matching pre-fetches the rule set once outside the loop. The naive path
  was O(decisions × whitelist) DB calls; the optimized path is 1 read + O(d×w) in Python.
- The poller stamps `poller.last_at` at end-of-cycle (not start), so `/health`'s
  staleness threshold measures completed work.
- Reconcile reads the in-memory `current_mt_entries` snapshot once per cycle, then
  computes diff in pure Python. No DB roundtrips inside the diff.

## Tuning knobs

| Knob                           | Default | Effect                                                                |
|--------------------------------|---------|-----------------------------------------------------------------------|
| `SYNC_INTERVAL_SEC`            | 10      | Reconcile cadence. Lower = faster bans but more MT API load.          |
| `BATCH_CAP`                    | 200     | Max ops/cycle. Raise during initial sync if your router can handle it. |
| `GEO_CACHE_TTL_DAYS`           | 7       | How long to trust a geo lookup before re-fetching.                     |
| `settings.approval_required`   | 0       | Set 1 to route every new decision through `/approvals` first.          |
| `federation.confidence_threshold` | 1    | Require N sources to agree before mirroring (paranoid mode for community lists). |

## Known scaling ceilings

- **Decisions**: 50k+ confirmed working. Above ~100k, `_desired_from_db` p95 starts to
  climb noticeably; consider raising `BATCH_CAP` proportionally so a cycle still drains
  the diff in one pass.
- **Address-list size**: MikroTik handles 100k+ entries comfortably (hash-based lookups).
  Above 30k, the initial-sync UX gets long — split into a few smaller address-lists if
  you want faster bootstrap.
- **Federation sources**: 10+ confirmed working. Each adds one bootstrap fetch + ongoing
  stream polls; backoff isolates failing sources from the cycle.
- **API tokens**: unbounded. sha256 lookup is O(1).
- **Webhook subscribers**: ~50 confirmed working. Worker is single-threaded, so each
  delivery is serial; very chatty subscribers benefit from a narrow `event_mask`.

## Comparing to your deployment

```bash
# Quick health-check oneliner
protekctl sync status
protekctl tile
curl -s http://127.0.0.1:8090/metrics | grep -E '^protek_(reconcile_duration|poller_lag|active_decisions|push_errors)'
```

If you see numbers materially worse than the table above, check `/perf` for the
slowest recent cycles first — almost always tells you which stage is dragging.
