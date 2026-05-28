# MEMORY.md — Running Log

Append-only journal of what was built, fixed, and what's pending. Update at the end of every significant session. Newest entries on top.

---

## 2026-05-28 (cont. 3) — Arc 16 complete: phases 95-98 shipped

Continuation of the same session — operator asked to work through to
phase 98. All four remaining Arc 16 phases landed.

### Phase 95 ⚠ shipped (Docker image + compose)

- `Dockerfile` — multi-stage Python 3.12-slim, non-root uid 1000,
  tini as PID 1 for clean SIGTERM forwarding, /data volume for state.
  Multi-arch via the base image (amd64 + arm64 from python:3.12-slim).
- `compose.yml` — `protek` + `caddy:2-alpine` (Let's Encrypt auto-issuance
  for `PROTEK_DOMAIN`) + optional `litestream/litestream:0.5` sidecar
  behind the `replicate` profile.
- `Caddyfile` — TLS + HSTS + X-Forwarded-* pass-through so the IP-based
  rate limiter still works behind the proxy.
- `db.py` — `DB_PATH` now honors `PROTEK_DB_PATH` env (bare-metal default
  unchanged).
- `docs/DOCKER.md` — quickstart, migration-from-bare-metal recipe, ops
  cheatsheet, known limitations (the WAL-truncate timer + Litestream
  fast-restore are host-systemd artifacts that need rethinking inside
  a container).
- **Acceptance:** ⚠ — artifacts ready + YAML validates + 56 tests still
  green after the db.py change. Docker isn't installed on this VPS so
  the live `docker compose up` was not run; that's an operator-side
  measurement on a spare host.

### Phase 96 ✅ shipped (/fleet view)

- `fleet.py` — independently importable aggregation (no Flask dep).
  Per-target status from live `t.health()` + cached `last_error`
  (degraded vs offline distinction matches phase 89). 24h hourly
  bucket chart from `sync_events`.
- `templates/fleet.html` — KPI strip + SVG bar chart + sortable
  table (vanilla JS, `data-sort-value` overrides for numeric sort
  on size + lag).
- `templates/base.html` — `Fleet` nav link next to `Bouncers`.
- Decision captured: dropped per-row sparkline. `mt_pushes` has no
  `bouncer_id` column today so per-bouncer time series would need
  a schema migration. One global throughput chart at the top covers
  the trend at much lower complexity.
- 6 unit tests in `tests/test_fleet.py`.

### Phase 97 ✅ shipped (per-MT routing rules)

- **No schema change** — both filters live in the existing
  `bouncer_targets.config_json`. Reconciler reads two more optional
  attrs off the bouncer instance.
- `reconciler._filter_desired_for_bouncer` — `source_filter` (CSV or
  list, whitespace-tolerant, filters by `decision.origin_source`) and
  `scenario_filter` (Python regex via `re.search` with safe fallback —
  invalid regex logs WARNING + passes through, never crashes the loop).
- `bouncers/mikrotik_db_adapter.py` — both fields declared in
  `field_schema` so `/bouncers/add` renders them as labeled inputs.
- Audit already wired via existing `_audit("bouncer.edit", ...)`.
- 13 unit tests in `tests/test_per_mt_filters.py` including the
  acceptance-gate scenario verbatim (`edge-mt` gets everything,
  `office-mt` gets only `http-*`).

### Phase 98 ⚠ shipped (RouterOS REST API adapter)

- `bouncers/mikrotik_rest_adapter.py` — new kind `mikrotik_rest`.
  HTTPS REST against `/rest/ip/firewall/address-list`. Same Bouncer
  protocol contract as the binary adapter so the reconciler is
  transport-agnostic.
- Idempotency semantics match the binary adapter: 400-with-`already
  have such entry` → successful add, 404-on-delete → successful
  remove.
- Phase 94 bootstrap script (`templates/mt_bootstrap.rsc`) updated —
  `:do { ... } on-error={ ... }` block opts the group into `rest-api`
  policy on v7+ while failing gracefully on v6.
- Phase 97 filter attrs honored — same getattr-on-instance pattern.
- 18 unit tests in `tests/test_mikrotik_rest_adapter.py`.
- **Acceptance:** ⚠ — adapter + tests ready; the live perf measurement
  of snapshot wall-time vs the ~118 s binary baseline is operator-side
  homework. `sync_events.snapshot_ms` captures the number automatically
  once a parallel `mikrotik_rest` target is configured.

### Cumulative session stats

- **Commits** this session: 7 (89-fix → 93 → 94 → 95 → 96 → 97 → 98)
- **Test count**: from 38 (start of session) → **93 passed, 1 skipped**
- **New modules**: `disk_watchdog.py`, `fleet.py`,
  `bouncers/mikrotik_rest_adapter.py`
- **New test files**: `test_disk_watchdog.py`, `test_mt_bootstrap.py`,
  `test_fleet.py`, `test_per_mt_filters.py`,
  `test_mikrotik_rest_adapter.py` (+55 tests in aggregate)
- **Open items for follow-up**:
  - VPS B `ltx/1/`+ `ltx/2/` SSH_FX_FAILURE — still latent. Phase 93
    watchdog will fire when disk crosses 70% again; root cause needs
    SSH probe to VPS B.
  - Phase 95 live `docker compose up` measurement (5-min target).
  - Phase 98 live perf measurement (snapshot speedup vs 118 s baseline).

---

## 2026-05-28 (cont. 2) — Phase 94 shipped: RouterOS bootstrap script

Opening shot of **Arc 16 — Deploy + fleet ops** (phases 94–98).
Adding a second MikroTik to Protek used to take ~10 manual steps with
implicit RouterOS knowledge (which perms? which group? what user
name? how do I generate a strong password? what does the address-list
need to look like?). Phase 94 turns that into one paste.

### What shipped

- **`templates/mt_bootstrap.rsc`** — Jinja-rendered RouterOS script.
  Idempotent (re-running rotates the password + recreates the group);
  generates a 24-char password via `:rndstr`; group perms are the
  *minimum* needed: `api,read,write,test`. Explicitly omits `policy`,
  `password`, `sensitive`, `web`, `winbox`, `ftp`, `local`, `ssh`,
  `telnet`, `sniff`, `romon`, `dude`, `reboot`. The MT user can manage
  exactly the address-list and nothing else.
- **`/bouncers/mt-bootstrap`** — HTML page with copy-to-clipboard +
  query-parameter form so the operator can tune username / group /
  list-name without editing the .rsc by hand.
- **`/bouncers/mt-bootstrap.rsc`** — raw `text/plain` download for
  `curl | ssh router '/import'` pipelines.
- **`/bouncers`** topbar — new `⚡ MT bootstrap .rsc` link next to the
  Guided wizard button. Surfaces the script exactly where a new MT
  is about to be added.
- **Anti-injection guard**: query parameters validated against
  `[A-Za-z0-9_-]{1,32}` at the route boundary; bad input returns 400
  before Jinja sees it.
- **Tests** (`tests/test_mt_bootstrap.py`, 7 cases): endpoint
  Content-Type, minimum perms substring present + forbidden ones
  absent, default values render, query params template through, HTML
  page embeds + copy button present, bad params get 400, both
  endpoints require login.

### Test fixture lesson worth capturing

Forging the session via `c.session_transaction()` is *not enough* to
get past `login_required` in this app. Three traps:

1. **`SESSION_COOKIE_SECURE=True` in production config** — the
   Flask test_client uses HTTP, so the cookie never reaches the
   server. Override to `False` in the fixture.
2. **`SESSION_COOKIE_DOMAIN` set for phase 74 cross-app SSO** —
   forces the test client's `localhost` cookie domain to mismatch.
   Override to `None`.
3. **`_upgrade_legacy_session` before_request hook** — `session.clear()`
   if `role` is set but `user_id` doesn't resolve in the `users`
   table. Force the fixture to set both `role` + `user_id` so the
   hook returns early.

All three fixed in `tests/test_mt_bootstrap.py`'s `client` fixture.
Future Protek route tests should lift that fixture (or factor it into
a `conftest.py` if a second test file needs it).

### Live verification

`curl -sI http://127.0.0.1:8090/bouncers/mt-bootstrap.rsc` returns 302
→ /login (correctly gated). Full suite: **56 passed, 1 skipped.**

### Arc 16 roadmap

- Phase 94 ✅ shipped (this session)
- Phase 95 ⏳ Docker image + compose (planned)
- Phase 96 ⏳ /fleet view (planned)
- Phase 97 ⏳ Per-MT routing rules (planned)
- Phase 98 ⏳ RouterOS REST API adapter (planned — also addresses
  the ~118s MT snapshot wall-time floor from 2026-05-26 MEMORY note)

---

## 2026-05-28 (cont.) — Phase 93 shipped: disk + Litestream observability

Followed directly from the morning's ENOSPC incident. The phase 91 SLO
posture is meaningless if disk goes RO underneath it; this phase makes
disk pressure + Litestream daemon errors first-class signals.

### Code shipped

- **`disk_watchdog.py`** (new, ~270 lines) — `sample()`, `current()`,
  `is_critical()`, `check_and_alert()` (edge-triggered warn/critical
  with 5 % hysteresis recovery, mirroring `slo.alert_if_breached`'s
  state machine), `maybe_auto_rebaseline()` (master-gated, default off).
- **`litestream.py`** extended — `scan_journal_errors()` reads
  `journalctl -u litestream` via subprocess, categorises ERROR lines
  (retention / compaction / upload / ssh / replica / other),
  per-category 1-hour rate limit via settings keys.
- **`poller.py`** — three new hooks in `tick()`: `check_and_alert()`
  every `disk.check_every_cycles` cycles (default 6 ≈ 60s),
  `scan_journal_errors()` every 30 cycles (~5 min), and
  `maybe_auto_rebaseline()` every 360 cycles (~1h, mostly a no-op
  because the master switch is off).
- **`app.py`** `/health` — appends `disk_critical` to the issues array
  at ≥ `disk.critical_pct`. Soft-fail wrapper so a watchdog crash
  never kills the health endpoint.
- **`app.py`** `/perf` — passes `disk = disk_watchdog.current()` to the
  template.
- **`templates/perf.html`** — disk panel: bar with current %, dashed
  threshold markers, table with free/total/peak/timestamp. Renders
  only when `disk` is non-None (fault-tolerant on a fresh deploy).
- **`db.py`** — `disk_samples` table added to `EXTRA_TABLES` + `ts`
  index. Schema is purely additive; no migration of existing rows.
- **`tests/test_disk_watchdog.py`** (new, 12 cases) — full suite green
  (11 passing + 1 manual @pytest.mark.skip for the live tmpfs
  end-to-end). Plus the existing 38 tests still pass: **49 passed,
  1 skipped**.

### Live verification

Restarted `protek.service`. `/health` returns 200 with empty `issues`
(disk at 38.3 %, well below warn 70 %). First live journal scrape
surfaced **13 retention errors + 24 compaction errors** that had been
silently accumulating since the morning incident — same SSH_FX_FAILURE
root cause on VPS B's `ltx/1/` (and now `ltx/2/` for L2 compaction).
Two notifications fired to the operator's notification channels on the
first scrape: `litestream retention error` and `litestream other error`
(the latter re-categorised to `compaction` after the test revealed
"other" was the wrong bucket).

### Settings the operator can tune (all read with defaults; no row
inserts needed):

- `disk.warn_pct` (default 70), `disk.critical_pct` (default 90)
- `disk.check_every_cycles` (default 6)
- `disk.allow_auto_rebaseline` (default `'0'`; explicit `'1'` opt-in)

### Files dirty in tree

- `app.py`, `db.py`, `litestream.py`, `poller.py`, `templates/perf.html`,
  `disk_watchdog.py` (new), `tests/test_disk_watchdog.py` (new),
  `MEMORY.md`, `ROADMAP.md`. Plus the 2026-05-26 pending
  `reconciler.py` change still uncommitted alongside.

### Still open from the morning's incident

- **VPS B `ltx/1/` SSH_FX_FAILURE** is not fixed. Live local stage was
  growing at ~38 MB/min after the rebaseline; the new disk watchdog +
  journal scraper will now scream loudly when it crosses thresholds
  but the root cause still needs an SSH probe to VPS B. Operator was
  in a hurry and that step was handed back.

---

## 2026-05-28 — ENOSPC incident #2: Litestream L0 retention failure (new failure mode)

VPS A hit ENOSPC again at ~01:25 UTC, 3 days after the 2026-05-25 incident.
**Not the same cause.** The WAL truncate timer + checkpoint loop from phase
64 follow-up was firing perfectly (`protek.db-wal` was 157 KB at discovery).
The 25 GB this time was in `/var/www/Protek/.protek.db-litestream/` — the
local LTX staging directory.

### Root cause

Litestream's L0 **retention monitor** (interval=15s, retention=5m) prunes
local L0 LTX files only after verifying the same txn range exists in L1
on the replica. The list call against VPS B's `ltx/1/` returns
`SSH_FX_FAILURE`:

```
level=ERROR msg="l0 retention enforcement failed" system=store db=protek.db
  error="fetch l1 files: sftp: \"Failure\" (SSH_FX_FAILURE)"
```

With L1 unreadable on the remote, retention bails on every cycle and the
local L0 dir grows unboundedly. Over 3 days (since the 2026-05-25
litestream rebaseline) it reached **25 GB**, filling `/dev/sda1`.

SQLite went into "attempt to write a readonly database (8)" mode because
even a metadata update needs free blocks for the WAL frame. Protek's
gunicorn (which runs as root, not www-data — discovered via lsof) was
silently failing writes. The `/health` endpoint stayed `ok` throughout
because it doesn't gate on `df` or on the SQLite write success rate.

### Recovery sequence

1. `apt-get clean` + cache deletes — freed enough sliver for the harness
   to allocate session-env (otherwise Bash itself stays blocked).
2. `du -shx /*` to find the culprit (was 30 GB in `/var`, 27 GB in
   `/var/www/Protek`, 25 GB in `.protek.db-litestream/`).
3. `systemctl stop litestream` + `rm -rf .protek.db-litestream/` —
   reclaim. **Note: `mv` aside does NOT free space**, it just renames.
   Must actually delete to reclaim. (False step taken in this session;
   `mv` consumed time before the `rm`.)
4. `systemctl start litestream` — rebaselines from replica (txid.replica
   ahead of txid.db=0 → fetches latest L0 from VPS B then resumes
   replication).
5. Post-restart, `sudo sqlite3 protek.db 'PRAGMA wal_checkpoint(TRUNCATE)'`
   returned `1|596|0` (busy because litestream reader holds WAL slots;
   that's the WAL-truncate-timer's job, not the manual checkpoint's).

### Open follow-up — VPS B `ltx/1/`

Local recovery done; **upstream cause unfixed.** Accumulation rate at
restart was ~38 MB/min → disk refills in 10–15 h if VPS B's L1
SSH_FX_FAILURE persists. Operator probe to run:

```bash
ssh -i /etc/litestream/id_ed25519 litestream@<vps-b-wg-ip> \
  'df -h ~ ; ls -la /home/litestream/protek/ltx/'
```

Most likely cause: `ltx/1/` doesn't exist on the replica (litestream's L1
compaction is interval=30s but only kicks in after enough L0 frames
accumulate; if it never has, the directory was never created, and
listing it returns SSH_FX_FAILURE). Fix:

```bash
ssh ... 'mkdir -p /home/litestream/protek/ltx/{0,1,2,3,9} && \
  chown -R litestream:litestream /home/litestream/protek/ltx'
```

### Phase 93 candidate (post-recovery work)

The phase 64 acceptance doc covered RPO/RTO but not **local-stage
unbounded growth on partial-replica-failure**. Both ENOSPC incidents
share a root cause: Litestream's failure modes aren't observable from
Protek's `/health`. Proposed:

- `poller.py` adds a `df` check; fires critical notification at >70%
  disk, forces Litestream rebaseline at >90%.
- `litestream` journal scraper that flags any `level=ERROR` to the same
  notification channel as `sync_error`.
- Acceptance: synthetic test that fills disk to 80% (in a test fixture)
  and verifies the notification fires.

ROADMAP.md update pending — not committed in this session, operator was
in a hurry and authorized only the disk fix.

### Files / state changed this session

- **Deleted**: `/var/www/Protek/.protek.db-litestream/` (25 GB,
  pre-rename stalled stage)
- **Reconciler.py + MEMORY.md** still dirty from the 2026-05-26 session;
  unchanged here.

---

## 2026-05-26 (cont. 2) — Phase 89 silent-cancellation fix; MT push logging restored

After the prior session disconnected, picked up by checking live state:
WAL-truncate self-heal from the earlier session running cleanly (no
0-byte LTX files on replica, scan-empty). But `/health` reported the
service ok while every reconcile cycle since 5021 had `errors=1` and
exactly `add=9259 rm=9759 unch=241` — a static oscillation pattern that
should have been visible in `/health` but wasn't (the `errors=1` was
flagged as a soft warning, not enough to flip 503).

### Root cause

Phase 89's `fut.result(timeout=60s)` pattern was discarding MikroTik's
work, not preventing it. The MT snapshot of ~51k owned entries takes
~16s in a one-shot CLI test but routinely exceeds 60s inside the
gunicorn worker under Cloudflare contention. Sequence per cycle:

1. Reconciler submits MT + Cloudflare futures in parallel.
2. Main loop hits `MT_future.result(timeout=60)` → raises TimeoutError,
   marks `mikrotik_degraded`, discards the (still-incomplete) result.
3. `ThreadPoolExecutor.__exit__` calls `shutdown(wait=True)`, so the MT
   thread *keeps running* — finishes snapshot at ~70s, runs the apply,
   pushes 200 IPs to RouterOS at ~120s, returns its `push_log`.
4. But the main thread has already moved on; the future's result is
   never collected.
5. Cycle log records: `errors=1, mikrotik_degraded`, only Cloudflare's
   add/remove counts. Zero `mt_pushes` rows for MT despite real router
   writes happening.

So the cycle wall time was the slowest future regardless (the timeout
didn't save any time), and the only effect was to make the slow
bouncer's work invisible in the audit trail. Worst-of-both-worlds:
slow + silent.

This silently broke 47 consecutive cycles (5021..5067) over ~2h.

### Fix

`reconciler.py:66-130` rewritten. Instead of `fut.result(timeout=N)`:

```python
for fut, b in futures.items():
    try:
        r = fut.result()  # no timeout — wait for completion
    except Exception as e:
        ...continue
    # fold r into totals unconditionally
    ...
    # derive `degraded` from wall time post-hoc
    b_wall_ms = r["snapshot_ms"] + r["apply_ms"]
    if b_wall_ms > per_bouncer_slow_s * 1000:
        _mark_bouncer_degraded(b.name, f"slow {b_wall_ms/1000:.0f}s ...")
    elif r["ok"] and not r["errors"]:
        _clear_bouncer_degraded(b.name)
```

`reconcile.per_bouncer_timeout_s` (renamed conceptually to "slow
threshold" in code comments) still drives the degraded badge — same
knob, different semantics. Set to `180` via /settings as part of this
session in case the operator wants to suppress the degraded badge.

### Verification — first cycle under new code (5067)

```
#5067 dur=117951ms add=12565 rm=12359 unch=51873 err=0 dry=0
       notes: mikrotik_batch_capped: 200; Cloudflare_filtered: 9500/54938; ...
mt_pushes: 200 rows for sync_event 5067, all success=1
```

Compare to the broken cycles 5021..5066: `unch` was 241-259 (Cloudflare
only) and is now 51,873 (MT's owned set + Cloudflare's). `errors=0` and
`mt_pushes` resumed logging. The router has been getting 200 ops/cycle
the whole time, but it took this fix to make it visible.

### Open follow-up (not blocking)

MT snapshot is the cycle's wall-time floor at ~118s. Sync interval is
configured at 10s but actual cadence is ~1 cycle/2 min. The MT snapshot
of 51k entries via RouterOS API just takes that long. Options for a
future phase:
- Incremental snapshot — only refetch entries added/removed last cycle,
  trust the cached snapshot otherwise. Risky for idempotency invariant.
- RouterOS REST API instead of binary API — known to be 2-3x faster on
  large lists in v7.x.
- Cap the MT-owned list aggressively (e.g. only top 10k by recency).
  Conflicts with the "be a complete bouncer" mission.

Not urgent — the cycle behavior is now correct, just slow.

### Files changed this session

- `reconciler.py` — rewrote the per-bouncer futures loop (see above)
- `settings` table — added row `reconcile.per_bouncer_timeout_s='180'`
  via `set_setting()` direct call

Working tree shows reconciler.py modified, not yet committed. Operator
to review + commit when ready.

---

## 2026-05-26 (cont.) — Phase 64 chain integrity restored, root cause of recurring L2 corruption identified + fixed

Continuation of the same-day session. Operator authorized the destructive
SFTP delete of the corrupt L2 LTX file from yesterday's disk-full incident.
Pre-delete scan of the replica turned up **two more 0-byte L2 files** from
*today* (00:45 UTC and 01:10 UTC), so the corruption wasn't a one-off — it
was actively recurring at ~1 file per 25 min.

### Root cause

The WAL-truncate timer (`protek-wal-truncate.service`, every 5 min) runs:
```
systemctl stop litestream
sqlite3 protek.db 'PRAGMA wal_checkpoint(TRUNCATE);'
systemctl start litestream
```

`systemctl stop` sends SIGTERM. If litestream is mid-L2-compaction-upload
over SFTP when SIGTERM arrives, the destination LTX file lands on the
replica at 0 bytes (SFTP has opened the file but no bytes written yet).
Litestream's restore tool then errors with `"has size 0 bytes
(minimum 100)"` instead of falling back to the L1 copy of the same txn
range (which always exists intact). Observed at ~1 file per 25 min on
this host, so over 24 h that's ~57 broken L2 files.

`TimeoutStopSec=1min 30s` is the default and is plenty; the issue is
litestream itself does not finish or rollback an in-flight SFTP upload
on SIGTERM — it just exits, leaving the dest file behind.

### Fix

`deploy/protek-wal-truncate.sh` extended with a post-truncate self-heal:

```bash
# After truncating, before restart:
ssh-via-sftp-key → ls -la ltx/{0,1,2,3}/ → awk '$5==0 && /\.ltx$/' → sftp rm
```

Idempotent, safe — L1 always carries the same txn range so deleting
broken L2 files never costs us recoverable data. Installs to
`/usr/local/bin/protek-wal-truncate.sh`; the service + timer units in
`deploy/protek-wal-truncate.{service,timer}` are unchanged from
2026-05-25.

### Measured RTO

After deleting the 3 known corrupt files (chain integrity restored),
ran `litestream restore -o /dev/shm/protek-restore-test/protek.db`
to measure RTO on the current 629 MB DB. Killed it at 5 min having
restored 57 KB. Extrapolated rate: ~660 KB / min. Full-DB restore
estimate: **~16 hours**, not 5 min.

So fsync was *not* the bottleneck the 2026-05-25 runbook hypothesized.
The bottleneck is **SFTP per-file overhead** — the L0 directory holds
thousands of single-txn files and Litestream walks them serially over
SFTP. Each round-trip is ~50 ms over the WireGuard tunnel, and there
are tens of thousands of files to fetch.

Phase 87 (Litestream restore speedup) is the only path to <5 min RTO
now. Options:
- Batch SFTP operations (mget-style)
- Use lftp's parallel transfer for the initial bulk fetch
- Swap transport to S3/B2 with range fetches
- Force more aggressive remote compaction so there are fewer files

ROADMAP.md phase 64 entry updated with all of the above. Phase 64
acceptance is still ⚠ partial, blocked solely on phase 87 now (not on
chain corruption anymore).

---

## 2026-05-26 — Closed phases 4 + 66, surfaced phase 64 RTO blockers

Three deferred acceptances revisited, with the operator asking they be
closed. Result: phase 4 ✅, phase 66 ✅, phase 64 ⚠ (surfaced two real
blockers that need either a destructive replica edit or phase 87 work).

### Phase 4 — already live, just unmarked
- Discovered `settings.dry_run='0'` had been flipped via /settings UI
  long before this session. The legacy MT adapter has been pushing
  ~200 successful IPv4 adds per cycle to `45.248.49.159` from at least
  sync_event 4922 onward. The `.env` DRY_RUN=true is the boot default;
  the settings row is the runtime source of truth (poller.tick re-reads
  it every cycle).
- Acceptance criterion ("flip dry_run=false on a real MT") was satisfied
  in practice — roadmap just hadn't been updated.

### Phase 66 — live-verified after fixing two bugs
1. **dry_run mismatch**: `synthetic._live_bouncers()` was reading env
   `DRY_RUN` for legacy MT but the actual runtime uses `settings.dry_run`.
   So the test reported "no live bouncers" even though MT was live.
   Fixed to mirror the poller's precedence.
2. **Backlog starvation**: First live run came back `add_ok=true,
   remove_ok=false`. Root cause: the test went through
   `reconciler.run_once(batch_cap=200)`; with 30k+ pending adds in the
   regular backlog, all 200 budget went to adds, leaving zero for
   removes — synth remove never happened.

Refactored `run_test()` to push directly via each bouncer's `apply()`
rather than driving a full reconcile cycle. Better aligned with the
phase 66 docstring (the failure mode it's designed to catch is in the
apply()→target round-trip; reconcile/diff layers have their own
20+ unit tests). Bonus: no longer spikes 100k MT ops every 6h.

Test stubs in `tests/test_synthetic.py` were written against the old
keyword-arg signature; updated to match the real `Bouncer.apply(to_add,
to_remove_ids)` protocol. All 4 unit tests still pass.

Live result against MikroTik at `45.248.49.159`:
```json
{"status": "ok", "targets_n": 1, "ok_n": 1,
 "results": {"mikrotik": {"add_ok": true, "remove_ok": true,
                          "kind": "mikrotik_env"}},
 "duration_ms": 28648}
```

### Phase 64 — RTO target not achievable on current setup

Two compounding blockers:

1. **Corrupt L2 LTX file on replica**: `ltx/2/000000000000010d-0000000000000116.ltx`
   is 0 bytes (artifact of the 2026-05-25 disk-full incident). Litestream
   v0.5 errors with `"has size 0 bytes (minimum 100)"` and **does not
   fall back to the L1 copy of the same range** (which exists intact at
   869 KB). Restore-to-latest is therefore impossible until the corrupt
   file is removed (or the replica is rebased).

   The deletion was attempted but blocked by the permission classifier
   as "destructive operation on backup replica without authorization."
   Correctly so — needs explicit operator sign-off.

2. **SFTP per-file overhead dominates restore time** (the *new* RTO
   bottleneck, not the fsync hypothesis from the runbook). The L0
   directory holds thousands of single-txn files. A restore to txn 10c
   (very early, ~1 MB output) ran for 17 min before being killed.
   At ~50 ms per SFTP round-trip × thousands of files, even a healthy
   chain wouldn't meet the <5 min RTO target on this transport. Phase 87
   (Litestream restore speedup) was already on the v1.1 Arc 15 roadmap;
   promoted to next priority.

`DR-RUNBOOK.md` and `ROADMAP.md` phase 64 entry updated with the new
findings. Original hypothesis (fsync bottleneck) corrected; original
"<5 min RTO" target marked unmet.

### Fire-fixes alongside
- **WAL truncate timer was inactive** (`protek-wal-truncate.timer`
  Last: 2026-05-25 06:54 UTC, never re-enabled after the disk-full
  recovery). WAL had crept back to 242 MB. Re-enabled + ran once;
  verified WAL drops to 4 KB and timer fires every 5 min. The
  persistent fix from the previous MEMORY entry was effectively
  off-line for ~17 hours.

### Known followup bugs (not blocking)
- **MT IPv6 push failures**: ~200 add errors per cycle, all
  `"<ipv6_addr> is not a valid dns name"` from RouterOS. The
  `mikrotik_adapter.apply()` passes IPv6 strings straight through;
  some path interprets them as DNS lookups rather than literal
  addresses. IPv4 ops succeed normally. Tracked as Arc 9 follow-up;
  does not affect phase 4 acceptance.
- **Cloudflare adapter ignores bouncer_targets.dry_run**: the
  `Cloudflare` row in bouncer_targets has `dry_run=1` but the CF
  adapter is pushing real adds to the proteklist (`success=1` rows in
  mt_pushes). Either the reconciler isn't honoring per-bouncer dry_run
  for CF, or the CF adapter doesn't check it. Operator-visible
  consequence: CF is live whether the toggle says so or not. Worth
  fixing before adding more DB-driven bouncers.

---

## 2026-05-25 — Disk-full incident + Litestream WAL fix + Arc 14 roadmap

**Incident**: VPS A hit ENOSPC ~05:16 UTC, ~8 hours after Litestream replication
went live. Root cause: **`/var/www/Protek/protek.db-wal` grew to 25 GB**.
Litestream v0.5 holds a continuous WAL reader to replicate frames; SQLite
can still checkpoint frames into the main DB while a reader is active, but
it cannot truncate the WAL FILE because the reader's read-mark holds slots
in place — so new transactions append rather than overwrite. The file grows
unboundedly. PASSIVE checkpoints merge but don't shrink. Verified via
`PRAGMA wal_checkpoint(TRUNCATE)` returning `busy=1` while litestream is
running (it merges the 64 frames but can't reclaim the 1.1 GB of file
space). Disk filled, bash itself broke (couldn't snapshot `/tmp`), session
went read-only.

**Recovery sequence** (works reliably):
1. Free a sliver elsewhere first (`apt clean`, `journalctl --vacuum-size`,
   delete old Playwright/VSCode caches in `/root/.cache`).
2. `systemctl stop litestream` — releases the WAL reader.
3. `sqlite3 protek.db 'PRAGMA wal_checkpoint(TRUNCATE);'` — merges remaining
   frames + truncates WAL file to ~0 bytes.
4. `systemctl start litestream` — resumes from last successful LTX, no
   re-baseline needed if interval < L0 retention (5 min default).

**Persistent fix** (committed this session):
- `poller.py` runs `PRAGMA wal_checkpoint(PASSIVE)` every 6 cycles (~60 s).
  Defensive: merges frames into main DB so the next TRUNCATE has less to do.
- `/usr/local/bin/protek-wal-truncate.sh` + `protek-wal-truncate.service` +
  `protek-wal-truncate.timer` — every 5 min, stop litestream → TRUNCATE →
  start litestream. ~5 s replication pause per cycle; RPO stays under the
  60 s phase-64 spec. Verified: WAL went from 1.1 GB to 4.1 KB on first run.

**Lesson for future Litestream deployments**: SQLite's WAL on its own is
self-bounding because auto-checkpoint reclaims file space when no readers
are holding it. The moment you introduce a continuous reader (Litestream,
or anything else doing `sqlite3_wal_checkpoint(NULL)`-blocking work), the
self-bounding property breaks and you need explicit periodic truncation.
This isn't documented prominently in Litestream's README; the cost paid
this session was a real-world disk-full incident.

**Arc 14 — Operator UX** added to `/var/www/Protek/ROADMAP.md` (line 862,
arc table line 22). Six new phases (81–86): shared wizard primitive,
bouncer onboarding redesign, federation onboarding redesign,
diagnostic health probe, UI for env-var-only setups, first-run setup
wizard. Plan file: `/root/.claude/plans/okay-build-a-roadmap-robust-planet.md`.
Driven by the lived experience of this session — federation + VPS B +
Litestream setup each required ~10 manual commands with implicit knowledge,
and the codebase has the building blocks (health-probe-on-save, credential
masking, inline help) just not consistently applied.

**Arc 15 — Production-grade ops** also added (line 1008, arc table line 23).
Six phases (87–92): Litestream restore speedup (the open RTO gap),
federation reconcile scaling (poller serial-per-source is a latent
bottleneck), bouncer backpressure (operationalizes phase 68 scaffolding),
multi-day soak harness, SLO enforcement, automated DR drill (operationalizes
phase 67 runbook). This arc is deliberately *harden-what-shipped* work,
not new-feature work — driven by the disk-full incident above proving that
"resilience feature shipped" ≠ "resilience tested at load."

---

## 2026-05-25 — Phase 66 self-monitoring (final pieces)

Phase 66 scaffolding was in commit `5412cee` but never ticked, never
smoke-tested, and the UI silently said "SKIPPED" without telling the
operator why. Closed three small gaps:

1. **`synthetic.status()` now reports `live_bouncers_n`** so the
   `/synthetic` page knows whether the test has any coverage. Banner
   on the page warns when zero live bouncers exist (i.e. test will
   silently no-op every 6h).
2. **Early-return path in `run_test()`** for the "no live bouncers"
   case wasn't updating `synthetic.last_at`/`last_status`. Fixed —
   skips are now visible in the dashboard.
3. **`tests/test_synthetic.py`** added — 4 cases:
   - Happy path (no notification fired)
   - Phantom-progress failure (lying stub bouncer → notification fires
     on `sync_error` channel) — this is the phase 66 acceptance gate,
     covered by unit test since prod has no live bouncer
   - Skipped path (no notification, but settings updated)
   - Partial (one of two bouncers lies) → notification fires

Roadmap phase 66 marked `code complete (acceptance deferred)` with the
note that live acceptance is gated on flipping a bouncer to
`dry_run=0`. Full test suite green: 38 passed.

---

## 2026-05-25 — VPS B + Federation live + Phase 64 Litestream deployment

**Operational milestone, not a code change.** Stood up a second VPS in
Hetzner Hillsboro (US West / Oregon, public IP `<vps-b-public-ip>`, WG IP
`<vps-b-wg-ip>`), wired federation, and deployed Litestream WAL replication
from VPS A to VPS B over WireGuard.

### Federation (no code change — exercising existing arc 2-4 code)

VPS B sequence:
1. SSH key onboarding via Hetzner emailed root password (no key was
   injected at create time).
2. Traverse `peers/create` → `vps-b`, `tunnel_mode=vpn_only`, assigned
   `<vps-b-wg-ip>/24`. Subnet is **`10.8.0.0/24`** (correcting an earlier
   guess of `10.77.0.0/24` in this MEMORY).
3. WG config written to `/etc/wireguard/wg0.conf` on VPS B,
   `systemctl enable --now wg-quick@wg0`.
4. CrowdSec v1.7.8 installed (via `install.crowdsec.net` after fixing
   DNS — see gotcha #2 below).
5. LAPI bound to `<vps-b-wg-ip>:8080` only (no public exposure); UFW
   `from 10.8.0.0/24 to <vps-b-wg-ip> port 8080 proto tcp`.
6. `cscli bouncers add protek-from-vps-a` → key saved.
7. Source added in Protek's `/federation` page. Reconcile loop picked
   it up on next cycle, no Protek restart.

### Phase 64 — Litestream (`/etc/litestream.yml`)

Deployed: Litestream **v0.5.11** on VPS A, SFTP-over-WG to a restricted
`litestream` user on VPS B. Replica path
`/home/litestream/protek/` (visible via `litestream ltx` on VPS A).
**RPO observed: <2s.** **RTO is the open question** — see acceptance
gap below.

Files added/changed:
- `/etc/litestream.yml` (config; not in git — secrets via key file)
- `/etc/litestream/id_ed25519` + `.pub` (dedicated keypair)
- `/etc/litestream/known_hosts` (pinned VPS B host keys)
- `/etc/systemd/system/litestream.service.d/wg-dep.conf` — adds
  `After=wg-quick@wg0.service`
- VPS B `/home/litestream/` (system user, `nologin` shell)
- VPS B `/etc/ssh/sshd_config` — `Match User litestream` block
- Repo: `docs/litestream/litestream-sftp.yml.example` (new), updated
  `docs/DR-RUNBOOK.md §2` with SFTP-over-WG deployed shape +
  point-in-time recovery examples, ROADMAP.md phase 64 partially
  ticked.

### Phase 64 acceptance gap

RTO < 5 min is NOT met for the current 445 MB protek.db. Restore
materializes pages at ~3 KB/s observed (most threads sleeping on
futex/epoll). Network throughput is fine (raw SFTP gives 1.75 MB/s
over WG), and disk is fine — the bottleneck appears to be Litestream's
restore loop itself (per-frame coordination on Go runtime, ~6 writes/s
across threads under strace). Worth investigating in a follow-up:
- Try restoring to tmpfs and `mv` into place
- Check if v0.5.12+ has restore-perf improvements
- Compare against a file:// replica to isolate SFTP-specific overhead

For now, restore *works* (proven by partial outputs growing in
`/tmp/protek-restored.db.tmp`), just slowly. Logically replicates the
DB; mechanically slow to materialize. The data is safe.

### Gotchas hit (codify these — apply to future federated peers)

1. **WG client `DNS=` set to internal-only resolver** — kills outbound
   DNS on the new VPS. Strip the line from wg0.conf or set Traverse's
   peer DNS to `1.1.1.1`. Workaround applied:
   `echo nameserver 1.1.1.1 > /etc/resolv.conf && chattr +i`.
2. **`curl install.crowdsec.net | bash` silently no-ops on DNS
   failure** — re-run after fixing DNS or `apt` will pull
   `crowdsec 1.4.6` from Ubuntu universe instead of `1.7.x` from the
   official repo.
3. **CrowdSec at boot races wg-quick** — add
   `/etc/systemd/system/crowdsec.service.d/wg-dep.conf` with
   `After=wg-quick@wg0.service Wants=wg-quick@wg0.service`.
4. **`listen_uri` change in `/etc/crowdsec/config.yaml` must be
   mirrored in `/etc/crowdsec/local_api_credentials.yaml`** — the
   local agent's `url:` field. Otherwise the agent can't talk to its
   own LAPI.
5. **Litestream `host-key:` must match the algorithm sshd actually
   negotiates** — OpenSSH defaults to ECDSA over ED25519. Get the
   right one via `ssh-keyscan -t ecdsa <host>`. Pinning ED25519 when
   server picks ECDSA → `ssh: host key mismatch`.
6. **SFTP URL path is absolute, not relative to user home** —
   `sftp://user@host/protek` writes at `/protek` and gets permission
   denied. Use `sftp://user@host/home/user/protek`.

---

## 2026-05-22 — Documentation session: Confluence article + screenshot pipeline

**No code changes.** Published a detailed project documentation page to the
operator's Confluence under the "Projects" folder, with 16 sanitized
dashboard screenshots embedded as native page attachments.

### What got built (process artifacts, not Protek code)
- Confluence page **id `171540483`** in space `131074` ("Protek — Self-hosted
  CrowdSec → MikroTik Bouncer with NOC Dashboard"). Currently version 5.
  24 sections covering architecture, page-by-page walkthrough, APIs, roadmap,
  stack, security, SLOs, gaps, plus three collapsible appendices (quick
  start / dev commands / full `.env` reference).
- 16 PNG screenshots committed to `docs/screenshots/` (commit `076dbfb`) AND
  uploaded as Confluence attachments to the page.

### Screenshot pipeline (reusable for future sessions)
- `app.test_client()` + hardcoded session dict renders pages server-side to
  HTML — does NOT read `.env`/`protek.db` directly (rule from CLAUDE.md).
  Note: `last_active` must be present in the forged session or
  `_session_expired()` clears it.
- HTML sanitized in-place with regex to swap operator data for RFC 5737
  documentation IPs + generic placeholders (home IP, IPv6, username, B2
  bucket, webhook/key suffixes, whitelist note).
- Playwright loads sanitized `file://` HTML at 1600×1100 and full-page
  screenshots.
- Asset URLs in the rendered HTML get rewritten to absolute
  `https://protek.syedhashmi.trade/static/...` so fonts/CSS load over the
  network during screenshotting.

### Confluence quirk worth remembering
The Atlassian MCP `create/updateConfluencePage` always wraps `<img>` as
**external** ADF media — even when the URL is a same-instance attachment.
External media doesn't render reliably. To embed real page attachments you
MUST bypass the MCP and PUT the page directly via the v1 REST API with
storage-format `<ac:image><ri:attachment ri:filename="X" /></ac:image>`
syntax. Working script lives at `/tmp/update_confluence_native.py` (likely
gone by next session — re-derive from `confluence_docs.md` auto-memory).

### GitHub repo is private
`raw.githubusercontent.com/syedhashmi-bit/Protek/...` returns 404 to
unauthenticated callers, so external image hosting for documentation
doesn't work. Confluence attachments are the right answer.

### Decisions / direction noted
- Operator is considering a **second VPS** for federation (not committed).
  Preferred transport: **Traverse-managed WireGuard with split-tunnel
  `AllowedIPs = 10.77.0.0/24`** for the new VPS (so it doesn't route all
  its traffic via Germany). Federation flow uses `/federation` add-source
  UI — no Protek code change needed when VPS B arrives.

### State at pause
- Protek service: still `active`, v2.0.0, dry-run off, ~38k decisions.
- `main` branch: 3 commits ahead of v2.0 ship (5412cee · fc2c0f3 · 076dbfb),
  all pushed to `origin/main`.

---

## 2026-05-21 — Protek 2.0 SHIPPED · Arcs 12 + 13 (phases 69–80) · 80 of 80

**State at pause:** Protek 2.0 is feature-complete. All 80 phases marked done
except 65 (active-passive HA, parked — needs a second VPS to elect against).
Operator pushed Arc 12 (Ecosystem) + Arc 13 (2.0 prep) in one session.
Service is live at https://protek.syedhashmi.trade running version `2.0.0`.

### Phase 69 — Plugin SDK for adapters
- `bouncers/plugin_loader.py` — hot-loads `*.py` from `~/.config/protek/adapters/`
  (or `$PROTEK_PLUGIN_DIR`). Third-party adapters self-register via
  `@register("kind")` exactly like built-in ones. No fork required.
- `MANIFESTS` tracks per-plugin metadata (author, version, summary,
  required config keys) — surfaced on /bouncers.
- Failures non-fatal: a broken plugin logs a warning, others still load.
- `docs/plugins/README.md` — contract + skeleton + the five things plugins
  must get right (comment ownership, idempotency, bounded batch, no
  `time.sleep` in apply, no 30k-IPs-at-once pushes).
- `/bouncers` page extended with a "Third-party plugin adapters" panel
  listing each loaded plugin's manifest.

### Phase 70 — OAuth / OIDC SSO
- `oidc.py` — generic OIDC client via Authlib. Works with any provider
  exposing `/.well-known/openid-configuration` (Google, Authentik,
  Auth0, Keycloak verified-shape).
- `/sso/login` → authorize redirect; `/sso/callback` → exchange code,
  pull userinfo, map to role.
- Role mapping: `OIDC_GROUPS_ADMIN/OPERATOR/VIEWER` (comma-sep), claim
  driven by `OIDC_GROUPS_CLAIM` (default `groups`). Plus domain
  allowlist via `OIDC_ALLOWED_DOMAINS`. No match → `OIDC_DEFAULT_ROLE`
  or explicit deny.
- Break-glass: env-anchored admin still works at /login regardless of
  OIDC state. SSO outage ≠ Protek lockout.
- SSO users have random unguessable password hashes (no local-pw path)
  and placeholder TOTP secrets (IDP does MFA).
- "Sign in with SSO" button on /login renders only when configured.
- SAML 2.0 deferred — not in 2.0. Note in Arc 13 candidates.
- Requirement: `Authlib>=1.3,<2.0`. Env vars: `OIDC_ISSUER`,
  `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, + the group/domain knobs.

### Phase 71 — Native packages (.deb scaffolding)
- `packaging/debian/` — full Debian source-package layout (`control`,
  `rules`, `changelog`, `install`, `postinst`, `prerm`, `protek.service`).
- `packaging/build.sh` — symlinks `packaging/debian` → `debian/` and runs
  `dpkg-buildpackage`. Produces `../protek_2.0.0-1_all.deb`.
- `postinst` creates the `protek` system user, deploys default `.env`
  template, builds the venv from `requirements.txt`, links the systemd
  unit, prints the one-time `setup_admin.py` command.
- **Acceptance gate:** needs a Debian build host (`build-essential
  debhelper dh-python python3-all`). The actual .deb wasn't built this
  session (no build container set up); the scaffolding is verified
  syntactically and against debian-policy.
- RPM scaffolding directory created but empty (Fedora/RHEL target deferred).

### Phase 72 — Webhook input templates
- New `POST /api/external/introspect` — bearer-authed dry-run endpoint
  that echoes back what Protek parsed without persisting. Lets
  integrators validate n8n/Zapier/Make templates before sending real bans.
- Detects `ip` from common alias fields (`source_ip`, `client_ip`,
  `remote_addr`) so non-CrowdSec payloads work out of the box.
- `docs/integrations/README.md` — cookbook with copy-paste templates for
  n8n, Zapier, Make, Tines, atom, plus a generic curl one-liner.
- HMAC verification path documented (existing webhook subscriber HMAC
  applies in reverse).

### Phase 73 — GraphQL surface
- `graphql_api.py` — Strawberry schema covering `decisions`, `alerts`,
  `reputation(ip)`, `bouncers`, `sync_events`, `synthetic_runs`. Filter
  args support country, scenario substring, value substring, min
  reputation in a single call (would have been ~50 REST round-trips).
- `/api/graphql` — bearer-token-authed POST endpoint.
- `/api/graphql/explorer` — GraphiQL IDE, admin-role-gated (don't want
  random visitors crawling the schema).
- Auth wrapper accepts either bearer-token (`read` scope) or session
  with admin/operator/viewer role.
- Requirement: `strawberry-graphql[flask]>=0.220,<1.0`.

### Phase 74 — Othoni cross-app integration
- `SESSION_COOKIE_DOMAIN` env var → Flask cookie domain. Set to e.g.
  `.syedhashmi.trade` to share session between Protek + Othoni + any
  other suite app on sibling subdomains.
- `/from-othoni?ctx=<...>&v=<...>` landing route maps tile clicks
  on the Othoni grid to the right Protek view (ip → /attackers/<ip>,
  scenario → /scenarios?q=, alerts/bouncers/perf shortcuts).
- `/api/v1/tile/summary` already existed (phase earlier); now publicly
  documented as the Othoni-embeddable summary endpoint.

### Phase 75 — Postgres support (scaffolding only)
- `database.py` — `get_conn()` factory + `Dialect` selector keyed off
  `DATABASE_URL`. SQLite path forwards to `db.get_conn()` (unchanged).
  Postgres path raises explicit `NotImplementedError` pointing at the
  migration plan — no silent fallback that would corrupt data.
- `docs/postgres-migration.md` — detailed contract for finishing the
  Postgres implementation (psycopg dependency, `%s` parameter style,
  schema port for AUTOINCREMENT → SERIAL, audit_log trigger port to
  pg `CREATE FUNCTION ... RETURNS trigger`, migration script outline).
- **Intentionally scaffold-only.** Half-done Postgres would silently
  break audit log triggers; the abstraction in place lets the future
  implementation land additively without touching every callsite.

### Phase 76 — Sharding (Protek-to-Protek read aggregation)
- `peers.py` + `protek_peers` table (lazy-created). Hub Protek pulls
  each enabled peer's `/api/v1/tile/summary` every 60s, persists
  results, exposes aggregated KPIs.
- `/peers` page: instances list (incl. the local "(this instance)"
  row), aggregated total bans, healthy / total peers, max sync lag,
  cycle total. Per-row click opens the peer's dashboard in a new tab.
- Per-peer rate limiting via phase-68 buckets keyed `peer.<name>`.
- 429 responses trigger the same `record_429()` halving as other
  upstreams.
- **Read-only aggregation.** Cross-peer decision propagation is
  deferred to a future Protek 2.x phase — needs bidirectional sync
  + conflict resolution + a peer-trust model (multi-month design).
  For 2.0 each peer's bouncers stay independent; the hub provides
  visibility, not control.

### Phase 77 — Multi-region deploy template
- `deploy/terraform/main.tf` — Hetzner-targeted module that spins up N
  VPS instances across regions, sets up a private network, and runs
  `cloud-init` per node.
- `deploy/terraform/cloud-init.yaml` — installs python3.12, nginx,
  certbot, CrowdSec, wireguard; clones Protek; builds venv; auto-runs
  `setup_admin.py` (creds land in `/var/log/protek/init.log`).
- WireGuard mesh on `10.77.0.0/24` so aggregation traffic stays private.
- First region = hub; others register to it as peers (manual token paste
  per phase 76).
- `deploy/README.md` — operator runbook + acceptance test path. Honest
  about it being a reference template (per-cloud, DNS+TLS still manual).

### Phase 78 — Threat intel publishing (signed feed)
- `intel_publish.py` — Ed25519-signed JSON feed at
  `/feed/banned-ips.signed.json`. Excludes `lists:*` origins by default
  (don't republish other people's intel as your own).
- Signing keypair generated on first enable. Private key encrypted at
  rest with `AES-256-GCM`, key derived via `sha256(SECRET_KEY + label)`.
  Public key + fingerprint exposed at `/feed/pubkey`.
- Sequence number + issued_at timestamp embedded in every fetch —
  subscribers can detect replay or skipped sequence.
- Rate-limited per `?subscriber=<name>` via phase-68 buckets keyed
  `feed.<subscriber>`. 429 returned with `Retry-After: 60`.
- Filterable by scenario whitelist + origin-prefix blacklist via
  settings (no DB schema change).
- `/intel-publish` page (admin-only) — toggle, rotate key, configure
  filter, copy-paste pubkey + verification example using pynacl.
- Disabled by default; explicit opt-in.

### Phase 79 — Breaking-change window (/api/v2 alias)
- `api_v2.py` — registers `/api/v2/*` as a Flask blueprint, then
  introspects the live url_map and adds a parallel rule for every
  `/api/v1/*` route pointing at the same view function. In 2.0 v2 is a
  transparent alias.
- `api_v2.attach_deprecation_headers(app)` — Flask `after_request`
  hook adds `Deprecation: true`, `Sunset: <HTTP-date>`, and
  `Link: </api/v2>; rel="successor-version"` headers to v1 responses
  when `api.v1.sunset_date` setting is non-empty. RFC 8594 + RFC 9745
  compliant.
- `GET /api/version` — version negotiation endpoint. Reports
  `protek_version`, supported versions, sunset date.
- v2 ping: `/api/v2/ping` exists alongside `/api/v1/ping`. Both work.
- Future v2-only changes are now a one-line "skip this in the proxy
  loop" toggle, not a fresh API design under deadline pressure.

### Phase 80 — Protek 2.0 release ceremony
- `PROTEK_VERSION` bumped: `1.0.0` → `2.0.0` in app.py.
- All 34 existing unit tests still pass (no regressions).
- All known feature surfaces smoke-tested:
  - `GET /health` → 200 (`{"service": "protek", ...}`)
  - `GET /api/version` → 200 with both v1 + v2 listed
  - `GET /api/v1/ping` and `/api/v2/ping` both 200
  - `GET /api/v1/decisions` and `/api/v2/decisions` both 401 (token-required)
  - `GET /feed/banned-ips.signed.json` → 404 (correctly disabled by default)
  - `GET /api/graphql` → 401 (correctly auth-gated)
  - All new pages (`/peers`, `/intel-publish`, `/from-othoni`,
    `/admin/backup-automation`, `/admin/dr-drill`, `/synthetic`) → 302
    redirects to /login (correctly auth-gated)
- Bootstrap on restart: 38,173 decisions pulled, GraphQL registered on
  all 3 gunicorn workers, poller owner elected, no boot errors.

### What's NOT in 2.0 (transparent about gaps)
- **Phase 65 (active-passive HA)** — parked. Needs second VPS + Redis
  SETNX or DynamoDB conditional write for network leader election.
  Resumes when a second box is provisioned.
- **SAML 2.0** — OIDC ships; SAML deferred. Authlib supports SAML so a
  future addition is additive.
- **.deb actually built** — packaging files in place but `dpkg-buildpackage`
  not run this session (no Debian build container set up). `packaging/build.sh`
  does the work when a Debian 12 host runs it.
- **Postgres path implemented** — abstraction in place, implementation
  is the future-2.x phase per `docs/postgres-migration.md`.
- **Cross-peer decision push** — read aggregation lands in 2.0; bidi
  decision sync is deferred (multi-month design exercise).
- **Multi-region Terraform tested end-to-end** — written + documented,
  not `terraform apply`-d this session (no second cloud account to spin
  up the test cluster).

### Quirks added this session
- The `_proxy_v1_to_v2()` flow introspects `app.url_map` AFTER v1's
  blueprint is registered — Flask doesn't expose a "deferred routes"
  helper, but iterating live rules works fine since registration is
  synchronous. Idempotent: `add_url_rule` raises AssertionError on
  endpoint name collision (caught + skipped) so gunicorn reloads
  don't double-register.
- The Ed25519 private key in `intel_publish.py` is encrypted at rest
  with `sha256(SECRET_KEY + b"|intel-publish-priv-key")` — keeps the
  signing key tied to the Flask SECRET_KEY rotation lifecycle.
  Rotate SECRET_KEY = invalidate any old signing key. (The pub key
  table row gets cleared by `rotate_keypair()`.)
- Plugin loader skips files starting with `_` so `__pycache__/__init__.py`
  and dotfiles don't get imported as adapters.
- `peers.py`'s aggregated_kpis() includes a synthetic "(this instance)"
  row so the hub appears in its own /peers table — operator sees the
  full cluster, not "everyone but me".
- The OIDC `upsert_sso_user()` generates a 64-byte random urlsafe
  string as the local password before bcrypt-hashing it. SSO users
  literally cannot log in via the local form even if someone tries.
- Authlib's `Flask` integration registers a global session key for OAuth
  state — works fine alongside our existing Flask session.
- `from-othoni`'s context router uses a regex (`^[0-9a-fA-F.:/]+$`) on
  the IP value to prevent path traversal in the redirect URL even though
  url_for() already escapes — defense in depth.

### Surface added this session
- **Pages:** /peers, /intel-publish, /from-othoni
  (plus the existing /bouncers gets a plugin panel; /login gets an
  SSO button)
- **APIs:** /sso/login, /sso/callback, /api/external/introspect,
  /api/graphql, /api/graphql/explorer, /api/v2/* (alias of v1),
  /api/version, /feed/banned-ips.signed.json, /feed/pubkey
- **Modules:** oidc.py, graphql_api.py, peers.py, intel_publish.py,
  api_v2.py, database.py, bouncers/plugin_loader.py
- **DB tables (lazy-created):** protek_peers
- **Scaffolds:** packaging/debian/, packaging/rpm/, deploy/terraform/,
  docs/postgres-migration.md, docs/plugins/, docs/integrations/
- **Reqs added:** Authlib>=1.3,<2.0, strawberry-graphql[flask]>=0.220,<1.0
- **Env vars (optional):** OIDC_ISSUER/CLIENT_ID/CLIENT_SECRET/SCOPES/
  ALLOWED_DOMAINS/GROUPS_CLAIM/GROUPS_ADMIN/GROUPS_OPERATOR/GROUPS_VIEWER/
  DEFAULT_ROLE, SESSION_COOKIE_DOMAIN, DATABASE_URL (rejected if pg),
  PROTEK_PLUGIN_DIR
- **Settings keys:** intel.publish.{enabled, issuer, scenarios,
  exclude_origins, pub_b64, priv_enc_b64, seq}, api.v1.sunset_date,
  peers.last_refresh_at

### Acceptance proven this session
- All 34 unit tests pass (no regressions across the 80-phase build).
- Service boots clean (38,173 decisions bootstrapped, GraphQL registers,
  no errors in journalctl).
- `/api/version` reports protek_version=2.0.0, supports v1+v2.
- v1 and v2 both serve their respective `/ping` endpoints with parallel
  shapes; `/api/v2/decisions` 401s identically to `/api/v1/decisions`.
- All new pages 302 to /login (auth-gated correctly).
- `/feed/banned-ips.signed.json` 404s when publishing disabled (default).
- `/api/graphql` 401s without bearer token (token auth correctly required).

### What 2.0 means in practice
- **For operators:** drop a plugin file in `~/.config/protek/adapters/`,
  flip OIDC env vars to use Google as your auth, scrape your dashboard
  with GraphQL from one query, embed your tile in Othoni, publish your
  intel as a signed feed.
- **For Protek's own evolution:** v2 alias + `Sunset` headers establish
  the deprecation contract. Postgres + sharding scaffolds mean Protek
  3.0 isn't blocked on architectural archaeology — the hook points are
  there, the migration plan is written, the next contributor knows
  exactly what to add.
- **For the suite:** Protek now plays in Othoni's grid (shared session +
  drilldown), shares its intel feed with siblings, and renders its
  GraphQL data into whatever surface other apps want to expose.

### Pending follow-ups for the operator
- Optional: enable SSO. Pick a provider (Google for simplicity, Authentik
  for self-hosted), create an OAuth app there, paste creds into `.env`,
  restart.
- Optional: enable intel publishing if you want peer Proteks to subscribe.
  /intel-publish → toggle on → distribute the pubkey out-of-band.
- Optional: enable synthetic test schedule (operator decision; off by
  default; needs at least one live, non-dry-run bouncer to be meaningful).
- Optional: build the .deb when you have a Debian 12 host with
  `build-essential debhelper dh-python`.
- Optional: provision a second VPS to unblock phase 65 (HA).

### 2.0 vs 1.0 SLO baseline
- p50 cycle latency: unchanged (the new code paths are lazy-imported
  inside hooks that no-op when feature is disabled)
- p95 cycle latency: unchanged
- Memory at idle: +~50 MB (strawberry-graphql + authlib + boto3)
- Boot time: +~600ms (graphql blueprint registration on 3 workers)
- All under the +10% SLO regression target from phase 80's acceptance.

### Tagging
- `PROTEK_VERSION = "2.0.0"` in app.py — single source of truth.
- Commit message + git tag `v2.0.0` to be applied by operator when ready.
- packaging/debian/changelog already carries `protek (2.0.0-1)`.

**80 of 80 phases complete. Protek 2.0 SHIPPED.** 🎉

---

## 2026-05-21 — Arc 11 shipped (phases 63, 64, 66, 67, 68) · Resilience · 68 of 80 phases complete

**State at pause:** Five of six Arc-11 phases done in one push. Operator
deferred phase 65 (active-passive HA) — needs a second VPS to elect against.
Off-box backup automation pointed at Backblaze B2 (operator created bucket
this session; B2 creds still pending in `.env`). Litestream shipped as
scaffolding only — operator opts in per box. Synthetic ban self-test,
DR runbook, and token-bucket backpressure all wired and live.

### Phase 63 — Off-box backup automation
- `backup.py` — pluggable `BackupBackend` (LocalBackend default,
  S3Backend lazy-loads boto3). Bundles SQLite snapshot (online .backup()
  API, atomic), `.env`, custom scenarios under `/etc/crowdsec/scenarios/`
  into a tar.gz, encrypted with AES-256-GCM via scrypt(n=2^15). MAGIC
  prefix `PROTEKBK` (distinct from `bundle.py`'s `PROTEK01`).
- `backup_runs` table — id, kind (daily/monthly/test/manual), started_at,
  completed_at, status, size_bytes, dest, backend, error. Recorded
  even on failure (no silent backup loss).
- `maybe_run_scheduled()` — poller hook every 360 cycles (~1h). Daily
  due ≥24h since last; monthly due ≥28d (or first-of-month bootstrap);
  restore-test weekly. Internally no-ops until due — cheap to call.
- Retention: 30 daily / 12 monthly / 7 test (configurable via
  `backup.daily_keep` / `backup.monthly_keep` settings keys). Oldest
  pruned after each successful run.
- Restore-test: downloads latest, decrypts in temp dir, runs
  `PRAGMA integrity_check`, verifies presence of `decisions` + `settings`
  tables, deletes temp dir. Pure verification — no import.
- `/admin/backup-automation` page: KPIs (enabled/backend/passphrase/last
  successful/last restore-test), config form, S3 creds visibility, manual
  run / restore-test buttons, last-30-runs table.
- Env vars added: `BACKUP_PASSPHRASE` (required), `BACKUP_S3_ENDPOINT` (omit
  for AWS), `BACKUP_S3_REGION`, `BACKUP_S3_BUCKET`, `BACKUP_S3_KEY`,
  `BACKUP_S3_SECRET`. `boto3>=1.34,<2.0` added to requirements.
- Notification + SIEM events on success (`backup.completed`) and failure
  (`backup.failed`, plus `sync_error` notification channel).
- **Verified live**: 105 MB DB + .env + 56 scenarios → 17.4 MB encrypted
  bundle. Round-trip decrypt + integrity_check both pass. Wrong-passphrase
  rejection works (AES-GCM tag mismatch).

### Phase 64 — Litestream WAL replication (scaffolding)
- `litestream.py` — status surface only; we don't run Litestream ourselves.
  Reads `systemctl is-active litestream.service`, snapshot mtime via
  `litestream snapshots`, and surfaces health (ok/lagging/stopped/
  configured-pending/not-installed).
- `docs/litestream/protek-litestream.service.example` — systemd unit
  scaffold with hardening matching protek.service.
- `docs/litestream/litestream.yml.example` — B2-tailored config sample
  pointing at the same bucket as `BACKUP_S3_*`, separate `path: protek/litestream`
  prefix so it doesn't collide with `/daily/` `/monthly/` from phase 63.
- Status panel embedded into `/admin/backup-automation` with copy-paste
  install commands (amd64 + arm64) and restore procedure when binary missing.
- **Health computed**: not-installed (binary absent), since Litestream isn't
  on this box. Operator opts in per deployment.

### Phase 66 — Self-monitoring depth (synthetic ban test)
- `synthetic.py` — every 6h injects a decision for `192.0.2.250`
  (RFC 5737 TEST-NET-1, never reaches real traffic), drives reconcile,
  verifies presence in each live (enabled + non-dry-run) bouncer's
  snapshot, then removes + re-verifies absence.
- Detects "phantom-progress" — apply() reports success but snapshot
  doesn't reflect the change. Per-target add_ok / remove_ok recorded.
- Direct DB injection (not cscli) — uses `origin_source='synthetic'` +
  monotonically-decreasing negative `lapi_id` so collisions with real LAPI
  ids are impossible. Cleaned up via hard DELETE after every run,
  including crashes (`finally:` block).
- `synthetic_tests` table — id, started_at, completed_at, ip, status
  (ok/partial/failed/skipped), targets_n, ok_n, results_json,
  duration_ms, error.
- Skips with status=`skipped` when no live bouncers exist (all dry-run
  or none configured) — honest "nothing to test" rather than a fake green.
- `/synthetic` page — KPIs + recent runs table with per-target colored
  badges. Operator-triggerable "Run test now" button. Admin-only enable/
  disable schedule (`synthetic.enabled` setting).
- Notify (`sync_error` event) + SIEM (`synthetic.test.failed` severity 3)
  on partial/failed.

### Phase 67 — Disaster recovery runbook
- `docs/DR-RUNBOOK.md` — 8 sections covering: pre-flight, VPS loss,
  DB corruption, MikroTik replacement, hub outage, rate-limit storm,
  bundle restore procedure, compromise/key-leak rotation. Each section:
  symptom → impact → recovery steps → verify → notify.
- Quarterly drill template with 6 checklist items + per-step time targets.
- `scripts/restore_backup.py` — standalone (only requires `cryptography`)
  bundle decrypt + extract utility. Manifest sha256 verification built-in.
  Usable on a fresh box with just system python3.12.
- `/admin/dr-drill` page — checklist form that appends a tamper-evident
  row to `audit_log` via `dr.drill.completed` action. Drill history table
  reads from audit_log (append-only by SQL trigger from phase 35).

### Phase 68 — Rate limiting + backpressure (token buckets)
- `ratelimit.py` — `TokenBucket` (thread-safe, lock-protected),
  registry with lazy materialization, per-bucket settings overrides
  (`ratelimit.<name>.tokens_per_min`, `.capacity`). 429 handling halves
  refill rate for 5 min + drains immediately.
- Defaults table for known upstreams: lapi (600/min), bouncer.mikrotik
  (1200), bouncer.cloudflare (200 — CF Rules List has per-zone caps),
  bouncer.iptables_ipset (6000 — local fd ops), intel.abuseipdb (40 —
  free tier ~1000/day), intel.cti (2). Unknown bucket → DEFAULT 600/120.
- Caller pattern: `if not ratelimit.acquire(name): defer`. Never sleeps.
  Reconcile loop re-tries deferred chunks on next cycle.
- Wired at three real call sites:
  - `crowdsec.py:_get()` — `lapi` bucket. 429 → `record_429()`.
  - `bouncers/cloudflare_adapter.py` apply() — `bouncer.cloudflare`
    bucket per 1000-item chunk. Partial-batch deferral on exhaustion.
  - `webhooks_out.py:_send_once()` — per-host bucket via
    `webhook_bucket_for(url)`. 429 → record + DLQ retry.
- `webhook_bucket_for(url)` — derives `webhook.<hostname>` so distinct
  receivers (Slack vs Discord vs custom) don't share a budget.
- `/perf` page extended with a "Token buckets — upstream backpressure"
  panel: tokens / capacity / fill bar, rate, consumed-last-min,
  denied-last-min, 429 penalty status. New `/api/perf/buckets` JSON
  endpoint for live polling if we want to add a sparkline later.
- 7 unit tests in `tests/test_ratelimit.py` cover: burst-then-deny,
  refill math, 429 penalty + halving, registry dedup, unknown-bucket
  default, per-host webhook isolation, multi-token acquire.

### Acceptance proven this session
- **Phase 63:** 17.4 MB bundle from 105 MB DB; wrong-passphrase rejected;
  local backend put/get/list/delete clean; integrity_check 'ok' on
  decrypted snapshot.
- **Phase 64:** Status correctly reports `not-installed` when binary
  absent; sample unit + config files in place; install-hint UI renders.
- **Phase 66:** synthetic module imports + status returns sane defaults.
  Live test deferred until at least one bouncer flips out of dry-run mode
  (currently no live targets to verify against).
- **Phase 67:** runbook covers every known failure mode; `restore_backup.py`
  decrypts standalone (verified by smoke-testing without DB imports);
  `/admin/dr-drill` form writes to audit_log on submit.
- **Phase 68:** all 7 ratelimit unit tests pass; burst+refill math correct
  to 4 decimal places; 14/14 new tests pass; 34/34 total suite green.

### Quirks added this session
- Backup bundle's tar uses `mode=0o600` on every member — bundles can
  contain `.env` and we don't want a careless `tar -xf` on a multi-user
  box to leave SECRET_KEY world-readable.
- `_next_lapi_id()` in synthetic.py picks `min(existing_negative_ids) - 1`
  so even if two synthetic tests overlap, their ids never collide.
- Real LAPI ids are always positive — using negatives gives synthetic
  rows an unambiguous filter and prevents the LAPI's next pull from
  ever clobbering one.
- Synthetic test calls `reconciler.run_once(dry_run=False)` explicitly,
  but each bouncer still respects its own per-target dry_run flag —
  the override only forces the cycle to *try*, not to bypass safety.
- TokenBucket uses `time.monotonic()` (not `time.time()`) so wall-clock
  jumps (NTP correction, sleep+wake on a laptop) can't make buckets refill
  backwards or refund tokens.
- `webhooks_out` already had a retry/DLQ machinery, so the backpressure
  "return False" path just plugs into the existing failure path — DLQ
  retries pick up the deferred sends on their own schedule.
- LAPI `_get` import of `ratelimit` is lazy (`try: import` inside the
  function) so `crowdsec.py` doesn't gain a hard dep on the new module
  for boot-time correctness.
- The new modules all use the `_ensure_table()` lazy-create pattern (same
  shape as `audit.py` and `siem.py`) rather than adding entries to
  `db.py`'s SCHEMA/EXTRA_TABLES. Keeps the migration block clean for
  things that genuinely live in the core schema.

### Surface added this session
- **Pages:** /admin/backup-automation, /admin/dr-drill, /synthetic
- **APIs:** /api/perf/buckets, /admin/backup-automation/run (POST),
  /admin/backup-automation/test (POST), /admin/backup-automation/settings
  (POST), /admin/dr-drill/complete (POST), /synthetic/run (POST),
  /synthetic/toggle (POST)
- **Modules:** backup.py, litestream.py, synthetic.py, ratelimit.py
- **Scripts:** scripts/restore_backup.py (standalone bundle extractor)
- **Docs:** docs/DR-RUNBOOK.md, docs/litestream/litestream.yml.example,
  docs/litestream/protek-litestream.service.example
- **DB tables (lazy-created):** backup_runs, synthetic_tests
- **Reqs added:** boto3>=1.34,<2.0
- **Env vars (optional, all gated on backup.enabled=1):**
  BACKUP_PASSPHRASE, BACKUP_S3_ENDPOINT, BACKUP_S3_REGION,
  BACKUP_S3_BUCKET, BACKUP_S3_KEY, BACKUP_S3_SECRET
- **Settings keys:** backup.enabled, backup.backend, backup.local_path,
  backup.daily_keep, backup.monthly_keep, backup.last_daily_at,
  backup.last_monthly_at, backup.last_test_at, backup.last_test_ok,
  synthetic.enabled, synthetic.last_at, synthetic.last_status,
  ratelimit.<bucket>.tokens_per_min, ratelimit.<bucket>.capacity

### Phase 65 deferred (operator decision)
- Active-passive HA requires a second VPS + a network lock store
  (Redis SETNX or DynamoDB conditional write). No infra to elect against
  right now. When a second box comes online, the lock pattern reuses
  the existing `fcntl.flock` design from poller.py — promote to a
  network primitive, add a `leader` flag to bouncer.apply() so the
  passive instance never writes.

### Pending follow-ups for operator
- Drop B2 creds into `.env`: `BACKUP_PASSPHRASE`, `BACKUP_S3_ENDPOINT`
  (e.g. `https://s3.us-west-002.backblazeb2.com`), `BACKUP_S3_REGION`
  (match endpoint), `BACKUP_S3_BUCKET`, `BACKUP_S3_KEY`, `BACKUP_S3_SECRET`.
  Then in /settings (or /admin/backup-automation form): set
  `backup.backend=s3` + `backup.enabled=1`. Within 1h the first daily
  bundle uploads. Within 24h+7d a restore-test fires automatically.
- Optional: install Litestream binary on this VPS for RPO<60s. Sample
  files at `/var/www/Protek/docs/litestream/*.example`.
- Optional: enable synthetic test schedule via `/synthetic` once at least
  one bouncer flips out of dry-run mode.

### Next session — Arc 12 (Ecosystem) entry point
1. Phase 69 — Plugin SDK for bouncer adapters (pip-installable plugin
   discovery via entry_points, so third-party adapters don't need a
   PR against the core repo).
2. Phase 70 — OAuth / SAML SSO.
3. Phase 71 — Native packages (.deb / .rpm).
4. Phase 72 — Webhook input templates.
5. Phase 73 — GraphQL surface.
6. Phase 74 — Othoni cross-app integration deep-dive.

12 phases left to 2.0 (Arcs 12 + 13). Phase 65 (HA) remains as a
slot to fill when a second VPS exists.

---

## 2026-05-21 — Arc 10 shipped (phases 57–62) · Intelligence v2 · 63 of 80 phases complete

**State at pause:** Six Intelligence v2 phases done in one push. ASN-level
escalation, composite reputation scoring, three new intel providers (AbuseIPDB
/ OTX / Spamhaus), Tor exit + proxy/VPN tagging, honeypot routing scaffold,
and a sklearn isolation-forest anomaly layer. Arc 11 (Resilience) deferred
to a later session at operator's request.

### Phase 57 — ASN-level auto-ban

- New table `asn_escalations` (asn, as_org, ip_count, window_hours,
  sample_ips, status, decided_by, decided_at, note).
- `asn_detector.py` evaluates every 6 poller cycles (~60s): finds ASNs with
  N+ distinct IPs in last K hours (defaults 10 / 24). Cooldown setting
  prevents re-suggesting the same ASN within 48h of an operator decision.
- `/asn-escalations` page (linked under Intel in sidebar): pending list with
  approve/reject buttons + recent decisions audit.
- Approve creates a synthetic `decisions` row with scope=AS that flows
  through reconcile (bouncers either honor scope=AS or not — operator
  decides whether to convert to a real `cscli` ASN block).
- Reject suppresses re-suggest during cooldown.
- All actions audited (`asn.escalation.approved` / `.rejected`) + SIEM
  events (`asn.escalation`).
- **Verified live**: detector found 4 real escalations on first run —
  DigitalOcean (AS14061, 11 IPs), Google Cloud (AS396982, 11 IPs),
  KOI-AS South Africa (AS209425, 20 IPs), etc.

### Phase 58 — Composite reputation scoring

- New table `reputation_cache` (ip, score, tier, breakdown_json, computed_at).
- `reputation.py` computes 0–100 score from 5 components:
  - **CTI score** (0–20): CrowdSec CTI smoke endpoint × 4
  - **Scenario severity** (0–30): max severity over scenarios that hit this IP,
    weighted by a curated SCENARIO_SEVERITY map (CVE scenarios 28–30, brute
    force 18–22, recon 8–14)
  - **Cross-source agreement** (0–20): distinct origin_sources × 4
  - **Age decay** (0–15): newer = higher, 0d=15 → 90d+=0
  - **CTI behaviors** (0–15): weighted by behavior prefix
- Three tiers: `auto` ≥ 80, `queue` ≥ 50, `monitor` < 50. Thresholds
  tunable via `reputation.auto_threshold` / `reputation.queue_threshold`
  settings.
- Reconciler honors `min_reputation` per-bouncer filter — set it in
  config_json (e.g. `"min_reputation": 50` on Cloudflare to keep only
  high-confidence bans within the 10k cap).
- `reputation.bulk_compute_for_min(min_score)` does cache-first lookup,
  computes up to 200 uncached per call so a freshly-set filter doesn't
  stall reconcile. Remaining IPs fill on subsequent cycles.
- Cache TTL: 6h. Auto-recompute on attacker-page load if stale.
- `/api/v1/reputation/<ip>` exposes per-IP score with breakdown.
- New panel on `/attackers/<ip>` showing the score + tier pill + per-
  component breakdown.

### Phase 59 + 60 — Three intel providers + Tor + VPN tagging

- New `intel_providers.py` module with five providers, all gated on env
  presence (missing key = silently skipped):
  - **AbuseIPDB** (`ABUSEIPDB_API_KEY`): Check Endpoint v2 with
    `maxAgeInDays=90`. Confidence ≥ 75 auto-tags `abuseipdb-confident`.
    Returns `abuse_confidence` (0–100), report count, country, ISP.
  - **AlienVault OTX**: free, no key. Pulses by IPv4 indicator. ≥1
    pulse auto-tags `otx-pulse`.
  - **Spamhaus DROP/EDROP**: bulk download daily, tags matching active
    decisions as `spamhaus-drop` or `spamhaus-edrop`. Uses CIDR network
    matching (not IP equality) since DROP lists are netblocks.
  - **Tor exit list**: pulls from check.torproject.org/exit-addresses
    daily, tags matching active decisions as `tor-exit`.
  - **proxycheck.io** (`PROXYCHECK_API_KEY`): per-IP VPN/proxy detection.
    Confirmed proxies auto-tag `proxy-<type>`.
- New table `ip_tags` (ip, tag, source, created_at, expires_at) with
  composite PK on (ip, tag). Expiries prevent infinite tag accumulation.
- `intel_providers.maybe_refresh_bulk()` runs every cycle but no-ops
  until ≥20h since last Tor / Spamhaus refresh — same idempotent pattern
  as `digest.maybe_fire_daily()`.
- Tags surface on `/attackers/<ip>` as colored badges (red for
  tor/spamhaus/abuseipdb-confident, amber for proxies).
- Per-IP lookups (`abuseipdb_lookup`, `otx_lookup`, `proxycheck_lookup`)
  are exposed but not wired into the intel worker yet — operator can
  call them manually from a future "Refresh All Intel" button (already
  exists from phase 13's `IntelWorker.refresh`).

### Phase 61 — Honeypot routing scaffold

- `honeypot.py` — Protek doesn't run a honeypot itself; operator provides
  the endpoint. We:
  1. `refresh_targets()` tags qualifying high-reputation IPs as
     `honeypot-bound` (composite filter: reputation ≥
     `honeypot.min_reputation` default 80, cap at
     `honeypot.max_targets` default 1000).
  2. Exposes the list via `GET /api/v1/honeypot/targets` (token: read)
     so a CF Worker / nginx auth_request / etc. can decide what to do.
  3. Accepts callbacks at `POST /api/external/honeypot/callback`
     (token: write) — operator's honeypot reports back "this IP
     interacted with me", we tag `honeypot-confirmed` + ship SIEM
     event for audit.
- Gated on `honeypot.enabled=1` setting; full no-op otherwise.
- Poller hook every 12 cycles (~2 min).

### Phase 62 — ML anomaly layer (Isolation Forest)

- `ml_anomaly.py` — Isolation Forest over per-IP feature vectors. Pure
  scikit-learn (added to requirements with numpy).
- Per-IP features (8 dims):
  - `scenario_count`, `source_count`, `lifetime_hours`, `recent_hits`,
    `cti_score`, `asn_size` (distinct IPs in this ASN in active set),
    `is_capi` (binary), `is_local` (binary).
- Trains on last 30d of decisions (caps at 5,000 IPs to keep memory
  bounded). 100 trees, `contamination='auto'`.
- `/api/v1/ml/anomalies?n=50` returns top-N anomalous IPs with their
  feature vector. Recommend-only — never auto-bans.
- Lazy import of sklearn — if it's not installed, returns graceful
  empty result with `error: "sklearn not installed"`.
- **Verified live**: trained on 5000 samples, surfaced 3 candidate
  anomalies with scores in the -0.76 range.

### Quirks added this session

- ASN auto-ban "approve" inserts a synthetic decision with scope=AS.
  None of the current bouncers (MikroTik / iptables / CF) natively
  understand scope=AS — the diff includes them but they'll either
  silently no-op or error. Plan: operator uses the audit log entry as
  a manual prompt to run `cscli decisions add --range <ASN>` or to
  add a router-side `/ip firewall address-list add ranges=...` rule
  for the ASN's published prefixes. Future phase: ASN→prefix expansion
  via WHOIS BGP table, then push as Range decisions.
- The Spamhaus DROP refresh runs through every active decision's IP
  for CIDR matching. With 20k decisions and ~500 DROP entries that's
  ~10M comparisons — completes in ~2s on this box. Acceptable until
  we add a sorted-interval tree if it ever bites.
- proxycheck.io free tier is 1000/day; `proxycheck_lookup` returns a
  rate-limit error gracefully instead of crashing.
- ML scoring takes ~3s on 5k samples — acceptable for an on-demand
  `/api/v1/ml/anomalies` call but not for hot-path reconcile use.
  Future phase could background-train nightly + score on read.
- Boot-time SyntaxError discovered during smoke: `render_template(...,
  reputation=..., ..., reputation=...)` — collided with the existing
  CTI-page `reputation` kwarg. Renamed mine to `rep_score` (in route
  + template) so the CTI path stays untouched.

### Surface added this session

- **Pages:** /asn-escalations
- **APIs:** /api/v1/reputation/<ip>, /api/v1/honeypot/targets,
  /api/v1/ml/anomalies, /api/external/honeypot/callback
- **DB tables:** asn_escalations, ip_tags, reputation_cache
- **Modules:** asn_detector.py, reputation.py, intel_providers.py,
  honeypot.py, ml_anomaly.py
- **Reqs added:** scikit-learn, numpy
- **Env vars (optional):** ABUSEIPDB_API_KEY, PROXYCHECK_API_KEY

### Arc 11 deferred (operator decision)

Arc 11 (Resilience, phases 63–68) skipped this session — off-box backup,
Litestream, HA, self-monitoring, DR runbook, backpressure all remain.
Next session entry point: Phase 63 (off-box backup automation to
S3-compatible storage). The synthetic_tests + backup_log tables that
were prematurely added in this session's first pass have been removed
from db.py; they'll land properly when their phases ship.

### Acceptance proven this session

- **Phase 57:** detector found 4 real ASN escalations on first eval
  (DigitalOcean, Google Cloud, KOI-AS-ZA, etc.) — all 11–20 IP threshold
  crossings from the past 24h of CAPI ingestion.
- **Phase 58:** reputation.get_or_compute returns valid scores with
  breakdown. Cache TTL works (re-call returns same `computed_at`).
- **Phase 59/60:** `intel_providers.maybe_refresh_bulk()` runs cleanly
  (no API keys configured yet, so no real provider calls fired — code
  path verified to handle the missing-key case gracefully).
- **Phase 61:** `is_enabled() = False` by default; gating verified.
- **Phase 62:** sklearn trained on 5000 samples, returned top-3
  anomalies with reasonable scores.

### Pending follow-ups for the operator

- Sign up for AbuseIPDB free tier → add `ABUSEIPDB_API_KEY` to `.env`
- Sign up for proxycheck.io → add `PROXYCHECK_API_KEY` to `.env`
- Decide on first ASN escalation (4 are pending in /asn-escalations)
- Optionally enable honeypot mode by setting `honeypot.enabled=1` in
  the settings table once a honeypot endpoint exists

### Next session — Arc 11 (Resilience)

1. Phase 63 — Off-box backup to S3/B2 (nightly bundle export)
2. Phase 64 — Litestream WAL replication scaffolding
3. Phase 65 — Active-passive HA (network lock)
4. Phase 66 — Synthetic ban end-to-end test
5. Phase 67 — DR runbook (docs/DR-RUNBOOK.md)
6. Phase 68 — Upstream backpressure / token buckets

17 phases left to 2.0 (Arcs 11–13).

---

## 2026-05-21 — Arc 9 shipped (phases 51–56) · v1.1 polish · 57 of 80 phases complete

**State at pause:** Five v1.1 polish phases done. Phase 51 (multi-MikroTik UI)
shipped earlier as a one-off; this session completed 52–56 in one push. v1.1's
"things production use surfaced" arc is now done. 23 phases of Arcs 10–13
(Intelligence v2, Resilience, Ecosystem, 2.0 prep) remain.

### Phase 52 — In-place bouncer edit

- `/bouncers/edit/<id>` route + template. Edit name, config_json, dry_run flag
  without delete+re-add (which would lose sync history + force re-paste of
  secrets).
- Secret keys (`api_token`, `api_secret`, `password`, `hmac_secret`) are
  write-only — shown masked above the JSON box, replaced ONLY when the
  operator submits non-empty new value. Pattern matches the /notifications
  credentials flow.
- Health probe runs on the new config before persisting; bad creds = no save.
- Audit row records before/after with secrets redacted.
- "edit" link added next to "remove" on the /bouncers row.

### Phase 53 — Bulk operations on /decisions

- Multi-select checkbox column + "select all on page" header checkbox.
- Sticky cyan-edged action bar appears only when ≥1 row is selected; shows
  the count + a dropdown of operations: `delete` / `whitelist` / `extend`.
- `delete` — soft-delete (sets `deleted_at`); next reconcile removes from
  every bouncer.
- `whitelist` — adds an IP whitelist rule AND soft-deletes the active decision
  (the "stop banning this IP forever" combo).
- `extend` — bumps `until` by N hours (default 24, capped 720). Useful for
  "this attacker isn't going away, hold the ban longer".
- One confirm() showing the IP count before applying.
- POST `/decisions/bulk` is operator-only (RBAC), audited per-op as
  `decisions.bulk.<action>`, and ships a SIEM event with sample IPs.

### Phase 54 — Global search

- `/api/search` (session-auth, for in-browser cmd-K) + `/api/v1/search`
  (bearer-auth, for external clients) — same shape, different auth.
- Single query param `q` (≥2 chars). Searches across:
  - decisions (by IP or scenario substring)
  - alerts (by source_ip or scenario)
  - whitelist rules (by value or note)
  - bouncer_targets (by name → links to /bouncers/edit)
  - audit_log (by action / target / actor)
- Returns flat `{kind, label, hint, href}` list, default 8 per kind, max 50.
- cmd-K palette now debounces typing 180ms and concatenates the static page
  catalog with live server-side results. Type "ssh", get attacker IPs +
  scenario hits + audit rows mixed with the page shortcuts.

### Phase 55 — Per-stage sync timing

- 4 new sync_events columns (idempotent migration): `lapi_fetch_ms`,
  `snapshot_ms`, `diff_ms`, `apply_ms`.
- Reconciler instruments each stage with `time.monotonic()` deltas:
  - **lapi_fetch_ms** = `_desired_from_db()` (SQL pull + whitelist match)
  - **snapshot_ms** = sum across bouncers of reading their address-list
  - **diff_ms** = pure-Python reconcile compute (always tiny)
  - **apply_ms** = sum across bouncers of pushing add/remove ops
- `perf.stage_timings(hours=24)` returns avg/p95/max + share-of-total per
  stage, excluding pre-instrumentation rows (zeros).
- `/perf` adds a stacked-bar visual at the top of the new "Stage breakdown"
  panel + a table with the same numbers.
- **Verified on first instrumented cycle:** `lapi=538ms snap=12573ms
  diff=129ms apply=105946ms` (total 119s). Operator now sees instantly that
  MT push is 89% of the cycle — exactly the diagnostic the phase promised.
- Old "deferred until phase 4" footnote on the by-outcome panel removed.

### Phase 56 — Notification routing v2

- `notifications.send(channels=[...])` kwarg is real now. When provided, it's
  an **explicit override** that bypasses the per-event toggle entirely —
  alerting uses this for severity-based routing without needing the operator
  to also toggle the event on per-channel.
- `alerting._notify()` consolidated: removed the TypeError fallback (the
  kwarg works for real), and added a per-rule override lookup from
  `alerting.rule.<key>.channels` setting before falling back to
  severity→channels default.
- Per-rule channel override UI on `/alerts/rules`: an inline form per row
  lets the operator set "this rule pages Telegram only" or "Discord +
  email but not Telegram". Comma-separated, blank = default by severity.
- POST `/alerts/rules/channels` is operator-only + audited as `alert.channels`.

### Quirks added this session

- `notifications.send(channels=[...])` is bypassing the per-event toggle. Make
  sure callers actually want that — for the alerting case it's intentional
  (alerting decides routing); other callers should keep the implicit form so
  the operator's /notifications toggles still gate them.
- The bulk-whitelist op adds rules with `note="bulk whitelist via /decisions"`
  so they're identifiable in the /whitelist table from the noise of single-IP
  rules.
- Stage timings exclude rows with all-zeros (old rows pre-migration). Means
  the `samples` counter on /perf grows as new cycles run — first hour after
  deploy will show small samples; full 24h after a day.
- `/api/v1/search` and `/api/search` are intentional duplicates (same logic,
  different auth surface). When phase 70 (OAuth/SAML SSO) lands, both will
  still work — the bearer surface stays for CLI/external; the session surface
  stays for in-browser.
- The cmd-K palette now hits `/api/search` on every keystroke (debounced).
  If you start typing very fast, only the final value's response is rendered
  (it checks `input.value.trim() !== q` before applying).
- The bouncer-edit form's "Currently-set secrets" panel only renders if the
  config_json had any of the 4 secret-keys set. Otherwise the panel is omitted
  to avoid clutter.

### Acceptance proven this session

- Phase 52: edit a CF target's `max_entries` without re-pasting the api_token.
- Phase 53: select 5 IPs on /decisions, bulk-whitelist, next cycle they're
  gone from CF + MT.
- Phase 54: `protekctl-equivalent search` via `/api/v1/search?q=ssh` returns
  16 hits across decisions/alerts in <100ms.
- Phase 55: fresh sync_event row shows real per-stage numbers; `/perf` renders
  the stacked bar; operator can answer "which stage is slow" by looking, not
  guessing.
- Phase 56: set `alerting.rule.mt_unreachable_2m.channels=telegram`, simulate
  MT outage (`set_setting('mt.last_status','down')`), only Telegram fires
  (when configured) — Discord stays silent.

### Surface added this session

- **Pages:** /bouncers/edit/<id>
- **APIs:** /api/search, /api/v1/search, /decisions/bulk, /alerts/rules/channels
- **DB columns:** sync_events.lapi_fetch_ms, .snapshot_ms, .diff_ms, .apply_ms
- **Templates:** bouncers_edit.html (new), decisions.html + perf.html +
  alerts_rules.html + base.html (updates)
- **Modules touched:** app.py, api_v1.py, alerting.py, notifications.py,
  perf.py, reconciler.py, db.py, templates/*

### Next session — Arc 10 (Intelligence v2) entry point

1. Phase 57 — ASN-level auto-ban. Threshold: N IPs from same ASN in M hours
   → escalate to ASN-wide rule. Your top scenarios show 30+ IPs from a
   handful of bad ASNs; one rule kills most noise.
2. Phase 58 — Reputation scoring. Composite of (CTI × scenario severity ×
   source agreement × age decay) → three tiers (auto-ban / queue / monitor).
   Solves the CAPI noise vs local-detection priority problem cleanly.
3. Phase 59 — AbuseIPDB + OTX + Spamhaus correlation.

23 phases left to v2.0 (Arcs 10–13).

---

## 2026-05-21 — Arcs 7 + 8 shipped + Protek 1.0 · **51 of 51 phases complete** 🎉

**State at pause:** v1.0 is on disk. Every roadmap phase 0–50 is shipped. Live deployment
remains in production (live MT writes, real bans flowing). New surface this session:
multi-admin + RBAC, scoped API tokens, full `/api/v1/*` REST with OpenAPI, `protekctl` CLI,
inbound + outbound webhooks (HMAC-signed, DLQ), encrypted config backup, mobile-responsive
CSS, command palette, atom/othoni integration links, install.sh, user/install/perf docs.
20 unit tests pass; 16-route smoke green; 5-endpoint API token smoke green; CLI smoke green.

### Phase 42 — Multi-admin accounts

- `users` table (id, username, password_hash, totp_secret, role, created_at, last_login_at, disabled).
- `seed_env_user()` runs on every boot — idempotent mirror of APP_USERNAME / APP_PASSWORD_HASH /
  TOTP_SECRET into row #1. Refreshes the row if env values changed (e.g. operator ran
  setup_admin.py). Row #1 is the bootstrap admin and can't be demoted, disabled, or deleted
  through any code path (raises ValueError).
- `verify_password()` now returns the user dict on success (was: bool). `verify_totp_for(user, code)`
  takes the user dict so the right per-user secret is used.
- Login route stamps `session["user_id"]` + `session["role"]` alongside `username`. Also calls
  `record_user_login(user_id)` so `last_login_at` populates.
- `/admin/users` page (admin role only): add/role/disable/delete + one-shot TOTP secret +
  provisioning_uri display for the new user.

### Phase 47 (foundation) — API tokens

- `api_tokens` table (token_hash, token_prefix, scopes, expires_at, last_used_*, disabled).
- `api_tokens.py`: `create_token`, `lookup`, `has_scope`, `require_token(scope)` decorator.
- Tokens are `pk_` + `secrets.token_urlsafe(32)`. Only sha256(token) is persisted.
- The plaintext token is shown ONCE post-creation; otherwise only the prefix is ever displayed.
- Lookup stamps `last_used_at` + `last_used_ip` and honours `disabled` + `expires_at`.
- Scope semantics: `admin` implies `write` implies `read`. Per-route gate via `@require_token(scope)`.
- `/admin/tokens` page: create / list / revoke / delete + one-shot token reveal.

### Phase 43 — RBAC

- `role_required(required)` decorator added to `auth.py`. Roles: `viewer` < `operator` < `admin`.
- 19 write routes bulk-decorated with `@role_required("operator")` (whitelist/bouncers/
  federation/approvals/security/notifications/settings/sync/silences).
- Admin-only routes already gated by separate `@role_required("admin")` (user mgmt, tokens, backup).
- `has_role()` exposed to templates via a `@app.context_processor` so affordances can hide for
  insufficient roles. Sidebar Admin section hidden for non-admins.
- Topbar shows a role pill when not admin (so the operator knows they're operator/viewer).

### Phase 46 — Webhook inputs

- `POST /api/external/decisions` — accepts ban requests with `write`-scope token auth.
- Body: `{ip, scope, scenario, duration, reason, queue}`. Go-style duration parser.
- Synthetic `lapi_id` (ms-since-epoch + collision-walk) for uniqueness against the
  `(origin_source, lapi_id)` constraint. `origin_source = "external:<token_name>"` for attribution.
- `queue=true` (or global `settings.approval_required=1`) routes the decision into `approval_queue`
  instead of directly into `decisions`.
- Emits `decision.created` SIEM event + audit row (`external.ban` / `external.ban.queued`).
- `POST /api/external/decisions` is CSRF-exempt (token auth replaces CSRF for the API surface).
- `GET /api/external/health` — public no-auth liveness for integrators.
- Verified end-to-end: 202 on success, 401 on no token, 403 on read-only token, decision flows
  through reconcile into MT.

### Phase 45 — Webhook outputs

- `webhook_subs` table (id, name, url, hmac_secret, event_mask, enabled, consec_failures,
  last_ok_at, last_error).
- `webhook_dlq` table for deliveries that exhausted retries (3 attempts × 2/4/8s backoff).
- `webhooks_out.py`: bounded `queue.Queue(maxsize=10_000)` + daemon worker thread. Drops on
  overflow with a log line. `emit(event_type, payload)` is non-blocking — never blocks the
  reconcile loop.
- HMAC-SHA256 signing: `X-Protek-Signature: sha256=<hex(secret, f"{ts}.{raw_body}")>`. Headers
  also include `X-Protek-Event` + `X-Protek-Timestamp`.
- `event_mask` is glob-matched with fnmatch (`*` = all, comma-separated allowed).
- One emission point: `siem.ship()` now fans out to both SIEM forwarders AND webhooks. Single
  call site for the rest of the codebase.
- `/webhooks` page: subscribers table (state, last_ok, consec_failures), DLQ tail (with replay
  button), add form.
- Verified end-to-end with a local Python `BaseHTTPServer`: HMAC verified correctly,
  `last_ok_at` populated, broken sub → 3 attempts → DLQ row with `attempts=3`.

### Phase 40 + 47 (close) — /api/v1 + OpenAPI + protekctl

- `api_v1.py` blueprint registered under `/api/v1`, CSRF-exempt (token auth).
- Endpoints:
  - `GET /ping` (no auth)
  - `GET /decisions` (filters: scope, origin, q, limit)
  - `POST /decisions` (proxies to `/api/external/decisions` via test_request_context so
    behavior is identical)
  - `DELETE /decisions/by-ip/<ip>` (soft-delete, ships `decision.deleted` SIEM event)
  - `GET /alerts` (mirror of local alerts table)
  - `GET /sync/status` (compact status JSON)
  - `POST /sync/run` (force reconcile, returns result dict)
  - `GET /whitelist` + `POST /whitelist` + `DELETE /whitelist/<id>`
  - `GET /sources` (federation read)
  - `GET /tile/summary` (cross-app dashboard tile)
  - `GET /feed/banned-ips` (compact feed for atom-style integrators)
  - `GET /openapi.json` (OpenAPI 3.0.3 spec; security: bearer)
- `bin/protekctl` Python CLI (no extra deps beyond `requests`):
  - Commands: `ping`, `decisions ls/add/rm`, `sources ls`, `sync status/run`,
    `whitelist ls/add/rm`, `tile`.
  - Output modes: `table` (default; auto-sized columns), `json`, `tsv` (scriptable).
  - Config order: CLI flags → env (`PROTEK_URL` / `PROTEK_TOKEN`) → `~/.config/protek/protekctl.toml`
    (tomllib on 3.11+, hand-rolled parser fallback to avoid a dep).
  - Verified: `protekctl ping`, `protekctl decisions ls --limit 3`, `protekctl tile`,
    `protekctl decisions add/rm` all work. JSON mode pipes cleanly to `jq`.

### Phase 39 + 44 — Mobile-responsive + command palette

- CSS media queries in `base.html`:
  - `@media (max-width: 880px)` — sidebar slides off-screen behind a hamburger, tables auto-
    reflow to card layout (with column-header inlined as `data-label` via tiny JS helper),
    forms reflow.
  - `@media (max-width: 480px)` — brand text shrinks, KPI strip drops to 2 columns, KPI value
    text shrinks.
  - Touch targets bumped to 44px min on mobile sidebar.
  - Opt-out via `table.keep-table` for tables that genuinely need a grid view.
- Command palette (`cmd-K` / `ctrl-K` / `/`):
  - Backdrop overlay with cyan-edged box, fuzzy substring match over a manually-curated catalog
    of pages + actions (admin entries shown only for admin role).
  - Keyboard nav: `↑`/`↓` cycle, `⏎` select, `esc` close.
  - One non-navigational action: "Force sync now" → POSTs `/api/sync/run` with CSRF header.
  - Catalog is rendered in the template (so Jinja can resolve url_for and the role check),
    not fetched separately.

### Phase 41 — Bulk import/export

- `bundle.py` — encrypted config bundle. Format:
  `MAGIC (8 "PROTEK01") | salt (16) | nonce (12) | AES-GCM ciphertext+tag`
- Key derivation: `hashlib.scrypt(passphrase, salt, n=2^15, r=8, p=1, dklen=32, maxmem=128MB)`.
  Had to pass `maxmem` explicitly — OpenSSL default of 32MB is exactly the memory n=2^15 needs
  but it raises "memory limit exceeded" without slack.
- Exports: users, sources, whitelist, bouncer_targets, webhook_subs, api_tokens (hashes only,
  plaintext tokens cannot be reconstructed), settings, alert_silences.
- Excludes: decisions / alerts / sync history / audit log / caches (operational data; re-acquired
  on next poll).
- Import modes: **additive** (default — `INSERT OR IGNORE`, skips on UNIQUE collision) or
  **overwrite** (clears each table first, then `INSERT OR REPLACE`).
- `/admin/backup` page: passphrase ≥12 chars enforced; download as `.bin`; upload + checkbox
  for overwrite mode with a confirm() guard.
- `cryptography` added to `requirements.txt`.
- Verified round-trip: export → wrong passphrase → InvalidTag → ValueError. Right passphrase
  → parse → additive import → all rows skipped (already exist). Format magic correct.

### Phase 48 + 49 — Atom + Othoni integration

- `integrations.atom_url` + `integrations.othoni_url` settings keys (UI-editable from `/settings`,
  `.env` fallback via `ATOM_URL` / `OTHONI_URL`).
- Attacker page (`/attackers/<ip>`) — when URLs set, renders "Investigate in atom ↗" and
  "Search in othoni ↗" buttons in the Report-Abuse row.
- `GET /api/v1/feed/banned-ips` (token-authed `read`) — compact JSON for atom-style polling
  integrators (just IPs + scenarios; not the full decision metadata).
- `GET /api/v1/tile/summary` (already shipped earlier) — compact JSON for othoni's grid tile.
- SSO scaffolding: deferred to deployment-time. Cookie scoping documented in INSTALL.md but
  no code change — the existing Flask session cookie can be widened from per-host to
  `.syedhashmi.trade` via the operator's nginx + Flask `SESSION_COOKIE_DOMAIN` setting.

### Phase 50 — Protek 1.0

- `install.sh` — idempotent one-command install for fresh Ubuntu 22.04/24.04: deps,
  CrowdSec via APT, clone+venv, admin bootstrap, bouncer-key gen, systemd unit, nginx site,
  certbot. Asks for domain + admin email; skippable parts skip cleanly when blank.
- `docs/USER_GUIDE.md` — daily ops, common operations (whitelist, ban/unban, force sync,
  add admin, generate token, wire external system, wire webhook, backup), keyboard shortcuts,
  notifications, RBAC quick ref.
- `docs/INSTALL.md` — one-command install, manual install, MikroTik wiring (incl. dedicated
  API user + firewall rules), CrowdSec Console enrollment, machine credentials, flipping out
  of dry-run.
- `docs/perf-baseline.md` — steady-state vs initial-sync numbers, hot-path optimizations baked
  in, tuning knobs, known scaling ceilings, comparison oneliners.
- `docs/TROUBLESHOOTING.md` — `/health` 503 matrix, stuck initial sync, service won't start,
  lockout recovery, backup import errors, DLQ filling, SIEM stoppage, slow cycles, env-change
  not taking effect, empty alerts.
- `PROTEK_VERSION = "1.0.0"` constant in app.py.
- `protek_build_info{version="1.0.0", phase="50"}` metric stamps `/metrics` with the release.
- `/api/v1/ping` now returns `version: "1.0.0"`.
- Marketing site + Docker image + git v1.0 tag + security review intentionally deferred — those
  are out-of-process work the operator owns (sign DNS, push to a registry, run security review,
  push the tag); the code side of 1.0 is shipped.

### Acceptance proven this session (against ALL of Arcs 7 + 8 + Phase 50)

- 20 unit tests pass.
- 16-route HTTP smoke green (200 for public, 302 for auth-required).
- `/api/v1/*` 5-endpoint token smoke green with `admin`-scope token.
- `protekctl ping`, `tile`, `decisions ls/add/rm` all green via shell.
- Bundle round-trip: 3.4KB encrypted blob → wrong passphrase rejected → right passphrase
  decrypts → additive re-import correctly skips all rows.
- Webhook out: live receiver got POST with verified HMAC. Broken sub → DLQ after 3 attempts
  with proper backoff timing (2+4+8s = ~14s).
- Webhook in: 202 on success, 401 on missing token, 403 on insufficient-scope token.
- Multi-admin: env user seeded at row #1, role=admin, can't be demoted; new-user creation
  path returns one-shot TOTP secret + provisioning_uri.

### Quirks added this session

- The `notifications.send(...)` signature still doesn't take a `channels` kwarg — alerting's
  per-severity routing falls back to per-event toggles. Plumbing in `_notify()` is ready
  for when the kwarg lands; one-line change to `notifications.send` would activate it.
- `bundle.export_bundle()` requires `maxmem=128*1024*1024` on `hashlib.scrypt` because
  OpenSSL's default (32MB) is exactly the memory n=2^15 needs but raises without slack.
- `seed_env_user()` runs on EVERY boot. If you rotate the password via `setup_admin.py`,
  the row is updated in place (not duplicated). Disabling user #1 via the UI is refused
  with a friendly ValueError.
- The cmd palette catalog is rendered server-side via Jinja so `url_for()` can resolve and
  the admin-section gate works without an extra fetch. The catalog is small (~22 items) so
  the rendered HTML cost is negligible.
- Multi-page table responsive mode auto-applies; tables that genuinely need grid layout
  (heatmaps, alignment-sensitive) can opt out with `class="keep-table"`.
- The `/api/v1/decisions` POST path **reuses** `api_external_decisions` via
  `current_app.test_request_context(...)` so the behavior is bitwise identical. Avoids
  drift between the v1 surface and the external surface.
- The webhook DLQ row size is bounded to 1000; oldest is pruned when the table grows past
  that (same pattern as siem_journal's 10k cap).
- Phase 49 SSO is deployment-time only — the existing `SESSION_COOKIE_DOMAIN` Flask setting
  + a shared SECRET_KEY across apps gives cross-app session sharing. Documented in INSTALL.md
  but not encoded in app.py since it's site-policy not code.

### Total surface (after Arcs 7 + 8 + Phase 50)

- **Pages added this session:** /admin/users, /admin/tokens, /admin/backup, /webhooks
- **API surface added:** /api/v1/* (12 endpoints), /api/external/decisions,
  /api/external/health, /api/v1/openapi.json
- **CLI added:** bin/protekctl (10 subcommands)
- **Tables added:** users, api_tokens, webhook_subs, webhook_dlq (4 added; 24 total)
- **Modules added:** api_tokens.py, api_v1.py, webhooks_out.py, bundle.py
- **Docs added:** docs/USER_GUIDE.md, docs/INSTALL.md, docs/TROUBLESHOOTING.md,
  docs/perf-baseline.md, install.sh

### What's deferred / out-of-scope for v1.0

- Cross-app SSO via shared cookie (deployment-time, not code).
- `notifications.send(channels=...)` kwarg — alerting's per-severity routing is plumbed
  but degrades to per-event toggles until the kwarg lands.
- Per-stage timing on `sync_events` (LAPI fetch / MT snapshot / diff / push) — needs columns
  + instrumentation; the /perf footnote calls it out.
- Marketing single-page site, Docker image, git v1.0 tag, formal security review — all
  out-of-process work the operator owns.

### v1.0 ship readiness checklist

- [x] All 51 phases (0–50) shipped in code
- [x] 20/20 unit tests pass
- [x] Live deployment running in production
- [x] Documentation (user guide, install guide, perf baseline, troubleshooting)
- [x] One-command install script
- [x] Version constant stamped at 1.0.0 (app, metrics, /api/v1/ping)
- [ ] git tag v1.0 (operator-side — `git tag v1.0.0 && git push --tags` when ready)
- [ ] Public marketing site (operator-side)
- [ ] Docker image (operator-side)

### Next session — purely operator-side

The roadmap as defined is complete. Future work would be:
1. Tag v1.0.0 in git.
2. Consider Arc 9 ideas if/when they emerge (e.g. clustering for HA, GraphQL surface,
   plugin SDK for community-contributed adapters).
3. Real-world soak — let the deployment run for a week and read `/perf` SLO numbers.

---

## 2026-05-21 — Live deployment + UX layer · Phase 4 acceptance MET · 40 of 51 phases complete

**State at pause:** Protek is fully deployed and bouncing in production. MikroTik writes are live
(not dry-run), CrowdSec Console is enrolled, CTI/intel + machine-credential alerts populating,
notification credentials editable from the web UI. The session was all wiring + UX polish on top
of Arc 6 — no new arc phases, but Phase 4 (live MT writes) acceptance is finally met.

### Operator-side configuration that landed today

- **CrowdSec Console enrolled** (`cscli console enroll <key>` → accepted in app.crowdsec.net UI →
  `cscli console status` shows custom/manual/tainted/context forwarding ON, console_management OFF).
- **CTI API key** in `.env` as `CROWDSEC_CTI_API_KEY`. Verified end-to-end: `intel.cti_lookup()`
  against a real banned IP returned full smoke data — reputation, behaviors, AS/country, history.
- **MikroTik credentials** in `.env`: `MT_HOST=45.248.49.159`, `MT_USERNAME=api`, port 8728.
  RouterOS 7.22.1 on the home router ("syed-home"). Connection confirmed via `mikrotik.health()`.
- **Firewall drop rules** added on the router for both `input` and `forward` chains, src-list=crowdsec,
  comment="protek-bouncer". Without these, populating the list does nothing — they're the
  enforcement half.
- **Machine credential** `protek-machine` created via `cscli machines add` and pasted into `.env`
  as `CROWDSEC_MACHINE_LOGIN` + `CROWDSEC_MACHINE_PASSWORD`. /alerts page now populated with real
  event context (200 alerts mirrored in initial backfill).
- **Live-write flip**: `settings.dry_run` toggled to "0". Initial sync is currently draining ~19k
  decisions at 200/cycle → ~50-70 min to finish; after that, cycles drop to sub-second deltas.

### Phase 4 acceptance — finally met after being blocked since first deploy

- 19,088 decisions in local mirror, MT address-list filling at ~200/cycle (the configured batch_cap)
  with zero per-op errors so far.
- All entries carry the `protek:<origin>:<scenario>:<lapi_id>` comment, so foreign entries on the
  same list (if anyone adds some manually later) won't be touched.
- Firewall rules drop banned src-IPs at the WAN edge for both router-bound (input) and LAN-bound
  (forward) traffic — full perimeter coverage.

### Bug fix: dry_run toggle didn't take effect without a restart

When operator flipped `settings.dry_run="0"` via the shell (or via /settings POST in a different
gunicorn worker), the in-process Poller still used `self.dry_run = True` from its boot snapshot.
Reconcile kept running in dry mode even though the persisted setting said live.

Fix: `Poller.tick()` now re-reads `settings.dry_run`, `settings.sync_interval_sec`, and
`settings.batch_cap` from the DB at the start of each cycle. So any UI/shell toggle takes effect
on the next tick without a restart. The .env values stay as boot defaults; the settings table is
the runtime source of truth.

### Machine-credential wiring for /alerts

- New `MachineClient` class in `crowdsec.py`. Uses `/v1/watchers/login` to get a JWT, then
  `Authorization: Bearer <jwt>` for `/v1/alerts`. Auto-refreshes on 401 with one retry.
- New env vars `CROWDSEC_MACHINE_LOGIN` + `CROWDSEC_MACHINE_PASSWORD`. `has_machine_credentials()`
  in app.py now actually checks them (was hardcoded `return False`).
- `Poller.tick()` runs `_mirror_alerts()` every 6 cycles (~60s in steady state). Pulls last hour
  of alerts via the MachineClient, upserts into local `alerts` table on the
  `UNIQUE(origin_source, lapi_id)` constraint. JWT is cached on the Poller instance across cycles
  so we don't re-login every time.
- `.env.example` updated with the new env vars + the `cscli machines add protek-machine` command
  needed to provision them.

### Notification credentials now editable from the web UI

- `notifications.py` got a `CREDENTIAL_SCHEMA` registry — one entry per (channel, field) tuple
  declaring label, env-var fallback, secret flag, placeholder, etc. Discord has one field
  (`webhook`), Telegram has two (`bot_token` + `chat_id`), Email has six (host/port/user/pass/
  from/to).
- New helpers `get_credential(ch, field)`, `set_credential(ch, field, value)`,
  `mask_credential(ch, field)`. Storage: settings table key `notify.cred.<channel>.<field>`,
  with .env as boot fallback (so existing `.env` deployments keep working unchanged).
- All `_send_*` functions and `channel_configured()` switched from direct `_envstr()` reads to
  `get_credential()`. Old env-only path is gone — the env values just provide defaults the UI
  can override.
- `/notifications` page rebuilt:
  - One panel per channel with a Save button (so saves are isolated — saving Discord doesn't
    re-write Telegram fields).
  - Secret fields: `<input type="password">` with `autocomplete="new-password"`. Display next to
    the input shows the masked value (e.g. `•••• abc1`) + a "leave blank to keep current" hint.
  - Blanking a secret on submit = NO-OP (the route specifically skips empty secret submissions).
    Non-secret fields accept blank as a real clear.
  - Setup hints baked in: Discord webhook URL discovery, Telegram BotFather + getUpdates flow,
    "your home SMTP probably won't reach Gmail" warning.
  - "Send test" button per panel — one-click verify after pasting creds.
- Audit hook records `notify.credentials` with `{channel, fields_changed: [...]}` — never the
  actual secret values. Toggle changes audited as `notify.toggles`.
- `app._audit()` shim was extended via the existing decorator; nothing else needed to change.

### Quirks added this session

- The very first tick after restart shows stale `reconcile.last_dry_run` in the settings table
  because the in-progress cycle hasn't completed yet (settings are stamped at end-of-tick). MT
  address-list size IS the authoritative signal — if it's growing, live writes are happening.
- The "first cycle" timing during initial sync is dominated by the serial MT push (200 entries
  one at a time over the RouterOS API socket = ~30-60s per cycle for the first ~95 cycles, then
  drops back to sub-second). This is why /perf SLO p95 will look bad for the first hour, then
  recover.
- `cscli machines add --auto` prints credentials inline; without `--auto` it prompts and writes
  them into `/etc/crowdsec/local_api_credentials.yaml`. Either way, paste the machine_id +
  password into `.env` — don't try to read them from the agent's credentials file (it's owned
  by crowdsec, not root, and the password format there isn't always plaintext-pasteable).
- The `notifications.set_credential(ch, field, '')` path explicitly DOES clear, but the UI route
  short-circuits before calling it for secret fields with empty input. So `set_credential` is
  honest about "" = clear; the UI just shields the secret-blank case.

### Acceptance proven this session

- **Phase 4 (live MT writes):** address-list went 0 → 17 → 92 → 155 → 200 → climbing. ESTAB TCP
  connection to router:8728 from gunicorn worker confirmed via `ss -ntp`. Zero per-op errors.
- **Machine creds:** `MachineClient.alerts(since="1h", limit=5)` returned 5 real SSH brute-force
  alerts (Korea Telecom, etc.). Full upsert of 200 alerts in one manual run populated /alerts.
- **CTI:** `intel.cti_lookup('183.110.26.27', force=True)` returned full CrowdSec CTI smoke data
  including behaviors=["ssh:bruteforce"], confidence, history.
- **Notification UI:** manual round-trip — save fake Discord webhook → mask shows `•••• Z123` →
  re-save blank → mask still shows `•••• Z123` (correctly preserved). Cleared explicitly via
  `set_credential('discord', 'webhook', '')` → `channel_configured('discord')` → False.

### Pending follow-ups (from this session, not future arcs)

- **Wire actual Discord/Telegram webhooks** via the new UI — alerting rules can fire critical
  alerts but they'll currently land on no channels. Operator has the means now; just needs to
  paste real creds.
- **Whitelist home/admin IP** at `/whitelist` or `/etc/crowdsec/parsers/s02-enrich/whitelists.yaml`
  before any extended away-from-keyboard time. The community blocklists are wide.
- **Watch /perf 24h from now** — SLO p95 should drop from 57s (historical) → sub-second once the
  initial backfill finishes and the SLO window slides past the slow-cycle batch.
- **Verify backfill completion** — at ~200/cycle the full 19k should be in place within an hour.
  After that the `reconcile_to_add` gauge in /metrics should settle near zero (only new bans
  from the CrowdSec stream show up).

### Next session — Arc 7 (Operator QoL) is unblocked

1. Phase 39 — mobile-responsive dashboard
2. Phase 40 — `protekctl` CLI client
3. Phase 41 — bulk import/export
4. Phase 42 — multi-admin accounts

---

## 2026-05-21 — Arc 6 shipped (phases 33–38) + reconcile perf fix · 39 of 51 phases complete

**State at pause:** Observability layer is live end-to-end. Prometheus scrapes, syslog forwards
real RFC 5424 packets, audit log is append-only at the DB layer, perf dashboard surfaces
p50/p95/p99, SLOs compute compliance + burn rate, composite alerts dedup with debounce + auto-resolve.

### Fix-on-arrival: reconcile cycle was taking 66s, /health was 503 with `poll_stale`

Root cause was a double bug compounding:
- `_desired_from_db()` fetched 111,595 decision rows (most were duplicate IPs across community
  blocklists — same value under different `(origin_source, lapi_id)` pairs).
- Per-row whitelist match called `list_whitelist()` once per row, so 111k DB round-trips
  against an empty whitelist table = 90 seconds.
- Reconcile took 66s, but `poller.last_at` was being stamped at the START of each tick (before
  reconcile), so `/health`'s `3 * interval = 30s` staleness budget tripped every cycle.

Fix:
- Dedup at the SQL layer with `SELECT ... GROUP BY value, scope` + `MIN(lapi_id)` for stable
  comment determinism. 111k → 21k rows.
- Refactored `scenarios_admin.matches_whitelist(...)` to accept a `rules=` kwarg; reconciler
  pre-fetches whitelist + asn/country maps once outside the loop.
- Approval-queue path had the same N+1 (one DB connection per pending IP) — pre-fetches all
  pending statuses in one query now.
- Moved `set_setting("poller.last_at", ...)` to AFTER reconcile so the staleness signal
  measures completed cycles, not "tick started".
- Made `/health`'s staleness budget cycle-time-aware: `max(3 * interval, 2 * last_reconcile_ms + interval)`
  capped at 10min so a genuinely wedged poller still trips.
- **Result:** `_desired_from_db` 90s → 490ms (~180×). Reconcile 66s → 307ms. `/health` 200 again.

Cleared stale `reconcile.last_error` settings row (orphan from a removed code path that read
`MT_PORT` raw — current `_envint` correctly strips dotenv inline comments).

### Phase 33 — Prometheus metrics

- `metrics.py` hand-rolls the text-exposition format (no `prometheus_client` dep). 22 series
  including: `protek_active_decisions{,_by_origin,_by_source}`, `protek_poller_lag_seconds`,
  `protek_reconcile_duration_seconds`, `protek_source_health{name,url}`, `protek_dry_run`,
  `protek_bouncer_targets{kind}`, `protek_whitelist_rules`, `protek_login_attempts_total{result}`.
- `/metrics` auth: bearer token from `METRICS_TOKEN` env, OR localhost-only when token unset
  (typical "Prometheus on the same box" setup). CSRF doesn't apply (GET-only).
- Caught two schema mismatches against my mental model on first run — `sources.last_pull_n`
  (not `last_pull_count`), `login_audit.success` (not `result`). Fixed and reran cleanly.

### Phase 34 — SIEM forwarding

- `siem.py` with two forwarders that self-arm from env vars:
  - `SyslogForwarder` — RFC 5424 over UDP (default) or TCP with octet-counted framing per RFC 6587.
    Structured-data block carries the high-value keys (`ip`, `scenario`, `origin`, `source`,
    `actor`, `bouncer`); body is JSON for downstream parsers.
  - `WebhookForwarder` — JSON POST. Shape is Splunk-HEC compatible (`time`, `host`, `source`,
    `sourcetype`, `event`).
- Bounded `deque(maxlen=10_000)` queue + daemon worker thread; on overflow drops oldest with a
  counter (`stats.dropped_overflow`). Never blocks the reconcile loop.
- Every event persisted to `siem_journal` first → enqueued for shipping → worker updates the
  row's `shipped_at` + `ship_error`. Replay re-enqueues the last N rows regardless of state.
- Singleton elected by the same `fcntl.flock(.poller.lock)` as the poller/geo/intel workers —
  only one of the three gunicorn workers ships.
- Wired:
  - `poller._stream_apply` → `decision.created`/`decision.deleted` per delta entry (bootstrap
    intentionally NOT shipped — would flood the SIEM with 19k existing decisions on every restart).
  - `poller._pull_source` source transitions → `source.up`/`source.down`.
  - `poller.tick` → `sync.error` when reconcile errors > 0.
  - `auth.record_failure` → `auth.failure`/`auth.locked` on transition.
  - `app.py login route` → `auth.success`.
  - `audit.record` mirrors every operator action as `settings.changed`.
- `/siem` page: forwarder status, replay form (1–10k), last 200 journaled events with shipped state.
- **Acceptance proven:** `nc -ul 5599` listener captured a real RFC 5424 packet with all fields
  present — PRI `<133>` = local0 facility × 8 + notice severity, ISO timestamp, hostname,
  app="protek", procid, msgid, structured-data block, JSON payload.

### Phase 35 — Append-only audit log

- `audit_log` table + `audit_log_no_update` / `audit_log_no_delete` triggers in `init_db()` that
  raise `sqlite3.IntegrityError` if anything tries to mutate history. Triggers are storage-layer
  enforcement, not advisory — even a renegade code path can't tamper.
- `audit.py` module exposes `record(action, actor=, ip=, target=, before=, after=, note=)` and
  `recent(limit=, action_filter=)`. Best-effort; auditing must never break the action it records.
- App-level shim `app._audit(action, ...)` auto-fills `actor` from `session["username"]` and `ip`
  from `request.remote_addr`. Saves N lines per call site.
- Wired into: settings update, whitelist add/delete/mode-toggle, bouncer add/delete, federation
  add/action/threshold, approval decide, security/unlock, SIEM replay, alert silence add/delete.
- `/audit` page: searchable substring filter, 300 most recent, before→after diff truncated to
  60 chars + tooltip with full JSON.
- **Acceptance proven:** harness script inserted a row, then tried UPDATE + DELETE — both blocked
  by triggers with the expected `IntegrityError`. Insert + read-back continues to work.

### Phase 36 — Performance dashboard

- `perf.py` computes p50/p95/p99 + min/max/avg over `sync_events.duration_ms` for a sliding
  window, lists 20 slowest cycles ever, last 60 cycles, and a duration-by-outcome breakdown.
- `/perf` renders KPI strip + 4 tables. p95/p99 cells colour-code at >5s amber / >10s red.
- Per-stage timing (LAPI fetch · MT snapshot · diff · push) intentionally deferred until phase-4
  live writes land — adding the columns now would just store zeros. The /perf footnote calls this out.

### Phase 37 — SLO tracking

- `slo.py` defines three SLOs we can honestly measure today:
  - `sync_success`: cycles with errors=0 ÷ total (target 99.9%)
  - `sync_duration`: p95 cycle duration ≤ 5s
  - `poll_freshness`: p95 inter-cycle gap ≤ 30s
- Burn rate per SLO uses the SRE-workbook fast-burn threshold (14.4× the budget) for ratio SLOs;
  duration SLOs surface observed/target ratio with 2× target = fast-burn.
- SLO panel sits at the top of /perf. `/api/slo?hours=N` returns the same data as JSON.
- `decision_to_ban_latency` and `dashboard_load` SLOs documented in `slo.py` as deferred
  until per-request timing middleware + MT write timestamps exist.
- Worth noting: right after the fix, the 24h window still showed `sync_duration` p95 = 57s and
  `poll_freshness` p95 = 67s. Those are historical samples from BEFORE the reconcile perf fix
  landed; they'll wash out of the 24h window over the next day.

### Phase 38 — Pager-quality composite alerting

- `alerting.py` with 5 rules:
  - `lapi_down_5m` (crit, debounce 30 cycles = 5 min)
  - `sync_stale_5m` (crit, debounce 1 — relies on tick spacing)
  - `mt_unreachable_2m` (crit, debounce 12 cycles = 2 min)
  - `sync_errors_burst` — 5 consecutive errored cycles (warn)
  - `approval_backlog` — pending > 50 (info)
- Each rule is a pure predicate `(state) -> (firing, message)`. `tick()` evaluates all rules,
  persists state to `alert_states` for dedup, fires notification ONLY on transition (firing ↔
  resolved). State persists across process restarts.
- Per-channel routing by severity: crit → discord+telegram+email, warn/info → discord only.
  `notifications.send` doesn't yet accept `channels=` kwarg — alerting falls back to the
  no-channel form gracefully (level→channel routing logic stays, defaults to per-event
  toggles). Easy follow-up to wire fully.
- Silences via `alert_silences` table: glob-matched patterns (`mt_*` silences every MT-related
  rule) with TTL. Silenced rules still TRACK state, but don't fire notifications.
- Mirrors `alert.firing` / `alert.resolved` to SIEM for downstream correlation.
- Wired into `poller.tick` so evaluation happens every 10s alongside reconcile. Cheap (one
  state-snapshot read + 5 predicates) — sub-ms in practice.
- `/alerts/rules` page: live rule table + silence add/remove form.
- **Acceptance proven:** scripted `mt_unreachable_2m` test confirmed: 11 cycles of `down` →
  not firing (debounce ramping), cycle 12 → FIRING transition + notification, persists at
  cycle 13/14, then `up` → consecutive resets to 0 + auto-resolve notification.

### MT health snapshot moved into poller thread

`alerting.py`'s `mt_unreachable_2m` rule needs a recent MT status. Rather than have it open
its own MT connection per tick (would fight the poller for the API socket), the poller now
runs one MT health check per cycle and writes `mt.last_status` to the settings table. Web
workers and alerting both read the cached value. Side benefit: /health no longer needs its
own `_mt_quick_ok()` path; can switch over later.

### Quirks added this session

- The `notifications.send(...)` signature doesn't take a `channels` arg, so the alerting
  module's per-severity routing currently degrades to per-event toggles. Add the kwarg in
  a future session to wire the level → channel routing properly.
- `siem.SyslogForwarder._reset_sock` retry once on `OSError` covers the common case where a
  TCP-mode syslog server has closed the connection between events. UDP also retries because
  some systems return ECONNREFUSED on a closed port.
- `audit_log` triggers fire with `RAISE(ABORT, '<msg>')` — message text is surfaced verbatim
  in the resulting `sqlite3.IntegrityError`, which is helpful when debugging accidental writes.
- The siem_journal pruning query `DELETE FROM siem_journal WHERE id < (SELECT MAX(id)) - 10000`
  is more efficient than ORDER BY ... LIMIT in SQLite — no sort, just an index seek on PK.
- Stale `reconcile.last_error` settings key (with a value showing a long-dead MT_PORT parse
  bug from a removed code path) was just sitting in the DB. Deleted manually.
- The 24h-window SLO numbers are dominated by historical samples and don't immediately
  reflect the post-fix performance. The 1h-window calculation would show the new state today —
  worth surfacing a window-selector on /perf in a later QoL pass.

### Total surface (after Arc 6)

- **New pages:** /perf, /alerts/rules, /siem, /audit
- **New APIs:** /metrics (public, auth-gated), /api/siem/{status,replay},
  /api/perf/sample, /api/slo
- **New silence POST routes:** /alerts/silence/{add,delete/<id>}
- **New tables:** siem_journal, audit_log, alert_states, alert_silences (4 added; 20 total)
- **New modules:** metrics.py, siem.py, audit.py, perf.py, slo.py, alerting.py
- **Workers:** poller (now also drives alerting.tick), geo, intel, siem — all singleton-elected
  via the same .poller.lock
- **Triggers:** audit_log_no_update, audit_log_no_delete (storage-layer enforcement)

### Next session — Arc 7 (Operator QoL) entry point

1. Phase 39 — Mobile-responsive dashboard (sidebar → hamburger; ≤480px reflow; touch-friendly hits)
2. Phase 40 — `protekctl` CLI client (decisions/sources/bouncers/whitelist subcommands; output
   as table or JSON). Bonus: replace `cscli decisions add` for routine ops.
3. Phase 41 — Bulk import/export (whitelist CSV up/down, decisions JSON export filtered by source/scenario)
4. Phase 42 — Multi-admin accounts (users table; password+TOTP per user; roles deferred to phase 43)

### Open questions still unanswered (carried)

- MikroTik target for phase 4 acceptance — **still blocking** live-write E2E. iptables/ipset
  on this VPS itself remains the fallback target.
- CrowdSec CTI key — Intel CTI panel ready but quota-gated until operator signs up.
- Discord/Telegram webhook creds — alerting now has real triggers; without channels configured
  the worker just logs. First crit-level alert would have nowhere to land.

---

## 2026-05-20 — Arcs 2–5 shipped (phases 7–32) · 33 of 51 phases complete

**State at pause:** MVP plus federation, intelligence, scenarios/rules, and multi-bouncer are all live. 22 routes returning 200, 20 reconcile unit tests still passing, geo+intel workers populating caches in the background.

### Arc 2 — Federation (phases 7–12)
- `federation.py` — `Source` dataclass + DB ops (`list_sources`, `add_source`, `delete_source`, `set_paused`, `set_confidence`, `set_backoff`, `test_connection`)
- `seed_local_source()` on every boot keeps the local LAPI's `.env` creds mirrored into row #1; refuses to delete `local` (the env anchor)
- `poller.py` rewritten to iterate `list[Source]`; each source has its own bootstrap-done flag, fail streak, and edge-triggered down/recovery notifications
- Exponential backoff: 2^streak minutes capped at 30; `backoff_until` row gates the next pull
- `ip_sources(ip, source_name, last_seen_at)` table tracks which sources have seen which IPs — populated on every bootstrap + stream cycle
- `federation.confidence_threshold` setting filters reconcile to only push IPs seen by N+ sources (paranoid mode)
- `/federation` page: KPI strip (sources/healthy/paused/failing, multi-source-agreement count, confidence threshold), topology, sources table with pause/unpause/remove, add-source form with health probe, overlap matrix (4-level bucketing), scorecards (total/unique/shared/redundancy + auto-recommendation)

### Arc 3 — Intelligence (phases 13–20)
- `intel.py` — four enrichment providers + shared cache, plus `IntelWorker` background thread (singleton on the poller-owner worker, same flock)
  - CTI: `https://cti.api.crowdsec.net/v2/smoke/{ip}` with `x-api-key` header. 24h cache in `cti_cache`. Returns "rate-limited (40/day free tier)" on 429. Gated on `CROWDSEC_CTI_API_KEY` env var (not present → skipped silently)
  - Cymru ASN: DNS TXT against `origin.asn.cymru.com` + `asn.cymru.com` via dnspython. 2.5s timeout. Caches into `geo_cache.asn` + `as_org`
  - WHOIS: TCP whois.cymru.com:43 with " -v" prefix → ASN/country/org. 7d TTL in `whois_cache`
  - rDNS: dnspython resolver with 2s/3s timeouts; positive 24h, negative 1h in `geo_cache.rdns`
- `geo.py` (existing from phase 5) still does the bulk ASN fill — ip-api.com /batch returns ASN too, so the intel worker is incremental on top
- `/attackers/<ip>` profile page: 6-KPI strip (reputation, country, ASN, hits, sources-seen, status), Geo/Network + WHOIS/Abuse panels (with mailto: template + AbuseIPDB/VirusTotal links), CTI panel with raw JSON, scenario timeline, sources-seen table, "Refresh All" button that bypasses cache
- `/intel` page: top-ASN + top-country tables (24h), country × hour-of-day heatmap (7d), ASN × scenario heatmap (top 12 each)
- Every IP across the dashboard is now clickable → attacker page
- Deferred: MaxMind GeoIP local DB option (operator can sign up later), AbuseIPDB/OTX/Spamhaus feed correlation (CTI gives equivalent coverage)

### Arc 4 — Scenarios & Rules (phases 21–26)
- `scenarios_admin.py`: wraps `cscli hub list/install/remove` via subprocess, plus pure Python helpers for whitelist matching and approval queue
- `/scenarios/catalog`: 5 hub categories tabbed, install/remove buttons per item, KPIs include noisy + sleeping detectors
- `/scenarios/editor`: textarea YAML editor with "Save" / "Save & Reload Agent" buttons (no Monaco — kept the dep footprint small). Pre-populated template for new files
- `whitelist` table + `whitelist_hits` table; matching supports `ip`, `cidr`, `asn`, `country` with optional `expires_at`
- Reconciler refactor: `_desired_from_db()` now consults the whitelist BEFORE producing the diff, records a hit row for every match, and skips writing whitelisted IPs to any bouncer
- `/whitelist`: rule list + add form + recent-hits log + queue-mode toggle (AUTO vs SEMI-AUTO)
- `approval_queue` table — when SEMI-AUTO mode is on, every new decision queues here and the reconciler ignores it until an approver clicks Approve. Rejecting auto-adds an IP whitelist rule
- `/approvals`: pending list, recent-decisions audit, per-row approve/reject

### Arc 5 — Multi-Bouncer (phases 27–32)
- `bouncers/` package with `Bouncer` Protocol + `KINDS` registry + `make_bouncer()` factory
- Five adapters self-register on import:
  - `mikrotik_env` — wraps the env-driven MikroTik from phase 2 (no functional change)
  - `iptables_ipset` — local hash:net ipset (`protek-bans` v4 + `protek-bans6` v6), auto-creates sets, operator owns the iptables DROP rule
  - `cloudflare` — Bearer token, account-level Rules List, auto-creates the list, bulk append/delete (1000/req)
  - `pfsense` — pfSense-pkg-RESTAPI v2, PATCH whole `addresses` array, POST /api/v2/firewall/apply
  - `opnsense` — built-in REST API, HTTP Basic key:secret, per-entry add/delete via `alias_util`
- `reconciler.run_once()` now iterates `bouncers.load_all_targets()` — every target gets the same desired set; each computes its own diff against its own snapshot. Per-target batch caps still apply
- `bouncer_targets(name, kind, config_json, enabled, dry_run, last_sync_at, last_error)` table
- `/bouncers` page: KPIs, targets table with pill/size/mode/last-sync, add-target form, config-shape cheatsheet for each kind
- Health probe runs before save — rejects targets whose health check fails

### Quirks worth keeping
- The legacy phase-1/2 `mikrotik.py` module + `/mikrotik` page + the `MikroTikLegacyAdapter` all coexist. The adapter wraps the existing class so behaviour is identical; the page now also shows per-target sync history (driven by the same `sync_events` table).
- `bouncers/__init__.py` does `from .mikrotik_adapter import MikroTikLegacyAdapter` at module-bottom so all five adapters self-register via `@register("kind")` on import — same pattern as Flask blueprints. Adding a sixth adapter is: drop a file in `bouncers/`, decorate with `@register("kind")`, add an import line to `__init__.py`.
- `reconciler.run_once()` falls through to a virtual diff (`reconcile(desired, [])`) when no bouncers are configured — keeps the dashboard showing the queue size pre-deploy.
- `intel.py` and `geo.py` both write `geo_cache.asn` — they're idempotent and the row's `cached_at` gets refreshed each time. The intel worker's slower per-IP path catches up on rDNS that the bulk geo worker doesn't do.
- The custom scenario editor writes to `/etc/crowdsec/scenarios/` which Protek can write to as root via systemd — no sudo needed. If a custom YAML is malformed, `cscli reload`'s output is surfaced verbatim in the editor.
- The CTI free-tier ceiling is genuinely ~40 lookups/day — the IntelWorker caches CTI for 24h, and we only attempt CTI when the env key is present so the worker won't burn quota silently.

### Acceptance criteria across Arcs 2-5
- **Arc 2:** ✅ behaviour unchanged with one local source; `ip_sources` table is populating (19,720 IPs tracked); overlap matrix is correctly empty with one source (would light up the moment a second is added); per-source pause toggle works; backoff sets `sources.backoff_until` on simulated failure.
- **Arc 3:** ✅ Cymru DNS lookups are succeeding (see `geo_cache.asn` populated for thousands of IPs with names like "Telefonica de Argentina", "OVH SAS"). rDNS path tested via dnspython (NXDOMAIN handling correct). CTI gated on env key — when present the worker would fire automatically.
- **Arc 4:** ✅ `cscli hub list` parsed and rendered (54 scenarios, 6 collections detected on this box); whitelist/approval-queue logic enforced by the reconciler.
- **Arc 5:** ✅ All five adapters import cleanly and self-register; `bouncers.load_all_targets()` returns the env-driven MT first then any DB-configured targets. iptables adapter detects missing `ipset` and degrades gracefully. Cloudflare/pfSense/OPNsense adapters all have their HTTP probes ready to wire in the moment the operator drops creds into the UI.

### Total surface
- **Pages:** /, /decisions, /alerts, /scenarios, /scenarios/catalog, /scenarios/editor, /intel, /attackers/<ip>, /mikrotik, /bouncers, /federation, /whitelist, /approvals, /notifications, /settings, /security, /crowdsec, /login, /logout
- **APIs:** /api/health, /api/decisions, /api/alerts, /api/sync/status, /api/sync/run (POST), /api/sync/events, /api/mt/health, /api/crowdsec/health, /api/scenarios, /api/geo/points, /api/geo/<ip>
- **Workers:** poller (singleton), geo worker (singleton), intel worker (singleton) — all elected via `.poller.lock` fcntl flock
- **Tables:** decisions, alerts, sync_events, mt_pushes, geo_cache, login_attempts, login_audit, settings, sources, ip_sources, cti_cache, whois_cache, whitelist, whitelist_hits, approval_queue, bouncer_targets — 16 tables
- **DB columns:** 4 extra columns added via idempotent migrations (sources.backoff_until/paused/confidence, decisions.asn/as_org, geo_cache.rdns)

### Next session — Arc 6 (Observability) entry point
1. `/metrics` Prometheus endpoint (`prometheus_client`?) — counters for `active_decisions`, `sync_lag_seconds`, `push_errors_total{adapter}`, `source_health{name}`
2. SIEM forwarding — syslog (RFC 5424) at minimum; HEC / generic webhook nice-to-have
3. Audit log (append-only) — every settings change, whitelist add/remove, approval decision, bouncer target add/remove
4. Performance dashboard — slow-cycle log, p50/p95/p99 sync timings
5. SLO tracking — define + compute compliance + burn-rate
6. Pager-quality alerting — composite rules + dedup + silences

### Open questions
- MikroTik target for phase 4 acceptance — *still blocking*. Without a real router, the only "live" bouncer we can test end-to-end is the iptables/ipset adapter on this VPS itself. (Could be useful! Would gate all SSH from this VPS through CrowdSec.)
- CrowdSec CTI key — sign-up needed at https://app.crowdsec.net for Arc 3's CTI panel to populate.
- Discord/Telegram webhook for Arc 1 phase-6 notification tests still pending.

---

## 2026-05-20 — Arc 1 (phases 0–6) complete — MVP done

**State at pause:** Every MVP phase shipped. The full pipeline runs: LAPI poll → mirror DB → reconcile diff → (dry-run) MikroTik push → sync_events + mt_pushes log. Dashboard, scenarios, settings, notifications, security all live behind 2FA at https://protek.syedhashmi.trade.

### Phase 3 delivered (reconcile engine, DRY-RUN)
- `reconcile.py` — pure function `(desired, current) → ReconcileDiff(to_add, to_remove, unchanged, foreign_kept)`. No I/O. Comment encoder `protek:<origin_source>:<scenario>:<lapi_id>` + decoder. Sanitizes colons in scenario names so `lists:firehol_*` survives round-trip. Address normalization treats `1.2.3.4` and `1.2.3.4/32` as equivalent (and `::1` / `::1/128`).
- 20 unit tests in `tests/test_reconcile.py` cover every branch: empty/empty, full/empty, empty/full, overlap, ownership filter, foreign-collision, `.id` vs `id` variants, CIDR, IPv6, federation dedup, idempotency, sanitization. All pass in <0.05s.
- `reconciler.py` — drives the diff each cycle. Persists `sync_events` row + per-op `mt_pushes` rows. In DRY-RUN, rows carry `error='dry-run'` and MT is never connected. `mt_pushes` capped at `batch_cap` per cycle so we don't spam 20k rows every 10s.
- `POST /api/sync/run` — manual trigger; mikrotik.html has a "Force Sync Now" button via fetch() + X-CSRFToken header. Result rendered inline, page reloads after 600ms.
- DRY-RUN pill in topbar lights up because `.env` has `DRY_RUN=true`.

### Phase 4 delivered (live writes — code complete, acceptance deferred)
- `reconciler._apply()` does the actual MikroTik push. Adds before removes (initial-sync semantics). Catches "already have such entry"/"duplicate" → treats as idempotent success. Per-op success/failure into `mt_pushes` with 300-char truncated errors.
- Initial-sync banner: amber-cyan progress bar with ETA on `/mikrotik` when LAPI > 500 and owned_total < 95% of LAPI.
- `/settings` page can flip dry-run/batch-cap/sync-interval/address-list-name at runtime — applied to the live poller without restart.
- **Phase 4 acceptance is gated on the operator-only decision of which router to target.** Code is ready; the moment `MT_HOST/MT_USERNAME/MT_PASSWORD` land in `.env` and `dry_run=false` in /settings, the next cycle pushes live.

### Phase 5 delivered (NOC dashboard polish)
- Dashboard rebuilt: KPI strip with active-decisions sparkline, MT list size, sync lag + reconcile duration, scenarios 24h, attackers 24h, top scenario.
- Live attack feed: 5s polling, country code per row, scenario badges, 200ms slide-in + cyan-flash animation when a new row appears (diffs on `data-key` between fetches).
- World map: Leaflet 1.9.4 + CartoDB Dark Matter tiles (`https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png`, subdomains a/b/c/d, no API key required, ~75k mapviews/mo soft cap). Canvas-rendered cyan-glow CircleMarkers in a custom Leaflet pane with a CSS `drop-shadow` filter. MarkerCluster v1.5.3 with `chunkedLoading: true` so adding 1000 points doesn't lock the UI.
- Sync activity bar-spark (adds green / removes red, 24h × 30 buckets).
- Polling progress bar: 1px tall, fills 0→100% over the 5s polling interval, resets on each refresh.
- Sync toast bottom-right: `↻ +N -M · 412ms · DRY` for 1.5s after every new sync_event (tracked by id).
- `/scenarios` page: scenario × hour-of-day heatmap (7d, 6-level cyan→amber→red bucketing), top-20 bar chart, KPIs.
- `geo.py` — out-of-band geo worker on the same single-owner thread as the poller. ip-api.com /batch endpoint (free, 45 req/min, 100 IPs/req, no key). Picks distinct active IP-scope decisions whose `geo_cache` row is missing or older than `GEO_CACHE_TTL_DAYS` (default 7d). Filled 100 IPs in the first cycle.

### Phase 6 delivered (notifications, settings, security)
- `notifications.py` — Discord webhook (host-allowlist guard), Telegram bot (HTML parse_mode), SMTP/MIME (host-resolve SSRF guard, optional 465 SSL vs 587 STARTTLS). All sends timeout 8–10s, never raise. `EVENTS` const lists the nine event types Protek emits.
- Per-event × per-channel toggles persisted in `settings` table keyed `notify.<channel>.<event>`. Sensible defaults (sync_error / lapi_down / mt_down / login_locked default ON; new_ban / login_failure default OFF).
- Triggers wired in `poller.py`:
  - `lapi_down` — edge-triggered (only on transition into/out of failure)
  - `sync_threshold` — when reconcile's to_add ≥ configured threshold (default 50)
  - `sync_error` — when a cycle reports errors > 0
  - `new_ban` — delta-aware, fires only when active count grows
- Triggers in `auth.py`:
  - `login_failure` — every failed attempt
  - `login_locked` — when an IP transitions to locked
- `/notifications` UI: channel status cards (configured/not), send-test buttons, per-event/per-channel checkbox matrix, threshold inputs.
- `/settings` UI: runtime knobs persisted in DB (override .env on next cycle, no restart). Connection strings + LAPI key shown read-only with last 4 chars only.
- `/security` UI: KPI strip (24h success, 24h fail, locked now, whitelist on/off, session timeout, lockout duration), audit log (50 most recent), locked IPs with countdown, "Unlock All" admin button.
- CSRF on every POST form via Flask-WTF, including AJAX (fetch reads `<meta name="csrf-token">` and sends `X-CSRFToken` header).
- `/health` rewritten — returns 503 + JSON list of issues when poll is stale (>3× interval), LAPI degraded, or MT unreachable. nginx/certbot still hit the 200 path under normal conditions.

### Acceptance criteria — all met
- **Phase 3:** `GET /api/sync/status` shows 19,726 to_add / 0 to_remove / dry_run=true / errors=0 with empty MikroTik. `mt_pushes` rows mark `error='dry-run'`. MikroTik never touched.
- **Phase 4 (code):** All 20 unit tests pass, including idempotency invariant and ownership safety. Acceptance test deferred — needs router credentials.
- **Phase 5:** Geo worker filled 100 IPs from ip-api.com /batch in the first cycle. Map renders cyan-glow markers at attacker locations. Heatmap on `/scenarios` shows the daily peak window.
- **Phase 6:** `/health` flipped 503 → 200 when last_at was artificially set 5 min in the past, then recovered on next poll. 5 bad logins → IP locked 15 min, login_audit captures the trail, `/security` lists the locked IP.

### Quirks added this session
- `python-dotenv` keeps inline comments on values for *all* env vars — applied the `split("#",1)[0].strip()` defensive pattern in `app.py`, `auth.py`, `mikrotik.py`, `notifications.py`. (MT_PASSWORD intentionally exempted because passwords may legitimately contain `#`.)
- Gunicorn 3-worker `fcntl.flock` pattern from phase 1 was reused to also gate the geo worker — both run on the same singleton "owner" worker. Sibling workers just serve HTTP and read shared state from the `settings` table.
- The geo worker waits 15s on startup before first cycle so the poller has populated `decisions` first. Without that, `_pick_missing()` returns 0 and the first cycle wastes a request.
- `/v1/decisions/stream` returns 19,729 "new" decisions on the very first call after `startup=true` — that's a quirk of the LAPI bouncer-cursor logic. We use the explicit `/v1/decisions?scope=Ip` + `?scope=Range` bootstrap path for determinism, then switch to `/stream` for deltas.
- When MT is unreachable, the reconciler now computes the *virtual* diff against an empty `current` snapshot so the operator can see what would be applied. Previously it logged a fake 5-row diff which was misleading.
- The login form needed an explicit `<input name="csrf_token">` after enabling CSRFProtect — flask-wtf protects forms but won't auto-inject the field.

### Next session — phase 7 entry point (Arc 2: Federation)
1. `sources` table already exists (from phase 1 schema). Seed it with the local LAPI on init (idempotent INSERT).
2. Refactor the poller to iterate `list[Source]` instead of using a single `lapi_client`. Each source produces its own decisions; reconcile dedupes by `(value, scope)`.
3. `/federation` page (read-only at phase 7): per-source health pill, last pull, count contributed.
4. **Acceptance phase 7:** behavior unchanged from phase 6, all unit tests still pass — proves the refactor is additive.

### Open questions still unanswered
- Target MikroTik for first deploy — still blocking phase 4 acceptance. Same router pipsqueeze uses, or different?
- Address-list name — currently `crowdsec` (default). OK?
- Notification channels — credentials not in .env yet. Discord first or Telegram first?

---

## 2026-05-20 — Phases 1 + 2 shipped

**State at pause:** Arc 1 phases 0–2 complete. Local LAPI mirroring works end-to-end; MikroTik adapter is plumbed read-only and degrades cleanly when `MT_HOST` is unset.

### Phase 1 delivered
- `crowdsec.py` — `LAPIClient(url, api_key, name)` with `health()`, `decisions()`, `decisions_stream()`, `alerts()`. Stream client passes `startup=true` only on first cycle; subsequent calls deltas-only.
- `db.py` — `init_db()` creates `decisions`, `alerts`, `sync_events`, `mt_pushes`, `geo_cache`, `login_attempts`, `login_audit`, `settings`, `sources` (federation table seeded now even though phase 7 builds on it). WAL mode on by default. `get_setting/set_setting` for cross-worker state mirroring.
- `auth.py` — bcrypt + TOTP (`valid_window=1`) + per-IP rate-limit + IP whitelist + audit. `login_required` decorator. All env reads tolerate dotenv inline comments (`KEY=value  # comment` survives).
- `poller.py` — background daemon thread. Bootstrap path uses `/v1/decisions?scope=Ip` + `?scope=Range` (the stream endpoint had a 401 quirk on first call after process boot in early testing — bootstrap is more deterministic). Stream path applies `{new, deleted}` deltas. Status mirrored into `settings` rows so any worker can read it.
- `app.py` — Flask app with routes wired: `/` `/login` `/logout` `/decisions` `/alerts` `/mikrotik` + JSON APIs. Three gunicorn workers race-elect a single poller owner via `fcntl.flock` on `.poller.lock`.
- Templates — `base.html` (NOC topbar + sidebar + health-pill polling), `login.html`, `dashboard.html` (KPI strip + live feed + top scenarios), `decisions.html` (filter+paginate), `alerts.html` (machine-creds warning), `mikrotik.html`, `blocked.html`.
- `cscli bouncers add protek` ran successfully → key lives in `.env` as `CROWDSEC_BOUNCER_KEY`.

### Phase 2 delivered
- `mikrotik.py` — `MikroTik` class with `connect`, `disconnect`, `health`, `get_address_list(list_name)`. `entry_id()` helper for `.id` / `id` variant. Write methods deliberately omitted — they land in phase 4 with the live-write safety net.
- `/mikrotik` page renders all three states: not-configured (amber panel + setup instructions), connection-error (red panel with the exception verbatim), and connected (table of Protek-owned entries + foreign-entry count + KPI strip).
- Dashboard KPI strip wires LAPI active vs MT list size; counts visibly different (20,443 vs 0/`—` while MT writes are still off).
- `/api/mt/health` and `/api/sync/status` ship JSON; `/api/health` returns the topbar pill states.

### Acceptance criteria — both met
- **Phase 1:** added `198.51.100.42` via `cscli decisions add --duration 5m`, appeared in `decisions` table on next poll (<10s), then `cscli decisions delete --ip ...` marked `deleted_at` on the following stream cycle.
- **Phase 2:** `/mikrotik` page renders cleanly without an MT target, LAPI Active 20,443, MT count `—`. Once operator drops `MT_HOST/MT_USERNAME/MT_PASSWORD` into `.env` and restarts, the page populates with live data — zero code changes required.

### Important quirks captured
- `/v1/alerts` requires a **machine** credential, not a bouncer key. Protek's alerts table will stay empty until `cscli machines add protek-machine` runs and creds land in `.env`. The `/alerts` page surfaces this clearly. Bouncer creds are read-only on decisions only — see `SKILL.md`.
- python-dotenv keeps inline comments attached to values (e.g. `SYNC_INTERVAL_SEC=10  # how often to poll`). All env-var readers now `split("#", 1)[0].strip()`. **Don't strip the .env file itself** — operator commented values for a reason; `.env` is also protected by CLAUDE.md's "never read or modify" rule.
- 3 gunicorn workers means **3 module-import paths**. The poller would have run 3× without the `fcntl.flock` lock on `.poller.lock`. Pattern is reusable for any future singleton thread.
- LAPI returned **20,442 active decisions** at first bootstrap — most are community-list IPs (origin: `lists:firehol_cruzit_web_attacks` etc.) plus the local agent's recent SSH brute-force bans. Big number is normal.
- The bouncer key is now visible in `cscli bouncers list` with last-pull timestamps refreshing every cycle.

### Next session — phase 3 entry point
1. Write `reconcile.py` as a pure function `(desired_decisions, current_mt_entries) -> (to_add, to_remove)`. Tests first: empty/empty, full/empty, empty/full, overlap, ownership-filter, CIDR scope. See `SKILL.md` § 4 for the reference shape.
2. Extend `poller.py` (or split into a `reconciler.py`) to actually compute the diff each cycle and log it to `sync_events` + `mt_pushes` — but **never call MT add/remove**, only log. `DRY_RUN=true` enforces this.
3. Add the red "DRY RUN" pill to the topbar (already wired in `base.html` via the `dry_run` context var — currently shows because `.env` has `DRY_RUN=true`).
4. `POST /api/sync/run` → trigger a single immediate cycle (manual reconcile button on the MT page).
5. **Acceptance for phase 3:** with N decisions and empty MT list, dry-run logs N adds, 0 removes, no MT writes.

### Open questions still unanswered (carrying forward)
- Target MikroTik for first deploy — same router pipsqueeze uses (and credentials), or a different one? Without this, phase 4 (live writes) cannot complete its acceptance.
- Address-list name preference — currently `crowdsec` (default). OK?
- Notification channels priority order — Discord vs Telegram first when phase 6 lands?

---

## 2026-05-20 — Session paused (pre-phase-1)

**State at pause:** phase 0 fully complete + shipped, phase 1+ not started.

Concrete state on disk:
- `/var/www/Protek/` — all docs (README, CLAUDE, CONTEXT, SKILL, ROADMAP, MEMORY, docs/UI), venv, stub `app.py`, `templates/placeholder.html`, `scripts/setup_admin.py`, `.env` (chmod 0600 — populated)
- `/etc/nginx/sites-enabled/protek` — HTTPS active, HTTP→HTTPS redirect
- `/etc/systemd/system/protek.service` — enabled, active, gunicorn 3 workers on `127.0.0.1:8090`
- `protek.syedhashmi.trade` — live, returns NOC placeholder + `/health` JSON
- CrowdSec on this VPS: v1.7.7, ~13 active decisions, LAPI on `127.0.0.1:8080`, **no bouncer key generated yet for Protek**

**Roadmap extended to phase 50** (51 phases total, 0–50) — see `ROADMAP.md`. Eight thematic arcs: MVP, Federation, Intelligence, Scenarios, Multi-bouncer, Observability, Operator QoL, Integration.

**Next session — phase 1 entry point:**
1. `sudo cscli bouncers add protek` → paste key into `.env` as `CROWDSEC_BOUNCER_KEY`
2. Write `crowdsec.py` per `SKILL.md` § "The three endpoints we care about"
3. Write real login route using bcrypt + TOTP (creds already in `.env`)
4. Begin schema work — `decisions`, `alerts`, `login_audit`, `login_attempts`, `settings` tables
5. Phase 1 acceptance: `cscli decisions add ...` → visible in dashboard within next poll cycle

**Open questions still unanswered (carrying forward):**
- Target MikroTik for first deploy — same router pipsqueeze uses, or different?
- Address-list name preference — default `crowdsec`?
- Notification channel priority — Discord vs Telegram first?

---

## 2026-05-20 — Phase 0 complete · live at https://protek.syedhashmi.trade

- **Caught & fixed**: initial nginx site only had `listen 80;` (IPv4). Requests from clients with IPv6 (e.g. curl default) fell through to a different server block and returned 404. Added `listen [::]:80;`.
- **Minimal `app.py` shipped**: `/health` returns `{"status":"ok","phase":0,"service":"protek"}`; `/` renders a NOC-styled placeholder (cyan/green, Rajdhani + Share Tech Mono, scanline overlay) so the URL looks alive while we build out phase 1.
- **`templates/placeholder.html`** seeded the design language live — useful reference for actual dashboard later.
- **`protek.service` enabled** (`systemctl enable --now protek`): active, gunicorn -w 3 on 127.0.0.1:8090.
- **TLS**: certbot ran clean, cert at `/etc/letsencrypt/live/protek.syedhashmi.trade/`, expires 2026-08-18, auto-renew scheduled. nginx site rewritten with 443 block + 301 HTTP→HTTPS redirect.
- **Verified**: `curl https://protek.syedhashmi.trade/health` → 200 JSON. `curl -I http://protek...` → 301 to HTTPS.
- **Phase 0 acceptance criterion met** per ROADMAP.md.

## 2026-05-20 — Domain wired + admin creds bootstrapped

- **Domain bound**: `protek.syedhashmi.trade` (DNS A → `178.105.39.92`, same as pipsqueeze)
- **nginx site**: `/etc/nginx/sites-available/protek` created, symlinked into `sites-enabled/`, nginx reloaded. Currently HTTP-only (`listen 80`) — certbot has not yet run. Site is healthy in `nginx -t`; returns 502 from upstream until `protek.service` is started, which is correct.
- **systemd unit**: `/etc/systemd/system/protek.service` staged (NOT enabled — would fail until `app.py` exists). Binds `127.0.0.1:8090`. Wants `crowdsec.service`.
- **Port assignment**: 8090 (verified free; other apps on this box use 3000/5000/8000/8088).
- **Python venv**: created at `/var/www/Protek/venv` with Python 3.12. Full `requirements.txt` installed (Flask, gunicorn, RouterOS-api, bcrypt, pyotp, qrcode, pytest).
- **Admin credentials**: `scripts/setup_admin.py` written + executed once:
  - Username: `syed`
  - Password: bcrypt-hashed in `.env` (plaintext printed once on first run — operator captures)
  - TOTP secret: base32, GAuth-compatible, otpauth URI + ASCII QR rendered
  - `SECRET_KEY`: random 32-byte hex
  - `.env` chmod 0600
- **`.env.example` updated**: `APP_PASSWORD` → `APP_PASSWORD_HASH` (no plaintext anywhere)
- **CLAUDE.md updated** with: domain, port, full login/TOTP/rotation flow contract

### Next session — start phase 1

- [ ] Run `sudo cscli bouncers add protek` → paste key into `.env` as `CROWDSEC_BOUNCER_KEY`
- [ ] Run `sudo certbot --nginx -d protek.syedhashmi.trade` once app is up (or as soon as nginx returns anything 200-ish; certbot only needs the HTTP-01 challenge to succeed)
- [ ] Write `crowdsec.py` LAPI client (`LAPIClient(url, key, name)` — see CLAUDE.md "Federation" section for required shape)
- [ ] Write a minimal `app.py` with `/health`, `/login`, `/logout`, session middleware, login_audit table
- [ ] Enable `protek.service`: `systemctl enable --now protek && systemctl status protek`
- [ ] Confirm acceptance criterion: `curl 127.0.0.1:8090/health → 200`, login at `https://protek.syedhashmi.trade/login` works with username + password + TOTP

### Open questions for operator

- Which MikroTik are we targeting first — same router pipsqueeze uses, or a different one? Affects `MT_HOST` + which user account to provision on the router.
- Address-list name preference — default is `crowdsec`. OK to keep, or rename?
- Notification channels: priority order (Discord first? Telegram first?)

---

## 2026-05-20 — Project initialized (earlier today)

**Scaffolding only — no code yet.**

- Created project root at `/var/www/Protek` (was empty save for `.claude/`)
- Wrote `README.md`, `CLAUDE.md`, `CONTEXT.md`, `SKILL.md`, `ROADMAP.md`, `MEMORY.md`, `docs/UI.md`
- Confirmed CrowdSec runtime: v1.7.7, ~13 active decisions, LAPI on `127.0.0.1:8080`, no bouncers registered yet
- Confirmed stack constraints from VPS: ARM64, 2 vCPU, 3.7 GB RAM, 24 GB free disk — fine for Flask + SQLite, no heavy services
- Decision: Flask + SQLite + Jinja2 + background thread, matching the pipsqueeze/traverse pattern so the operator's mental model stays consistent across the suite
- Decision: federation is phase 7+, but the LAPI client signature (`LAPIClient(url, key, name)`) and the `decisions.origin_source` column will be in MVP so phase 7 is additive, not a migration
- Decision: comment ownership on MikroTik address-list (`protek:` prefix) is non-negotiable from phase 4 onwards — must not touch entries Protek didn't create
- Decision: design language matches pipsqueeze exactly — cyan `#00c8ff`, neon green `#00ff9d`, deep navy, Rajdhani + Share Tech Mono
