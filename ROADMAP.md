# ROADMAP.md — Protek

Phased plan, 0 → 50. Each phase has an explicit **acceptance criterion** — it isn't done until that's green.

Phases are arranged into **arcs**. Arcs are thematic groupings; the order *within* an arc is mostly fixed, the order *between* arcs is flexible and may interleave based on operator priorities. Whatever ships, ships in numerical order.

| Arc | Phases | Theme |
|---|---|---|
| 1 | 0–6 | **MVP** — local CrowdSec → MikroTik with NOC dashboard |
| 2 | 7–12 | **Federation** — cross-box decision sharing |
| 3 | 13–20 | **Intelligence & enrichment** — CTI, GeoIP, WHOIS, ASN, threat feeds |
| 4 | 21–26 | **Scenarios & rules** — browse/edit/test CrowdSec scenarios, whitelist UX |
| 5 | 27–32 | **Multi-bouncer / multi-target** — pfSense, OPNsense, iptables, Cloudflare, multi-MT |
| 6 | 33–38 | **Observability** — Prometheus, SIEM, audit, SLOs |
| 7 | 39–44 | **Operator quality of life** — mobile, CLI, RBAC, bulk ops |
| 8 | 45–50 | **Integration & extensibility** — webhooks, REST API, suite integration, 1.0 |

---

# Arc 1 — MVP

## Phase 0 — Project scaffolding ✅ complete

- [x] `README.md`, `CLAUDE.md`, `CONTEXT.md`, `SKILL.md`, `ROADMAP.md`, `MEMORY.md`, `docs/UI.md`
- [x] `.gitignore`, `.env.example`, `LICENSE`, `requirements.txt`
- [x] venv created, requirements installed
- [x] nginx site at `protek.syedhashmi.trade` (with IPv4 + IPv6 listeners)
- [x] systemd unit `protek.service` enabled
- [x] `scripts/setup_admin.py` — generates SECRET_KEY, bcrypt hash, TOTP secret
- [x] Admin credentials bootstrapped
- [x] Stub `app.py` with `/health` + NOC placeholder page
- [x] TLS via certbot, HTTP → HTTPS redirect

**Acceptance:** ✅ `curl https://protek.syedhashmi.trade/health` → 200 JSON.

---

## Phase 1 — Read-only CrowdSec client + login ✅ complete

- [x] `crowdsec.py` `LAPIClient(url, api_key, name)`: `health()`, `decisions()`, `decisions_stream()`, `alerts()`
- [x] Background poller hits stream every 10s, persists to `decisions` table (alerts stays empty until machine creds added — bouncer key cannot read `/v1/alerts`)
- [x] DB init + migration block in `init_db()` (`db.py`)
- [x] Login route — username + bcrypt password check → TOTP form → `pyotp.verify(valid_window=1)`
- [x] Session middleware, login_required decorator, login_audit table, rate-limit on `IP`
- [x] `/decisions` + `/alerts` pages (basic tables, NOC styling)
- [x] `/api/decisions`, `/api/alerts` JSON endpoints
- [x] `cscli bouncers add protek` → key in `.env`

**Acceptance:** ✅ `sudo cscli decisions add --ip 198.51.100.42 --duration 5m` appeared in the `decisions` table within next 10s poll cycle; `cscli decisions delete --ip 198.51.100.42` marked `deleted_at` on next cycle. Login requires password AND TOTP (verified via test client).

---

## Phase 2 — MikroTik connection + read-only mirror ✅ complete

- [x] `mikrotik.py` adapted from pipsqueeze: `connect()`, `get_address_list()`, `health()` (write methods deliberately omitted — added in phase 4)
- [x] `/mikrotik` page — address-list contents filtered to `protek:` comments; foreign-entry count shown separately
- [x] Dashboard KPI: LAPI active vs MT list count (clearly different until phase 4)
- [x] `/api/mt/health`, `/api/sync/status`
- [x] Connection failure → red pill + exact error in panel

**Acceptance:** ✅ MT page renders cleanly even with `MT_HOST` blank, showing the "Not Configured" panel; LAPI shows 20,443 active decisions; MT list size = `—`; counts visibly differ. Once `MT_HOST/USER/PASS` land in `.env`, the page will populate live without code changes.

---

## Phase 3 — Reconcile engine (DRY-RUN ONLY) ✅ complete

- [x] `reconcile.py` pure function `(desired, current) → ReconcileDiff(to_add, to_remove, unchanged, foreign_kept)`
- [x] 20 unit tests covering: empty/empty, full/empty, empty/full, overlap, ownership filter, foreign-collision, .id-vs-id, CIDR scope, /32 IPv4 + /128 IPv6 normalization, comment encode/decode round-trip, sanitization of colons in scenario names, federation dedup, idempotency
- [x] `reconciler.py` wired into poller — runs after every LAPI poll cycle
- [x] `DRY_RUN=true` enforced — `mt_pushes` rows marked `error='dry-run'`, MT never touched
- [x] `POST /api/sync/run` → manual trigger; renders JSON result; AJAX-driven button on `/mikrotik`
- [x] Red "DRY RUN" pill in topbar (driven by `dry_run` context var)

**Acceptance:** ✅ with 19,726 active decisions + unconfigured MikroTik, dry-run cycle logged 19,726 adds, 0 removes, batched first 200 into `mt_pushes`, wrote nothing to a router. Verified via `GET /api/sync/status`.

---

## Phase 4 — Live writes + ownership safety ✅ code complete (acceptance deferred)

- [x] Comment encoder/decoder `protek:<origin_source>:<scenario>:<lapi_id>` in `reconcile.py`
- [x] Ownership filter — `is_owned()` gates removals in `reconcile.reconcile()`, foreign entries counted as `foreign_kept`
- [x] Live writes wired in `reconciler._apply()` — adds first, then removes, capped at `BATCH_CAP` per cycle
- [x] Duplicate-add tolerance — catches "already have such entry"/"duplicate"/"already exists" and treats as idempotent success
- [x] Remove-missing tolerance — catches "no such item"/"not found"
- [x] Per-op success/failure logged in `mt_pushes` with truncated error text
- [x] Initial-sync progress banner on `/mikrotik` (cyan progress bar + ETA when MT empty + LAPI > 500)
- [x] Settings UI flip from DRY_RUN→LIVE without restart (poller picks up new `dry_run` flag on next cycle)

**Acceptance:** ⏳ **deferred** — full acceptance requires a real MikroTik target. `MT_HOST/MT_USERNAME/MT_PASSWORD` still blank in `.env`. Once set: flip `dry_run=false` in `/settings`, restart not required. Code path verified via unit tests + dry-run logging (every cycle correctly proposes the right diff).

---

## Phase 5 — NOC dashboard polish ✅ complete

- [x] KPI strip: active decisions + sparkline, MT list size, sync lag + cycle count + reconcile duration, scenarios 24h, attackers 24h, top scenario
- [x] Live attack feed: newest 20, 5s auto-refresh, country code per row, scenario badges, slide-in + cyan-flash animation for new rows
- [x] World map: Leaflet 1.9.4 + CartoDB Dark Matter tiles, canvas-rendered cyan-glow circle markers, MarkerCluster v1.5.3 with chunked loading; auto-attribution; +geo popups
- [x] Top Scenarios panel + Sync Activity bar-spark (adds green / removes red, 24h)
- [x] Health pills (LAPI / MT / Sync) in topbar, polled every 5s
- [x] `geo.py` background worker — ip-api.com /batch endpoint (45 req/min, 100 IPs/req, no key), TTL 7d, runs every 30s in single-owner thread
- [x] `/scenarios` page: heatmap (scenario × hour-of-day, last 7d, 6-level cyan→amber→red bucketing), top-20 bar chart, KPIs
- [x] Polling progress: 1px bar top of feed fills over 5s polling interval
- [x] Sync toast bottom-right: `↻ +N -M · 412ms · DRY` for 1.5s after each new sync_event

**Acceptance:** ✅ at-a-glance NOC. KPI strip → live feed → map; no Bootstrap. Geo worker filled 100 IPs in first cycle; map populates progressively across pageloads.

---

## Phase 6 — Notifications, settings, security hardening ✅ complete

- [x] `notifications.py` adapted from pipsqueeze patterns — Discord webhook, Telegram bot, SMTP/MIME, all with 8–10s timeouts, SSRF guards on hosts, per-channel `channel_configured()` gating
- [x] 9 event types: `new_ban`, `sync_threshold`, `sync_error`, `lapi_down`, `mt_down`, `login_failure`, `login_locked`, `hourly_digest`, `daily_digest`. Edge-triggered LAPI down/recovery in the poller, new_ban delta-aware
- [x] Per-event × per-channel toggles in `settings` table, with sensible defaults (sync_error / lapi_down / mt_down / login_locked default on; new_ban / login_failure default off)
- [x] `/notifications` page — channel status cards, send-test buttons, full toggle matrix, threshold inputs
- [x] `/settings` page — sync interval / batch cap / dry-run / address-list name persisted to DB and applied to the live poller without restart; .env still source of truth for secrets and connection strings (shown read-only)
- [x] `/security` page — KPI strip (success 24h, fail 24h, locked now, whitelist status, session timeout, lockout duration), audit log (last 50), locked-IPs table, "Unlock All" admin button
- [x] CSRF protection via Flask-WTF on all POST forms; meta tag in `base.html` for fetch() AJAX (`X-CSRFToken` header)
- [x] Secure + HttpOnly + SameSite=Lax cookies already in place
- [x] `/health` returns **503 + JSON list of issues** (`poller_disabled`, `poller_not_started`, `poll_stale`, `lapi_degraded`, `mt_unreachable`); flips back to 200 on recovery

**Acceptance:** ✅ `/health` correctly returned 503 with `["poll_stale"]` when last_at was artificially backdated, then recovered to 200 on next cycle. Lockout: 5 bad logins → IP locked for 15 min, audit log captures every attempt, `/security` lists the locked IP with countdown.

---

# Arc 1 — MVP complete ✅

All six MVP phases shipped. The bouncer pulls from CrowdSec, computes the diff, and would push to MikroTik if `MT_HOST` were configured (phase 4 acceptance gates on that one operator decision). Dashboard, notifications, settings, and security pages are live behind 2FA at `https://protek.syedhashmi.trade`.

---

# Arc 2 — Federation ✅ complete

## Phase 7 — Federation foundation ✅
- [x] `sources` table (already in phase-1 schema); `decisions.origin_source` from day one
- [x] `federation.py` — `LAPIClient(url, key, name)` instances per source, no `.env` reads in methods
- [x] Poller iterates `list[Source]`, dedupes by `(value, scope)` via reconcile.py
- [x] `federation.seed_local_source()` on every boot
- [x] `/federation` page — sources list, last pull, contribution counts

## Phase 8 — Add remote sources ✅
- [x] Add-source form with name/URL/key/confidence/test-connection
- [x] Per-source health pill in topology + sources table
- [x] Decision union: any source says ban → banned

## Phase 9 — Federation hardening ✅
- [x] Per-source exponential backoff (2^streak minutes, capped at 30)
- [x] Per-source edge-triggered down/recovery notifications
- [x] Pause-without-delete toggle
- [x] Verified TLS path (requests' default)

## Phase 10 — Cross-source agreement scoring ✅
- [x] `ip_sources` table tracks every (ip, source_name, last_seen_at) on bootstrap + stream
- [x] Confidence threshold setting; reconciler filters via SQL `HAVING COUNT(DISTINCT source_name) >= N`
- [x] Federation page shows "Multi-Source Agreement" KPI

## Phase 11 — Federation overview ✅
- [x] Topology diagram (CSS): sources → PROTEK hub → MikroTik
- [x] Cross-source overlap matrix with 4-level cyan-to-green bucketing

## Phase 12 — Source reputation tracking ✅
- [x] Per-source scorecards: total contributed, unique, shared, redundancy %
- [x] Auto-recommendations: "highly redundant — consider pausing" / "highly complementary"

---

# Arc 3 — Intelligence & Enrichment ✅ complete (CTI gated on key)

## Phase 13 — CrowdSec CTI ✅ (gated on `CROWDSEC_CTI_API_KEY` env var)
- [x] `intel.cti_lookup()` — `x-api-key` against `https://cti.api.crowdsec.net/v2/smoke/{ip}`
- [x] `cti_cache` table: reputation, score, classifications, behaviors, raw_json (24h TTL)
- [x] Attacker profile renders CTI panel with score + raw JSON
- [x] 429 detection ("rate-limited (40/day free tier)") surfaced cleanly
- [x] Lookups in background via `IntelWorker` when key present

## Phase 14 — ASN enrichment ✅
- [x] `intel.cymru_lookup()` via DNS TXT (`<rev>.origin.asn.cymru.com` + `AS{n}.asn.cymru.com`)
- [x] Per-decision `asn` + `as_org` columns populated by IntelWorker + geo worker (ip-api batch)
- [x] `/intel` top-ASNs widget; bonus: top-countries

## Phase 15 — GeoIP MaxMind option ⏳ (free-tier path only; MaxMind requires sign-up)
- [x] Geo worker uses ip-api.com /batch as the default (no key, 100 IPs/req)
- [ ] MaxMind GeoIP2 local-DB path — not implemented; operator can add later by extending `geo.py`

## Phase 16 — WHOIS lookup ✅
- [x] `intel.whois_lookup()` via `whois.cymru.com:43` (verbose mode → ASN + country + org)
- [x] `whois_cache` table, 7d TTL
- [x] Attacker page renders WHOIS panel + mailto: abuse template + AbuseIPDB / VirusTotal links

## Phase 17 — rDNS ✅
- [x] `intel.rdns_lookup()` via dnspython with 2s/3s timeout, NXDOMAIN/Timeout caught
- [x] Stored in `geo_cache.rdns` (positive 24h TTL, negative 1h)
- [x] Attacker page surfaces rDNS

## Phase 18 — Threat-feed correlation ⏳ (deferred — needs operator API keys)
- [ ] AbuseIPDB / OTX / Spamhaus integrations — left as future work; CTI gives equivalent coverage

## Phase 19 — Attacker profile pages ✅
- [x] `/attackers/<ip>` renders geo + ASN + WHOIS + CTI + rDNS + scenario timeline + sources-seen list
- [x] IPs are clickable everywhere — decisions table, dashboard feed, approvals queue
- [x] Live "Refresh All" button forces a network round-trip and refreshes every enrichment row
- [x] Cached data renders immediately; works for any IP, banned or not

## Phase 20 — Intel heatmaps ✅
- [x] `/intel` page: country × hour-of-day, ASN × scenario heatmaps (6-level bucketing)
- [x] Top ASNs + Top Countries tables (24h)

---

# Arc 4 — Scenarios & Rules ✅ complete

## Phase 21 — Scenarios browser ✅
- [x] `/scenarios/catalog` uses `cscli hub list -o json` (5 categories: scenarios, parsers, collections, postoverflows, contexts)
- [x] Install / Remove buttons per item — call `cscli <kind> install <name>` and `--force` remove
- [x] Reload CrowdSec agent on every change (systemctl reload, falls back to restart)
- [x] Counts surfaced per category + noisy/sleeping detectors as KPIs

## Phase 22 — Scenario performance metrics ✅
- [x] `scenario_stats(window_hours)` — fires, unique IPs, fires/IP ratio
- [x] `noisy_scenarios()` — fires ≥ 100 with ratio ≥ 5 (false-positive proxy)
- [x] `sleeping_scenarios()` — installed-but-not-fired in 30d
- [x] Existing `/scenarios` (per-scenario top-N + heatmap from phase 5)

## Phase 23 — Custom scenario editor ✅
- [x] `/scenarios/editor` textarea-based YAML editor (no Monaco — kept dependency footprint small)
- [x] Save to `/etc/crowdsec/scenarios/<name>.yaml`
- [x] "Save & Reload Agent" button — reloads CrowdSec and shows reload output / errors
- [x] Pre-populated template for new files
- [ ] (deferred) test harness — paste sample log lines and watch the scenario fire; would need a sandbox crowdsec instance

## Phase 24 — Whitelist management ✅
- [x] `/whitelist` UI with per-IP / per-CIDR / per-ASN / per-country rules
- [x] Time-bounded entries (`expires_at`)
- [x] Whitelist-hit log on the same page
- [x] Reconciler filters via `scenarios_admin.matches_whitelist()` BEFORE the diff is computed — whitelisted IPs never reach MT, hit is logged

## Phase 25 — Auto-allowlist ✅ (rejection-driven)
- [x] Rejecting a decision in the approval queue auto-adds the IP to whitelist with note "auto: rejected from approval queue"
- [ ] (deferred) successful-auth detector tied to nginx/ssh logs — would need a log tailer; out of MVP scope

## Phase 26 — Decision approval queue ✅
- [x] `approval_queue` table; `scenarios_admin.approval_required()` toggles via /whitelist
- [x] Reconciler queues every new decision when in SEMI-AUTO mode; only approved IPs flow to MT
- [x] `/approvals` page: pending decisions with approve/reject buttons, recent-decisions audit
- [x] Rejected decisions auto-create a whitelist rule for the IP so they don't re-queue
- [ ] (deferred) SLA timer for auto-approve after N minutes — settable in /settings later if useful

---

# Arc 5 — Multi-Bouncer / Multi-Target ✅ complete

## Phase 27 — Abstract `Bouncer` interface ✅
- [x] `bouncers/__init__.py` defines the `Bouncer` Protocol + `KINDS` registry + `make_bouncer()` factory
- [x] `bouncers/mikrotik_adapter.py` wraps the env-driven phase-2 MikroTik (kind `mikrotik_env`)
- [x] `reconciler.run_once()` iterates `bouncers.load_all_targets()` — every target gets the same desired set, each computes its own diff against its own snapshot
- [x] All 20 reconcile unit tests still pass

## Phase 28 — pfSense adapter ✅
- [x] `bouncers/pfsense_adapter.py` (kind `pfsense`) — uses `pfsense-pkg-RESTAPI v2`
- [x] PATCH whole `addresses` array per cycle (v2 dropped per-entry add/delete)
- [x] `POST /api/v2/firewall/apply` on every push
- [x] Auth via `X-API-Key`; verify-TLS togglable for self-signed certs

## Phase 29 — OPNsense adapter ✅
- [x] `bouncers/opnsense_adapter.py` (kind `opnsense`) — built-in REST API, no plugin needed
- [x] Per-entry add/delete via `/api/firewall/alias_util/{add,delete,list}/<alias>`
- [x] Auth: HTTP Basic with `key:secret`

## Phase 30 — Plain iptables/ipset adapter ✅
- [x] `bouncers/iptables_adapter.py` (kind `iptables_ipset`) — local-only (runs as root via systemd already)
- [x] Two sets managed: `protek-bans` (hash:net inet) + `protek-bans6` (hash:net inet6)
- [x] Auto-ensures sets on first health() with `-exist` flag (idempotent)
- [x] Adapter NEVER writes iptables rules — operator owns the consuming `-m set --match-set protek-bans src -j DROP` rules (same separation as MikroTik phase-2)
- [x] Graceful degradation when `ipset` binary is missing

## Phase 31 — Cloudflare WAF push ✅
- [x] `bouncers/cloudflare_adapter.py` (kind `cloudflare`) — v4 API, Bearer token auth
- [x] Auto-creates a Rules List on first health() if `auto_create_list=true`
- [x] Bulk append + bulk delete (1000 items/request, paginated snapshot via cursor)
- [x] Operator writes the WAF Custom Rule `(ip.src in $protek_bans)` manually once

## Phase 32 — Multi-target UI ✅
- [x] `/bouncers` page: KPI strip (total / online / errors / total-entries), targets table, add-target form
- [x] Per-target health pill + size + dry-run badge + last-sync timestamp + remove button
- [x] DB-driven `bouncer_targets` table (name, kind, config_json, enabled, dry_run)
- [x] Health-probe before save — rejects targets whose health check fails
- [x] Per-target dry-run flag (env MT stays on env's `DRY_RUN` for backwards compat)

---

# Arc 6 — Observability

## Phase 33 — Prometheus metrics export

- [ ] `/metrics` endpoint (auth via bearer or IP allowlist)
- [ ] Metrics: active_decisions, mt_list_size, sync_lag_seconds, sync_duration_ms, scenarios_fired_total, push_errors_total, source_health
- [ ] Grafana dashboard JSON in `docs/grafana/`

**Acceptance:** Prometheus scrapes Protek successfully, sample Grafana board imports cleanly.

---

## Phase 34 — SIEM forwarding

- [ ] Per-decision event push to: syslog (RFC 5424), JSON over HTTP (Splunk HEC / generic webhook), or Kafka
- [ ] Backpressure-safe queue (don't block reconcile if SIEM is slow)
- [ ] Replay capability — re-ship the last N events on demand

**Acceptance:** point a syslog listener at Protek, see every decision event arrive within 5s.

---

## Phase 35 — Audit log

- [ ] Every operator action (settings change, manual decision add/remove, allowlist edit, scenario enable/disable) logged with: actor, IP, before/after, timestamp
- [ ] `/audit` page — searchable, exportable
- [ ] Audit log is **append-only** at the storage layer (separate table, no DELETE/UPDATE allowed in code paths)

**Acceptance:** make a settings change, see it in `/audit` with diff. Try to alter an audit row in code → review test fails.

---

## Phase 36 — Performance dashboard

- [ ] `/perf` — sync timing breakdown (LAPI fetch, MT snapshot, diff compute, push), p50/p95/p99
- [ ] Slow-cycle log (cycles > N ms get detailed traces)
- [ ] Memory + DB-size growth over time

**Acceptance:** identify the slowest sync cycle in the last 24h with one click; understand why (which stage).

---

## Phase 37 — SLO tracking

- [ ] Define SLOs: sync lag P95 ≤ 30s, decision-to-ban latency P95 ≤ 15s, dashboard load P95 ≤ 500ms
- [ ] Compute compliance, surface burn rate
- [ ] SLO panel on dashboard

**Acceptance:** SLO panel shows real numbers and clear pass/fail with burn-rate context.

---

## Phase 38 — Health alerting (pager-quality)

- [ ] Composite alert rules ("LAPI down ≥ 5min", "MT unreachable ≥ 2min", "sync lag > 5min")
- [ ] Alert dedup + auto-resolve
- [ ] Per-channel routing (Discord for warnings, SMS/Telegram for critical)
- [ ] Alert silencing (planned-maintenance windows)

**Acceptance:** simulated MT outage → critical alert within 2min; alert auto-resolves when MT recovers.

---

# Arc 7 — Operator Quality of Life

## Phase 39 — Mobile-responsive dashboard

- [ ] All pages reflow for ≤ 480px wide
- [ ] Touch-friendly hit targets, swipe-to-dismiss toasts
- [ ] Sidebar → hamburger
- [ ] Optimized table → card layouts on narrow viewports

**Acceptance:** dashboard usable on a phone — review on iPhone SE and Pixel 7 widths.

---

## Phase 40 — CLI client (`protekctl`)

- [ ] Standalone CLI under `bin/protekctl` (Python, packaged)
- [ ] Same operations as the web UI: decisions ls/add/rm, sources ls/add/rm, sync run, allowlist mgmt
- [ ] TSV + JSON output modes (scriptable)
- [ ] Authenticates via API token (new token type in Protek)

**Acceptance:** `protekctl decisions ls --json | jq` works; `protekctl sync run` triggers a cycle and reports outcome.

---

## Phase 41 — Bulk import/export

- [ ] Export entire config (sources, settings, allowlists, scenarios, notification channels) → encrypted bundle
- [ ] Import — fresh Protek install can restore from bundle in one command
- [ ] Useful for moving to a new VPS, or A/B-testing config changes

**Acceptance:** export from VPS A, import into VPS B, verify identical config.

---

## Phase 42 — Multi-admin accounts

- [ ] `users` table — multiple admin accounts, each with own bcrypt + TOTP
- [ ] First-run admin still created by `setup_admin.py`; subsequent admins added via `/admin/users`
- [ ] Per-user session, per-user audit attribution

**Acceptance:** add a second admin, log in as them, see their actions attributed in audit log.

---

## Phase 43 — RBAC

- [ ] Roles: `viewer` (read-only), `operator` (everything except user mgmt), `admin` (everything)
- [ ] Per-route role check
- [ ] Visible affordances hidden for insufficient role (no "clicking forbidden buttons that 403")

**Acceptance:** viewer account can browse decisions, alerts, dashboards; cannot add sources or change settings; sees no buttons for those actions.

---

## Phase 44 — Keyboard shortcuts + command palette

- [ ] `cmd-K` / `ctrl-K` command palette — search any page, any decision, any setting
- [ ] Vim-ish keys for tables (`j`/`k` row nav, `o` open, `x` select, `D` delete with confirm)
- [ ] `?` overlay shows the full shortcut sheet

**Acceptance:** can navigate Protek end-to-end without touching the mouse.

---

# Arc 8 — Integration & Extensibility

## Phase 45 — Webhook outputs

- [ ] On every decision event (added / removed / approved / rejected), POST to configured webhook(s)
- [ ] HMAC signing, retry with backoff, DLQ for permanent failures
- [ ] Templated payloads per webhook target (custom JSON shape)

**Acceptance:** configure a webhook, see decisions land at the receiver within 2s with valid HMAC.

---

## Phase 46 — Webhook inputs

- [ ] `/api/external/decisions` — accept ban requests from external systems (atom, custom scripts, third-party security tools) with API-token auth
- [ ] Decisions arrive into the same pipeline as CrowdSec-sourced ones, attributed as `origin: external:<name>`
- [ ] Optional approval queue (always require human sign-off on external bans, configurable)

**Acceptance:** `curl -X POST /api/external/decisions -d '{"ip":"...","reason":"..."}'` → decision flows through reconcile to MT.

---

## Phase 47 — REST API v1 stable

- [ ] Full OpenAPI spec at `/api/openapi.json`
- [ ] Backwards-compatibility contract — `/api/v1/*` paths frozen
- [ ] API tokens with scopes (read / write / admin), expiry, last-used timestamp
- [ ] `/api/v1` self-documenting page

**Acceptance:** generated client (e.g., from OpenAPI Generator) can drive every UI action.

---

## Phase 48 — Atom integration

- [ ] Atom's recon findings (per `atom`'s schema) can publish synthetic CrowdSec-shaped events to Protek via phase-46 webhook input
- [ ] Bidirectional: Protek's banned IPs appear as a feed atom can subscribe to for its agent's context
- [ ] One-click "investigate this IP in atom" link from any IP profile page

**Acceptance:** atom finds a SQL-probing IP → publishes to Protek → IP in MT within sync interval. Conversely, click any Protek IP → opens atom's investigation view with the IP loaded.

---

## Phase 49 — Othoni tile + cross-app SSO

- [ ] Protek exposes `/api/tile/summary` (active bans, sync lag, top scenario, health) for othoni to render as a "perimeter security" card
- [ ] Shared session cookie domain across the suite (cookie scoped to `.syedhashmi.trade` with care)
- [ ] Optional: SSO via one of the apps as identity broker (simplest path: othoni-as-IdP since it already has user mgmt)

**Acceptance:** open othoni dashboard, see Protek summary tile populated live. Log in to one app, navigate to another — same session.

---

## Phase 50 — Protek 1.0

- [ ] Documentation pass: user guide, install guide, troubleshooting, FAQ
- [ ] Public marketing site (single page, screenshots, feature matrix)
- [ ] `install.sh` — one-command install on a fresh Ubuntu VPS (matches the install.sh pattern from othoni)
- [ ] Docker image (optional path for non-Ubuntu deployers)
- [ ] License/credits page, contributor guide
- [ ] Perf baseline doc (matches atom's `docs/perf-baseline.md`)
- [ ] Security review pass (own pen-test using atom against a staging Protek)
- [ ] Tag `v1.0` on git

**Acceptance:** a stranger can clone the repo and have a working Protek on a fresh Ubuntu VPS within 30 minutes, end-to-end, without reading anything but the install instructions.

---

# Anti-roadmap — things we are deliberately NOT building

- A CrowdSec **agent**. Protek does not detect attacks. It reads decisions and remediates them.
- A **multi-tenant** mode. Single-operator (per phase 42, "multi-admin" is multi-user not multi-tenant). Federation handles multi-source on the input side.
- A **native mobile app**. Phase 39's responsive web is enough.
- A **rule editor for the operator's MikroTik firewall itself**. Protek owns the address-list; the operator owns the firewall rules that consume it. This separation is what makes Protek safe to install.
- **Detection logic that bypasses CrowdSec**. If a scenario or parser is missing, write a CrowdSec scenario for it (phase 23), don't add detection inside Protek.
- A **billing / SaaS hosted version**. Self-hosted only. If someone wants hosted, they fork.

---

# Post-50 candidate threads (not committed)

Recorded so we don't lose them, not prioritized:

- HTTP/3 + QUIC on the perimeter for the dashboard
- gRPC variant of the REST API
- Plugin system for community-contributed bouncer adapters
- Native Linux packages (deb/rpm) in addition to the install script
- ARM cluster mode (Protek runs across multiple ARM SBCs at the edge with leader election)
- Honeypot pipeline as a built-in feature (vs the separate "honeypot aggregator" project idea)
- Machine learning anomaly layer on top of CrowdSec scenarios
- Federation with non-CrowdSec sources (Suricata EVE, Zeek notice.log)
- Read-only public mode ("wall of shame") as a deployable static export
