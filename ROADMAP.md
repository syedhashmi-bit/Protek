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
| 9 | 51–56 | **(v1.1) Polish** — multi-MikroTik, in-place edit, bulk ops, global search, per-stage timing, routing v2 |
| 10 | 57–62 | **(v1.1) Intelligence v2** — ASN auto-ban, reputation scoring, AbuseIPDB/OTX, Tor, honeypot, ML |
| 11 | 63–68 | **(v1.1) Resilience** — off-box backup, Litestream, HA, self-monitoring, DR runbook, backpressure |
| 12 | 69–74 | **(v1.1) Ecosystem** — plugin SDK, OAuth/SAML, deb/rpm, webhook templates, GraphQL, othoni |
| 13 | 75–80 | **(2.0 prep)** — Postgres, sharding, multi-region, intel publishing, deprecation policy, 2.0 |

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

# v1.1 Roadmap — post-1.0 refinements

v1.0 shipped the full vision. v1.1 sands the rough edges discovered in production
use + opens the door to genuinely new capabilities. Numbered continuing from 50 so
ROADMAP stays one source of truth.

| Arc | Phases | Theme |
|---|---|---|
| 9 | 51–56 | **Polish** — UX gaps from v1.0 production use |
| 10 | 57–62 | **Intelligence v2** — smarter targeting, reputation scoring |
| 11 | 63–68 | **Resilience** — HA, backups, off-box durability |
| 12 | 69–74 | **Ecosystem** — plugin SDK, OAuth, native packages |
| 13 | 75–80 | **2.0 prep** — Postgres, GraphQL, breaking-change window |

---

## Arc 9 — Polish (gaps surfaced after first production deploy)

### Phase 51 — Multi-MikroTik via the UI (✅ shipped early)

- [x] New `mikrotik` adapter kind (sibling to `mikrotik_env`) takes config from `bouncer_targets.config_json`
- [x] /bouncers add form lists the new kind first with worked-example JSON
- [x] Per-bouncer filter knobs (`max_entries`, `origins`, `exclude_origins`) honored

**Acceptance:** add a second MikroTik via /bouncers, watch its address-list fill on the next reconcile cycle, verify the env-anchored router still operates unchanged.

---

### Phase 52 — In-place edit for bouncer targets

- [ ] /bouncers/edit/<id> — change config_json without delete+re-add
- [ ] Preserve sync state, last_ok_at, last_error across edits
- [ ] Mask secret fields in the edit form (same pattern as /notifications creds)

**Acceptance:** update a CF list_name without losing the target's history or having to re-paste the API token.

---

### Phase 53 — Bulk operations on /decisions

- [ ] Multi-select checkbox column + sticky action bar
- [ ] Bulk delete, bulk-add-to-whitelist, bulk-extend-duration
- [ ] Confirmation modal showing the operation count + first 5 affected IPs
- [ ] Action audit row records "bulk operation: N items"

**Acceptance:** filter decisions by ASN, select all matching, bulk-add to whitelist with one click — 5 seconds total.

---

### Phase 54 — Global search

- [ ] `cmd-K` palette extended to search across decisions, alerts, scenarios, attackers, audit log
- [ ] Backend: `/api/v1/search?q=<term>` with ranked results
- [ ] Saved searches per user (settings table)

**Acceptance:** type `1.2.3` in the palette, get hits across all four entity types in <100ms.

---

### Phase 55 — Per-stage sync timing

- [ ] sync_events columns: `lapi_fetch_ms`, `snapshot_ms`, `diff_ms`, `push_ms`
- [ ] /perf shows stacked-bar breakdown per cycle
- [ ] Slow-cycle log identifies "this cycle was slow because of MT push, not LAPI"

**Acceptance:** open /perf during initial sync, see clearly that "MT snapshot took 8s, push took 50s" — no more guessing.

---

### Phase 56 — Notification routing v2

- [ ] `notifications.send(..., channels=[...])` kwarg actually wired (alerting fallback removed)
- [ ] Per-rule channel override on /alerts/rules ("this rule fires Telegram only")
- [ ] Multiple webhooks of the same type (e.g. two Discord channels for different teams)
- [ ] Per-user notification preferences (when phase 42 multi-admin is in use)

**Acceptance:** critical alerts page Telegram + email; warnings only Discord; one user receives nothing.

---

## Arc 10 — Intelligence v2

### Phase 57 — ASN-level auto-ban

- [ ] Threshold: "if N IPs from same ASN attack in M hours, escalate the ASN"
- [ ] Optional action: ban /24 (or whole ASN) instead of single IP
- [ ] /intel ASN page surfaces escalated ASNs with one-click "convert to permanent rule"

**Acceptance:** demo ASN with 10+ IPs hitting SSH in an hour gets ASN-wide rule auto-suggested for operator approval.

---

### Phase 58 — Reputation scoring

- [ ] Per-IP composite score: `cti_score × scenario_severity × cross_source_agreement × age_decay`
- [ ] Three tiers: `auto-ban` (≥80), `queue-for-approval` (50–80), `monitor-only` (<50)
- [ ] /attackers page shows the score breakdown
- [ ] Operator can tune thresholds per-bouncer (some targets stricter than others)

**Acceptance:** noisy CAPI feed entries score low + age out fast; locally-detected SSH brute force scores high + stays.

---

### Phase 59 — AbuseIPDB + OTX correlation

- [ ] Three new providers in intel.py alongside CTI (AbuseIPDB, AlienVault OTX, Spamhaus DROP/EDROP)
- [ ] Per-provider rate-limit awareness
- [ ] Cross-provider "consensus" panel on attacker page ("this IP is on 4/5 feeds")
- [ ] Optional: contribute back — report locally-detected attackers to AbuseIPDB (operator opt-in)

**Acceptance:** attacker dossier shows reputation scores from all configured providers; setting a "report-to-abuseipdb" toggle starts contributing back.

---

### Phase 60 — Tor exit + VPN/proxy detection

- [ ] Pull Tor exit list daily, mark matching decisions
- [ ] proxycheck.io or ipinfo VPN/proxy lookup for high-score IPs
- [ ] UI toggle: "auto-block Tor exits" / "auto-block known VPNs"
- [ ] Per-scenario whitelist option: "this scenario doesn't count Tor users"

**Acceptance:** an attacker via Tor shows up tagged "tor-exit"; toggle blocks all Tor edge traffic on opt-in.

---

### Phase 61 — Honeypot mode

- [ ] Instead of dropping high-score attackers, route them to a configurable honeypot URL (proxy via Cloudflare workers or similar)
- [ ] Collect their behavior, feed back into reputation scoring
- [ ] Optional integration with `atom` for replay/analysis

**Acceptance:** flagged attacker visits the honeypot; their session is logged; reputation score updates from the captured behavior.

---

### Phase 62 — ML anomaly layer

- [ ] Lightweight scikit-learn isolation forest on per-IP feature vector (request rate, scenario diversity, ASN reputation, time-of-day pattern)
- [ ] Trained on the operator's own LAPI history
- [ ] Flags "anomalous" IPs that haven't fired CrowdSec scenarios but look weird
- [ ] Recommend-only — never auto-bans

**Acceptance:** review a week of decisions, see a "candidates" panel of IPs the ML thinks are suspicious; sanity-check a few.

---

## Arc 11 — Resilience

### Phase 63 — Off-box backup automation

- [ ] Nightly `/admin/backup` export to S3-compatible storage (Backblaze B2, MinIO, AWS S3)
- [ ] Retention policy (keep last 30 dailies, 12 monthlies)
- [ ] Restore-test job that decrypts the latest bundle and verifies integrity (no actual import)

**Acceptance:** simulate a VPS loss — restore from yesterday's bundle to a fresh box, full config back in <5 minutes.

---

### Phase 64 — Litestream-based DB replication

- [ ] Stream the SQLite WAL to S3 in near-real-time (Litestream sidecar)
- [ ] RPO < 60 seconds, RTO < 5 minutes
- [ ] Documented restore procedure

**Acceptance:** kill the VPS mid-cycle; restore from Litestream; lose at most one minute of decisions / alerts.

---

### Phase 65 — Active-passive HA

- [ ] Two Protek instances, one elected leader writes to bouncers
- [ ] Leader election via the existing fcntl.flock pattern extended to a network lock (Redis SETNX or DynamoDB conditional write)
- [ ] Failover within 30 seconds
- [ ] Acceptance: kill the leader; passive takes over; bouncer push continues

**Acceptance:** simulated leader crash → passive becomes leader → next reconcile cycle pushes within 30s, no decisions lost.

---

### Phase 66 — Self-monitoring depth

- [ ] Detect "phantom-progress" failure modes (LAPI returning stale data, MT silently accepting writes that don't land, etc.)
- [ ] Synthetic ban test: every 6h, ban a private-range test IP via cscli + verify it appears in each bouncer's snapshot within one cycle
- [ ] Alert if synthetic doesn't propagate

**Acceptance:** disable MT API mid-test, verify the synthetic alarm fires within 10 minutes.

---

### Phase 67 — Disaster recovery runbook

- [ ] docs/DR-RUNBOOK.md — every failure mode with explicit recovery steps
- [ ] DR drill template — operator runs it quarterly, results land in audit log
- [ ] Inventory: what fails if the VPS dies / router dies / CF outage / CrowdSec hub down

**Acceptance:** quarterly drill completes in <30 minutes per scenario, full restoration verified.

---

### Phase 68 — Rate limiting + backpressure

- [ ] Token bucket per upstream (LAPI, each bouncer, each webhook target)
- [ ] Graceful degradation when an upstream is rate-limiting us
- [ ] /perf shows the bucket states ("CF: 80/100 req/min consumed")

**Acceptance:** stress-test with 5x normal traffic; no upstream returns 429; cycles slow but don't error.

---

## Arc 12 — Ecosystem

### Phase 69 — Plugin SDK for adapters

- [ ] Publish the Bouncer protocol as a documented public interface
- [ ] cookiecutter template: `cookiecutter gh:syedhashmi-bit/protek-adapter-template`
- [ ] Hot-load adapters from `~/.config/protek/adapters/*.py` (no fork-and-merge needed)
- [ ] Adapter manifest format with metadata (author, kind, version, required config keys)

**Acceptance:** community contributor writes a Sophos adapter using the template, drops it in a hot-load dir, it appears in /bouncers.

---

### Phase 70 — OAuth / SAML SSO

- [ ] OIDC provider integration (Google Workspace / Authentik / Auth0)
- [ ] SAML 2.0 SP role
- [ ] Maps external claims → Protek role (viewer/operator/admin)
- [ ] Per-domain restriction (`@yourcompany.com` only)
- [ ] Fallback to local user table for break-glass

**Acceptance:** log in via Google, see your role auto-assigned based on group claim, audit log attributes actions to your SSO identity.

---

### Phase 71 — Native packages (.deb / .rpm)

- [ ] dh_python3 build → official Debian/Ubuntu package
- [ ] RPM equivalent for Fedora/RHEL/Rocky
- [ ] Hosted in a GitHub-Pages-hosted APT/YUM repo
- [ ] `apt install protek` works on supported distros

**Acceptance:** fresh Debian 12 → `apt install protek` → service runs → `systemctl status protek` green.

---

### Phase 72 — Webhook input templates

- [ ] Ship example payloads for common integrators (n8n, Zapier, Make, Tines, atom)
- [ ] Inbound webhook signature verification (per-token HMAC secret)
- [ ] /api/external introspection endpoint for integrators to test their payload shape
- [ ] Rate limiting per token

**Acceptance:** n8n cookbook in docs/integrations/ — paste the JSON, set the token, decision lands in Protek within 2s.

---

### Phase 73 — GraphQL surface

- [ ] /api/graphql alongside REST (Strawberry or Ariadne)
- [ ] Same scope-based auth as REST
- [ ] Self-documenting GraphiQL at /api/graphql/explorer (admin role only)
- [ ] Schema covers all reads; mutations limited to safe operations

**Acceptance:** a single query fetches "all active SSH brute-forcers from China with reputation > 70 plus their CTI dossier" — would have needed 50 REST calls.

---

### Phase 74 — Otho­ni cross-app integration deep-dive

- [ ] Embed Protek's tile into othoni's grid (via /api/v1/tile/summary)
- [ ] Cross-app session via shared cookie (`SESSION_COOKIE_DOMAIN=.syedhashmi.trade`)
- [ ] Single-pane drilldown: click Protek tile in othoni → land on a contextualized dashboard view

**Acceptance:** sign in to othoni, navigate to Protek's tile, click through to the per-IP attacker page — same session, no re-auth.

---

## Arc 13 — 2.0 preparation

### Phase 75 — Postgres support (additive)

- [ ] DB abstraction layer (SQLAlchemy Core or just a thin shim around our raw SQL)
- [ ] Postgres schema mirroring SQLite, including the audit_log triggers
- [ ] Migration tool: dump SQLite → load Postgres
- [ ] CI matrix tests both backends

**Acceptance:** boot Protek with `DATABASE_URL=postgresql://...`, full functionality, unit tests pass on both backends.

---

### Phase 76 — Sharding by decision origin

- [ ] One Protek instance per origin / region (e.g. dedicated instance for CAPI feeds)
- [ ] Federation between Protek instances (not just CrowdSec sources)
- [ ] Aggregated read across shards for the dashboard

**Acceptance:** 3 sharded Protek instances appear as one dashboard; pushing decisions through any of them lands on every shared bouncer.

---

### Phase 77 — Multi-region deploy template

- [ ] Terraform module: deploy Protek to N regions with private mesh between them
- [ ] WireGuard or Tailscale baked in
- [ ] Region-affinity for source IP geo (the closest Protek detects)

**Acceptance:** `terraform apply` brings up 3-region cluster with mesh + leader election in <10 min.

---

### Phase 78 — Threat intel publishing (be the source, not the sink)

- [ ] Protek exports its own decisions as a public feed (HTTP + signed)
- [ ] Federation peers can subscribe directly (no CAPI middle-man)
- [ ] Opt-in opt-out per scenario / origin
- [ ] Per-subscriber rate limiting

**Acceptance:** a peer Protek instance configures yours as a federation source, gets the decision stream signed and rate-limited.

---

### Phase 79 — Breaking-change window for 2.0

- [ ] Deprecation policy: 6 months notice on /api/v1 removals
- [ ] /api/v2 alongside /api/v1 with the migration playbook
- [ ] Config bundle format v2 (older v1 bundles still importable for one major version)
- [ ] CLI flag `--api-version`

**Acceptance:** community projects depending on /api/v1 have 6 months and a documented upgrade path before any breaking change.

---

### Phase 80 — Protek 2.0

- [ ] All Arc 9–13 phases shipped
- [ ] Performance regression suite vs 1.0 baseline (no >10% degradation on any /perf SLO)
- [ ] Re-do security review (own pen-test using atom)
- [ ] Migrate the public site + docs to a versioned model
- [ ] Tag `v2.0.0`

**Acceptance:** install Protek 2.0 on a fresh VPS, restore a 1.0 bundle, every feature works, no functionality regressed.

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
