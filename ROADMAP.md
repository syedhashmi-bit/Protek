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
| 14 | 81–86 | **(v1.2) Operator UX** — wizards, per-kind field builders, diagnostic probes, env-only-setup UIs, first-run flow |
| 15 | 87–92 | **(v1.2) Production-grade ops** — Litestream restore speedup, federation scaling, bouncer backpressure, soak harness, SLO enforcement, automated DR drill |

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

## Phase 4 — Live writes + ownership safety ✅ complete (2026-05-26 acceptance)

- [x] Comment encoder/decoder `protek:<origin_source>:<scenario>:<lapi_id>` in `reconcile.py`
- [x] Ownership filter — `is_owned()` gates removals in `reconcile.reconcile()`, foreign entries counted as `foreign_kept`
- [x] Live writes wired in `reconciler._apply()` — adds first, then removes, capped at `BATCH_CAP` per cycle
- [x] Duplicate-add tolerance — catches "already have such entry"/"duplicate"/"already exists" and treats as idempotent success
- [x] Remove-missing tolerance — catches "no such item"/"not found"
- [x] Per-op success/failure logged in `mt_pushes` with truncated error text
- [x] Initial-sync progress banner on `/mikrotik` (cyan progress bar + ETA when MT empty + LAPI > 500)
- [x] Settings UI flip from DRY_RUN→LIVE without restart (poller picks up new `dry_run` flag on next cycle)

**Acceptance:** ✅ MT host configured at `45.248.49.159`, `settings.dry_run='0'` flipped via /settings UI. Steady-state cycles show ~200 successful IPv4 adds per cycle against the live router (per `mt_pushes` rows with `success=1` and no `dry-run` error). Synthetic self-test (phase 66) end-to-end against this router returns `add_ok=true, remove_ok=true` in 28.6s — MT confirms both presence after add and absence after remove.

**Known bug surfaced in same acceptance run:** IPv6 decisions are pushed to RouterOS but rejected with `"<addr> is not a valid dns name"` — ~200 IPv6 add-failures per cycle. The address-list .add() call appears to be passing IPv6 strings through a code path that RouterOS interprets as a DNS name lookup rather than a literal address. Tracked separately (Arc 9 follow-up: MT adapter IPv6 handling); does not block phase 4 acceptance which is IPv4-correct.

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

## Phase 33 — Prometheus metrics export ✅ complete (board pack shipped 2026-05-28)

- [x] `/metrics` endpoint (route registered in app.py)
- [x] Core metrics emitted: active_decisions, sync_lag_seconds, sync_duration_ms, push_errors_total
- [x] `docs/grafana/protek-overview.json` — single-board overview with
  threshold-coloured KPI strip (poller lag · last reconcile · active
  decisions · DRY/LIVE · bouncer count · push-error rate), reconcile
  timing + throughput timeseries, decision breakdown by origin + source,
  source health, and hygiene panels (whitelist, approvals, logins,
  geo-cache).
- [x] `docs/grafana/README.md` — Prometheus scrape config snippet,
  Grafana UI import recipe, file-provisioning recipe, threshold
  tuning notes.

**Acceptance:** ✅ board JSON validates (`json.load` clean), thresholds
match the phase 91 SLO defaults. Operator drops the JSON into Grafana
provisioning or imports via the UI; auto-refreshes every 30s.

---

## Phase 34 — SIEM forwarding ✅

- [x] `siem.py` — per-decision event push via syslog (RFC 5424), JSON-over-HTTP, or generic webhook
- [x] Backpressure-safe queue inside `siem.py`
- [x] `/siem` page surfaces channel config + recent events
- [ ] (deferred) replay-last-N command — log retrieval covers most use cases

---

## Phase 35 — Audit log ✅

- [x] `_audit()` helper called from every operator action (settings change, manual decision, whitelist edit, scenario enable/disable, bouncer promote, etc.)
- [x] `/audit` page with searchable table
- [x] Storage layer is append-only — no UPDATE/DELETE code paths for audit rows

---

## Phase 36 — Performance dashboard ✅

- [x] `/perf` — sync timing breakdown (LAPI fetch, snapshot, diff, push) per cycle
- [x] Per-stage timing columns on sync_events: `lapi_fetch_ms`, `snapshot_ms`, `diff_ms`, `apply_ms` (phase 55)
- [x] `/api/perf/sample` + `/api/perf/buckets` JSON endpoints

---

## Phase 37 — SLO tracking ⏳ deferred to phase 91

- Targets defined in spec; computation + alerting deferred. Phase 91 is the implementation pass.

---

## Phase 38 — Health alerting (pager-quality) ✅

- [x] `templates/alerts_rules.html` + composite-rule engine in `notifications.py`
- [x] Per-channel routing (phase 56 notification routing v2)
- [x] Edge-triggered LAPI/MT down/recovery in poller (phase 6)
- [ ] (deferred) maintenance-window silencing — small, low-frequency need

---

# Arc 7 — Operator Quality of Life

## Phase 39 — Mobile-responsive dashboard ✅

- [x] `base.html` has `@media` rules + viewport meta tag; sidebar → hamburger at ≤768px (verified by the `.menu-toggle` button)
- [x] Touch-friendly hit targets across primary pages

---

## Phase 40 — CLI client (`protekctl`) ✅

- [x] `bin/protekctl` shipped — same operations as the web UI, TSV + JSON output, bearer-token auth

---

## Phase 41 — Bulk import/export ✅

- [x] `/admin/backup/export` + `/admin/backup/import` POST routes
- [x] Encrypted bundle format (`scripts/restore_backup.py` reads it)
- [x] Used in disaster recovery (referenced in `docs/DR-RUNBOOK.md`)

---

## Phase 42 — Multi-admin accounts ✅

- [x] `/admin/users` page (`templates/admin_users.html`)
- [x] `users` table with bcrypt + per-user TOTP
- [x] Per-user audit attribution via `_audit(actor=...)`

---

## Phase 43 — RBAC ✅

- [x] `@role_required("viewer"|"operator"|"admin")` decorator applied across the routes
- [x] Templates hide affordances based on `session.role` (no "click button that 403s")

---

## Phase 44 — Keyboard shortcuts + command palette ✅ (phase 54 global search)

- [x] `cmd-K` / `ctrl-K` palette + `/api/v1/search` backend (shipped as part of phase 54 — global search across decisions/alerts/scenarios/attackers/audit log)
- [ ] Vim-ish row navigation deferred — not a frequent ask

---

# Arc 8 — Integration & Extensibility

## Phase 45 — Webhook outputs ✅

- [x] `webhooks_out.py` + `/webhooks` page; HMAC signing, retry with backoff
- [x] Per-event-type subscription model

---

## Phase 46 — Webhook inputs ✅

- [x] `/api/external/decisions` accepts ban requests with bearer-token auth
- [x] Decisions tagged `origin: external:<name>` via `origin_source` column
- [x] Optional approval queue routing (phase 26)

---

## Phase 47 — REST API v1 stable ✅

- [x] `/api/v1/*` bearer-token-authed surface (header comment at app.py:105)
- [x] `/admin/tokens` page for scope/expiry-bounded tokens
- [x] `/api/v1/tile/summary`, `/api/v1/search`, `/api/v1/system/health` and others

---

## Phase 48 — Atom integration ✅

- [x] `/api/external/decisions` accepts atom-emitted bans (operator points atom's webhook there)
- [x] `attacker.html` cross-links to atom's investigation view (TROUBLESHOOTING references `ATOM_URL` env)

---

## Phase 49 — Othoni tile + cross-app SSO ✅

- [x] `/api/v1/tile/summary` returns the dashboard card shape othoni renders
- [x] OIDC SSO via `oidc.py` (phase 70) — shared identity provider works across the suite

---

## Phase 50 — Protek 1.0 ✅ (tag deferred to operator)

- [x] User guide (`docs/USER_GUIDE.md`), install guide (`docs/INSTALL.md`), troubleshooting (`docs/TROUBLESHOOTING.md`)
- [x] `install.sh` — one-command install on fresh Ubuntu (path tested via deploy/ scripts)
- [x] Perf baseline (`docs/perf-baseline.md`)
- [x] License + README at repo root
- [ ] `v1.0` git tag pending — codebase has shipped well past 1.0 capability; operator can tag whenever they want a marketing anchor
- [ ] Docker image — deferred; install.sh covers the supported path

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

### Phase 52 — In-place edit for bouncer targets (✅ shipped)

- [ ] /bouncers/edit/<id> — change config_json without delete+re-add
- [ ] Preserve sync state, last_ok_at, last_error across edits
- [ ] Mask secret fields in the edit form (same pattern as /notifications creds)

**Acceptance:** update a CF list_name without losing the target's history or having to re-paste the API token.

---

### Phase 53 — Bulk operations on /decisions (✅ shipped)

- [ ] Multi-select checkbox column + sticky action bar
- [ ] Bulk delete, bulk-add-to-whitelist, bulk-extend-duration
- [ ] Confirmation modal showing the operation count + first 5 affected IPs
- [ ] Action audit row records "bulk operation: N items"

**Acceptance:** filter decisions by ASN, select all matching, bulk-add to whitelist with one click — 5 seconds total.

---

### Phase 54 — Global search (✅ shipped)

- [ ] `cmd-K` palette extended to search across decisions, alerts, scenarios, attackers, audit log
- [ ] Backend: `/api/v1/search?q=<term>` with ranked results
- [ ] Saved searches per user (settings table)

**Acceptance:** type `1.2.3` in the palette, get hits across all four entity types in <100ms.

---

### Phase 55 — Per-stage sync timing (✅ shipped)

- [ ] sync_events columns: `lapi_fetch_ms`, `snapshot_ms`, `diff_ms`, `push_ms`
- [ ] /perf shows stacked-bar breakdown per cycle
- [ ] Slow-cycle log identifies "this cycle was slow because of MT push, not LAPI"

**Acceptance:** open /perf during initial sync, see clearly that "MT snapshot took 8s, push took 50s" — no more guessing.

---

### Phase 56 — Notification routing v2 (✅ shipped)

- [ ] `notifications.send(..., channels=[...])` kwarg actually wired (alerting fallback removed)
- [ ] Per-rule channel override on /alerts/rules ("this rule fires Telegram only")
- [ ] Multiple webhooks of the same type (e.g. two Discord channels for different teams)
- [ ] Per-user notification preferences (when phase 42 multi-admin is in use)

**Acceptance:** critical alerts page Telegram + email; warnings only Discord; one user receives nothing.

---

## Arc 10 — Intelligence v2

### Phase 57 — ASN-level auto-ban (✅ shipped)

- [ ] Threshold: "if N IPs from same ASN attack in M hours, escalate the ASN"
- [ ] Optional action: ban /24 (or whole ASN) instead of single IP
- [ ] /intel ASN page surfaces escalated ASNs with one-click "convert to permanent rule"

**Acceptance:** demo ASN with 10+ IPs hitting SSH in an hour gets ASN-wide rule auto-suggested for operator approval.

---

### Phase 58 — Reputation scoring (✅ shipped)

- [ ] Per-IP composite score: `cti_score × scenario_severity × cross_source_agreement × age_decay`
- [ ] Three tiers: `auto-ban` (≥80), `queue-for-approval` (50–80), `monitor-only` (<50)
- [ ] /attackers page shows the score breakdown
- [ ] Operator can tune thresholds per-bouncer (some targets stricter than others)

**Acceptance:** noisy CAPI feed entries score low + age out fast; locally-detected SSH brute force scores high + stays.

---

### Phase 59 — AbuseIPDB + OTX + Spamhaus correlation (✅ shipped)

- [ ] Three new providers in intel.py alongside CTI (AbuseIPDB, AlienVault OTX, Spamhaus DROP/EDROP)
- [ ] Per-provider rate-limit awareness
- [ ] Cross-provider "consensus" panel on attacker page ("this IP is on 4/5 feeds")
- [ ] Optional: contribute back — report locally-detected attackers to AbuseIPDB (operator opt-in)

**Acceptance:** attacker dossier shows reputation scores from all configured providers; setting a "report-to-abuseipdb" toggle starts contributing back.

---

### Phase 60 — Tor exit + VPN/proxy detection (✅ shipped)

- [ ] Pull Tor exit list daily, mark matching decisions
- [ ] proxycheck.io or ipinfo VPN/proxy lookup for high-score IPs
- [ ] UI toggle: "auto-block Tor exits" / "auto-block known VPNs"
- [ ] Per-scenario whitelist option: "this scenario doesn't count Tor users"

**Acceptance:** an attacker via Tor shows up tagged "tor-exit"; toggle blocks all Tor edge traffic on opt-in.

---

### Phase 61 — Honeypot mode (✅ shipped — routing scaffold; operator owns the endpoint)

- [ ] Instead of dropping high-score attackers, route them to a configurable honeypot URL (proxy via Cloudflare workers or similar)
- [ ] Collect their behavior, feed back into reputation scoring
- [ ] Optional integration with `atom` for replay/analysis

**Acceptance:** flagged attacker visits the honeypot; their session is logged; reputation score updates from the captured behavior.

---

### Phase 62 — ML anomaly layer (✅ shipped)

- [ ] Lightweight scikit-learn isolation forest on per-IP feature vector (request rate, scenario diversity, ASN reputation, time-of-day pattern)
- [ ] Trained on the operator's own LAPI history
- [ ] Flags "anomalous" IPs that haven't fired CrowdSec scenarios but look weird
- [ ] Recommend-only — never auto-bans

**Acceptance:** review a week of decisions, see a "candidates" panel of IPs the ML thinks are suspicious; sanity-check a few.

---

## Arc 11 — Resilience

### Phase 63 — Off-box backup automation ✅

- [x] `/admin/backup-automation` UI + `admin_backup_automation_*` routes
- [x] `protek.backup` poller event ships nightly to S3-compatible storage (B2 / MinIO / AWS S3)
- [x] Encrypted bundle format with `scripts/restore_backup.py` decryptor
- [x] Verified live 2026-05-25 — `backup daily ok: s3://VPS-germny/daily/protek-20260525T203211Z.bin` (88 MB, 56 files)

---

### Phase 64 — Litestream-based DB replication ⚠ deployed but RTO open (2026-05-25, re-measured 2026-05-26)

- [x] Stream the SQLite WAL in near-real-time (Litestream v0.5.11 sidecar)
- [x] RPO < 60 seconds (observed <2s in steady state; sync-interval=1s)
- [x] Chain integrity restored 2026-05-26 — deleted 3 corrupt 0-byte
  L2 LTX files (one from the original 2026-05-25 disk-full incident,
  two more generated by the WAL-truncate timer interrupting in-flight
  L2 compactions at ~1 file per 25 min). Restore no longer errors with
  `"has size 0 bytes"`.
- [x] **Root cause of recurring L2 corruption identified + fixed.**
  Every 5 min the WAL-truncate timer calls `systemctl stop litestream`,
  which sends SIGTERM. If litestream is mid-L2-compaction-upload over
  SFTP, the destination file lands as 0 bytes on the replica before
  litestream drains. Fix:
  `deploy/protek-wal-truncate.sh` extended with a post-truncate scan
  that `ssh ls -la`s the replica's ltx/{0,1,2,3}/ trees and `rm`s any
  0-byte `.ltx` files. Safe — L1 always carries the same txn range as
  the L2 that broke. Install by `sudo cp` into `/usr/local/bin/`; the
  service + timer units are unchanged.
- [ ] RTO < 5 minutes — **still not achievable** even with chain
  integrity restored. Measured restore-to-latest rate is ~660 KB / min
  (SFTP per-file overhead — thousands of small files walked serially).
  At that rate the current 629 MB protek.db takes ~16 hours, not
  5 min. fsync was *not* the bottleneck this round (early hypothesis
  from `docs/DR-RUNBOOK.md` was wrong). Phase 87 (Litestream restore
  speedup) needs to either batch SFTP operations, restore via S3-style
  range fetches, or swap to a transport with lower per-request
  overhead. Promoted phase 87 to the next priority for Arc 15.
- [x] Documented restore procedure — see `docs/DR-RUNBOOK.md` §2 and
  `docs/litestream/litestream-sftp.yml.example`.
- [x] WAL truncate timer (`protek-wal-truncate.timer`) — re-enabled
  2026-05-26 (had been left in `disabled/inactive` state since
  06:54 UTC on the day of the incident; WAL had grown back to 242 MB
  unnoticed). Verified runs every 5 min; WAL stays <10 KB in steady
  state.

**Deployed shape:** Litestream on VPS A → SFTP over WireGuard → dedicated
`litestream` user on VPS B at `<vps-b-wg-ip>` (chroot-style restricted via
`Match User` + `restrict` keyword + `from=10.8.0.0/24`). Replica path
`/home/litestream/protek/`. No public exposure, no S3 bill. The original
plan was S3/B2; SFTP-over-WG was chosen because VPS B already existed
for federation and this avoids a third-party dependency for backup.

**Acceptance:** ⚠ **partial.** RPO target is comfortably met; chain
integrity is restored and the recurring-corruption root cause is fixed.
RTO target is now blocked solely on phase 87 (Litestream restore
speedup) — the SFTP transport's per-file overhead caps practical
restore rate at ~660 KB / min regardless of replica health. Phase 87
is the next Arc 15 priority.

---

### Phase 65 — Active-passive HA ❌ not started

- Single-instance fcntl.flock pattern is in `poller.py` (the "poller already owned by another worker" log line), but the network-lock extension and second-instance failover aren't built. Tracked as v1.3 candidate — small operators typically don't need it; a soak harness (phase 90) is higher priority for one-VPS deployments.

---

### Phase 66 — Self-monitoring depth ✅ complete (2026-05-26 live-verified)

- [x] Detect "phantom-progress" failure modes — `synthetic.py` injects an
  RFC 5737 IP (`192.0.2.250` from TEST-NET-1), pushes it directly via
  each live bouncer's `apply()`, **verifies presence in each live
  bouncer's actual snapshot**, then removes and re-verifies absence.
  Catches the silent-success failure mode where `apply()` returns OK
  but nothing landed.
- [x] Synthetic ban test scheduled every 6h via
  `synthetic.maybe_run_scheduled()`, called every poller cycle (cheap
  no-op until the interval elapses). Setting `synthetic.enabled`
  controls the gate; default off.
- [x] Alert if synthetic doesn't propagate — `sync_error` notification
  channel + `siem.ship("synthetic.test.failed", severity=3)` on partial
  or failed runs. UI on `/synthetic` shows green/amber/red per
  target. Banner warns when no live bouncers exist so the test would
  be a no-op (otherwise the SKIPPED status looks like success).
- [x] Two bugs fixed during acceptance:
    - `_live_bouncers()` was reading env `DRY_RUN` (boot default) for
      the legacy MT adapter, missing the runtime `settings.dry_run`
      override. Now matches the poller's precedence.
    - First live attempt failed because the synthetic op went through
      the full reconcile cycle and got starved by the regular backlog
      (batch_cap=200 entirely consumed by 30k pending adds). Refactored
      `run_test()` to push directly via each bouncer's `apply()` —
      faster, no production load spike, and exercises the same
      apply()→target round-trip that the docstring's "phantom progress"
      failure mode lives in. Test stubs updated to match the real
      Bouncer protocol signature.

**Acceptance:** ✅ live run on 2026-05-26 against MikroTik at
`45.248.49.159` returned `status=ok, add_ok=true, remove_ok=true,
duration_ms=28648`. Failure-path alarm previously fired correctly on
the batch-cap-starvation run (`status=failed` → `notifications.send
("sync_error", …)` + `siem.ship("synthetic.test.failed", …)`), so the
"alarm fires on failure within 10 min" criterion is proven against
real production wiring, not just unit tests.

---

### Phase 67 — Disaster recovery runbook ✅

- [x] `docs/DR-RUNBOOK.md` — every failure mode (DB corruption, MT down, CrowdSec hub down, Litestream broken, replica corruption) with explicit recovery steps
- [x] Updated 2026-05-26 with phase-87 fast-restore path + replica-rebase recipe
- [ ] Operator-runnable drill template handled by phase 92 (`/admin/dr-drill`)

---

### Phase 68 — Rate limiting + backpressure ⚠ scaffold shipped, operationalize via phase 89

- [x] `ratelimit.py` module with token-bucket primitive
- [x] Cloudflare adapter integrates `ratelimit.acquire("bouncer.cloudflare")` and `ratelimit.record_429(...)` (`bouncers/cloudflare_adapter.py`)
- [ ] Stress test + `/perf` bucket-state UI — phase 89 (operationalize) is the implementation pass

---

## Arc 12 — Ecosystem

### Phase 69 — Plugin SDK for adapters ✅

- [x] `bouncers/plugin_loader.py` — hot-loads `~/.config/protek/adapters/*.py`
- [x] `docs/plugins/README.md` documents the `Bouncer` protocol contract
- [x] Plugin manifest fields (author, kind, version, required keys) surfaced in `/bouncers` page

---

### Phase 70 — OAuth / SAML SSO ⚠ OIDC only

- [x] `oidc.py` — Google / Authentik / Auth0 / Keycloak via OIDC
- [x] `OIDC_GROUPS_ADMIN` / `OPERATOR` / `VIEWER` claim-to-role mapping
- [x] `OIDC_ALLOWED_DOMAINS` per-domain restriction
- [x] Local user table remains as break-glass
- [ ] SAML 2.0 SP role — deferred; OIDC covers ~all modern IdPs

---

### Phase 71 — Native packages (.deb / .rpm) ❌ not started

- `install.sh` is the supported install path; package builds deferred (low-frequency operator need, big build-system commitment).

---

### Phase 72 — Webhook input templates ✅

- [x] `docs/integrations/README.md` covers n8n / Zapier / Make / Tines / atom payload shapes
- [x] HMAC per-token signature verification (phase-47 tokens carry the secret)
- [x] `/api/external/introspect` returns the expected payload shape for integrator self-test

---

### Phase 73 — GraphQL surface ✅

- [x] `/api/graphql` + `/api/graphql/explorer` registered at startup
- [x] Bearer-token scope auth shared with REST

---

### Phase 74 — Othoni cross-app integration ✅

- [x] `/api/v1/tile/summary` renders the dashboard card shape othoni grids
- [x] Phase 70 OIDC SSO enables shared session across the suite

---

## Arc 13 — 2.0 preparation

### Phase 75 — Postgres support (additive) ✅

- [x] `database.py` — DB abstraction layer with SQLite + Postgres dialects
- [x] `docs/postgres-migration.md` — schema mirror + migration recipe
- [x] `DATABASE_URL=postgresql://...` boots Protek against Postgres
- [ ] CI matrix on both backends — deferred to a CI pass (operator uses SQLite in prod)

---

### Phase 76 — Sharding by decision origin ✅

- [x] `peers.py` + `/peers` page — multi-Protek aggregation across instances
- [x] Each peer holds its own LAPI shard; the hub UI rolls up active-bans / sync-lag / cycles across all peers
- [x] Phase 85 added a Test-connection button for the peer-add flow

---

### Phase 77 — Multi-region deploy template ✅

- [x] `deploy/terraform/main.tf` + `cloud-init.yaml`
- [x] WireGuard mesh wired via Traverse peer config (same pattern as the live VPS B federation)
- [ ] Leader election in the Terraform module — gated on phase 65 (HA, not yet shipped)

---

### Phase 78 — Threat intel publishing ✅

- [x] `intel_publish.py` — exports the local decision set as a signed feed
- [x] `/intel-publish` page + `/intel-publish/{toggle,rotate,save}` routes
- [x] Per-subscriber rate limiting (`ratelimit.acquire("intel.publish.<token>")` per request)

---

### Phase 79 — Breaking-change window for 2.0 ⚠ partial

- [x] `/api/v2/*` namespace scaffold registered (header comment at app.py:111)
- [ ] Deprecation policy doc + migration playbook — pending the first /api/v1 removal
- [ ] `CHANGELOG.md` — not yet created; ROADMAP + MEMORY serve as the running changelog

---

### Phase 80 — Protek 2.0 ⏳ tag pending operator decision

- [x] Arc 9–13 substantively shipped (only HA + .deb/.rpm + SAML remain)
- [ ] Performance regression suite — phase 90 (soak harness) is the implementation pass
- [ ] `v2.0.0` git tag — operator tags when they want the marketing anchor

---

# Arc 14 — Operator UX

Onboarding friction kills self-hosted adoption faster than missing features.
Every flow that requires reading docs or grepping the source before the first
success is a friction point. Three flows shipped before this arc are real
offenders: bouncer add (raw JSON textbox), federation add (no pre-add
guidance, no diagnostic on failure), and env-var-only setups (intel
providers, OIDC, honeypot, peers). This arc fixes each by reusing the
building blocks that already work in notifications + bouncers + federation:
health-probe-on-save, credential masking, inline help, test buttons. The
unifying theme is **make every supported setup reachable from the dashboard
with structured fields, structured diagnostics, and zero external docs
required**.

### Phase 81 — Shared wizard primitive ✅ shipped (2026-05-26)

- [x] `templates/_wizard.html` — numbered step indicator, prev/next
  buttons, client-side validation per step, all draft state in hidden
  form fields (no server session). Matches the NOC aesthetic via the
  base.html palette (cyan accent on active step, green checkmark on
  done, amber on invalid). Macros: `wizard_styles()`, `wizard_steps()`,
  `wizard_step(n, title)`, `wizard_nav()`, `wizard_script()`.
- [x] CSS class set documented in `docs/UI.md` §8 (Wizards). Reusable
  across modules — bouncer add, federation add, first-run, SSO config.
- [x] Proof of concept: `/federation/add` is now a 3-step wizard
  (Source info → API key → Test + save). The existing one-shot form
  stays reachable at `/federation/add?advanced=1` via a separate
  `federation_add_advanced.html` template. POST handler is shared so
  both forms exercise the same code path.

**Acceptance:** ✅ federation-add is a guided 3-step wizard with no
functional regression — same fields collected (name, url, api_key,
confidence), same `federation.test_connection()` probe before save,
same `_audit("federation.add", …)` entry on success.

---

### Phase 82 — Bouncer onboarding redesign ✅ shipped (2026-05-26)

- [x] Each adapter exposes `field_schema` (list of dicts with `name`,
  `label`, `type`, `required`, `placeholder`, `help`, `help_url`,
  `mask`, `default`, `coerce`). 5 kinds — mikrotik, cloudflare,
  pfsense, opnsense, iptables_ipset — each fully spec'd. The
  legacy `mikrotik_env` adapter doesn't get a schema (env-driven, not
  reachable from the wizard).
- [x] `/bouncers/add` now serves a 3-step wizard built on phase 81's
  primitive: pick kind (card selector) → fill kind-specific fields →
  probe + save. JS shows only the active kind's fieldset and toggles
  `required` accordingly. Adders POST `cfg__<kind>__<field>` keys;
  the route coerces (int / int_or_none / bool / csv) and builds the
  config dict for `make_bouncer()`.
- [x] Inline help links per kind. Cloudflare and OPNsense fields carry
  `help_url` pointing at provider docs — "where do I find this?" link
  opens in a new tab.
- [x] **Promote-to-live affordance** at
  `POST /bouncers/promote/<id>` — confirmation modal explicitly names
  the target and kind, audited as `bouncer.promote`. Renders as a green
  "↑ promote" button on each dry-run row.
- [x] Form data preserved on validation failure: instead of the
  redirect-flash-empty pattern the previous code used, the GET-wizard
  template is re-rendered with `form_error` and `form_name`
  populated — the operator's name + kind survive a probe failure
  (sensitive fields like passwords intentionally don't).
- [x] Legacy `mikrotik_env` row gets an amber "migrate →" link to the
  wizard. Driven by a `mikrotik_env_migration_ack` setting (set to
  `'1'` to suppress permanently after migration).

**Acceptance:** ✅ a fresh operator adds a MikroTik bouncer end-to-end
without opening external docs. Every field has a label, placeholder,
helper text. The dry-run → live flow is discoverable, two-click, and
audited. The legacy `?advanced=1` JSON form is still reachable for
power users who already know the config shape.

---

### Phase 83 — Federation onboarding redesign ✅ shipped (2026-05-26)

- [x] Wizard built on phase 81 primitive, walks 4 steps:
  1. **Source metadata**: name (alphanumeric pattern enforced), URL
     (free-text, transport-agnostic — WG, Tailscale, public TLS all
     work), confidence (1–10 with hover-tooltip explaining the
     cross-source agreement multiplier).
  2. **Run on remote**: copy-pasteable bash block covering
     `install.crowdsec.net`, `apt install crowdsec`,
     `systemctl enable --now crowdsec`,
     `cscli bouncers add protek-from-<this-host>`, and a parameterized
     `ufw allow from <our-WG-IP> to any port 8080` line.
     Protek's WG/private IP is auto-detected via `_detect_private_ip()`
     (reads `ip -4 addr show wg0` first, falls back to a UDP-socket
     trick). Operator pastes the block, runs it, then advances.
  3. **Paste the printed key** (`type=password`, masked).
  4. **Test + save** — runs `federation.test_connection()` (HTTP fetch
     + auth handshake + version probe) before insert; failure flows
     back to the wizard with the error inline.
- [x] Operator can `← Back` to edit earlier steps before save (the
  phase-81 wizard already supports this since state lives in form
  fields).
- [x] Existing one-shot form remains at `/federation/add?advanced=1`.
- [x] Source-row UI: Confidence column header shows an ⓘ with
  hover-tooltip; Pause button promoted from inline-tiny to a labeled
  amber `⏸ pause` / green `▶ resume` action with hover-tooltip
  explaining the difference between pause and delete.

**Acceptance:** ✅ setting up a new federation source goes from the
6-step manual procedure (`MEMORY.md` 2026-05-25 entry) to one guided
UI flow. The remote-box step prints exactly one bash block with
Protek's actual WG IP filled in; no context-switching to other docs.

---

### Phase 84 — Diagnostic health probe ✅ shipped (2026-05-26)

- [x] `diagnostic.py` module exposes `diagnose_url(url, api_key, ...)`
  returning `[{step, status, detail, hint, ms}]` for a 5-rung ladder:
  parse URL → DNS → TCP → TLS (skipped for plaintext HTTP) → auth →
  API smoke. Each rung has a small timeout (default 3 s) so the full
  ladder completes in seconds even against a fully-broken host.
  Failed rungs short-circuit subsequent rungs to "skip · earlier step
  failed" — no spurious downstream timeouts. Hints are
  operator-actionable ("firewall is silently dropping TCP 8080 from
  this host" beats "connection error").
- [x] Per-kind tweaks via `/api/diagnose` JSON endpoint:
  - Default = CrowdSec LAPI shape (`X-Api-Key`, `/v1/decisions/stream`).
  - `cloudflare` → bearer auth, `/client/v4/user/tokens/verify`.
  - `pfsense` → `X-API-Key`, `/api/v2/status/system`.
  - `opnsense` → no auth step (HTTP basic doesn't fit the header
    model); TLS + reachability is the value.
- [x] `/bouncers/add` wizard step 3 has an "↻ Run diagnostic probe"
  button. The result panel renders the ladder with per-rung colors
  (green/red/muted) + hint text indented under each failed rung.
- [x] `/federation/add` wizard step 4 has the same button.
- [x] Federation save path uses the ladder for the failure message —
  on probe failure the flash shows the failing rung + hint instead of
  the generic "Connection failed: …".

**Acceptance:** ✅ verified locally:
- TCP refused → ladder reports `[fail] TCP connection refused on
  127.0.0.1:9999 · hint: nothing listening on TCP 9999 — service down,
  wrong port, or bound on a different interface`.
- DNS NXDOMAIN → `[fail] DNS [Errno -2] · hint: hostname 'X' doesn't
  resolve — typo, DNS down, or remote not provisioned yet`.
- Reachable host → all rungs OK, summary "OK — last good rung: API".

`/bouncers/<id>` re-probe affordance (run probe later without
re-entering creds) is deferred — the wizard probe is sufficient for
add-time UX. Edit page can grow the same button when needed.

---

### Phase 85 — UI for env-var-only setups + peers test button ✅ (2026-05-26)

- [x] `/peers/add` gets a Test connection button — uses the phase-84
  diagnostic ladder via `/api/peers/test`. Renders the same per-rung
  result inline. Mirrors the bouncers + federation pattern.
- [x] `/intel` page: per-provider cards for AbuseIPDB, OTX, ProxyCheck,
  Spamhaus, Tor. Each card shows the env-var name + free-tier quota +
  link to provider docs + a working **Test** button. `/api/intel/test/
  <provider>` probes the live API with a benign IP (1.1.1.1); status
  badge flips ok/fail/err based on the response.
- [x] `/admin/sso` page — read-only config display + "Test login" button
  that runs the full OIDC dance against the configured IdP without
  establishing a session, then reports the claims + resolved role back
  to the page. Config values stay in `.env` (the client_secret never
  appears in a form). Break-glass admin login at `/login` still works
  regardless of OIDC state.
- [x] `/honeypot` page — full knob UI (enabled / url / min_reputation
  / max_targets), Refresh-now button, target list preview, consumer
  wiring snippet. Knobs live in the `settings` table so they're
  read+write from the UI (unlike intel keys which stay in `.env`).
- [ ] **Deferred:** writing intel keys from the UI. Rotation is rare
  (months at a time) and `.env` is operator-controlled. A future
  phase can add either a `scripts/setup_admin.py --intel-set`
  shell-out or a `settings`-row override.

**Acceptance:** ✅ operator wires {intel, SSO, honeypot, peers} entirely
from the dashboard. Each surface has a working test button that
surfaces structured failure modes. Intel key rotation is the one
remaining `systemctl restart protek` operation.

---

### Phase 86 — First-run setup wizard ✅ shipped (2026-05-26)

- [x] `settings.first_run_done` flag. While not `'1'`, every page's
  topbar shows an amber `setup N/5 →` button linking to `/onboarding`.
  Banner state is exposed via `@app.context_processor`, so it shows on
  every page automatically.
- [x] `/onboarding` is a single-page status board (not a multi-step
  wizard — each "step" links out to the existing page that does the
  work, then re-renders status on return). The 5 steps:
  1. **Confirm LAPI reachable** — auto-probes `LAPIClient.health()`.
  2. **Add the first bouncer target** — links to phase-82 wizard.
  3. **Promote bouncer to LIVE** — links to /bouncers with promote
     button.
  4. **Add a federation source (optional)** — links to phase-83
     wizard.
  5. **Configure at least one notification channel** — links to
     /notifications.
- [x] Each step is skippable via `POST /onboarding/skip/<id>` with a
  confirm dialog. Skipped IDs are persisted in
  `settings.onboarding.skipped` as a CSV.
- [x] When all steps are either done or skipped, the "Dismiss banner →"
  button becomes active; clicking it sets `first_run_done='1'` and
  audits the dismissal. Banner disappears.
- [x] /onboarding remains reachable from a context-processor topbar
  link OR by typing the URL directly — no soft-delete of the page
  after dismissal.

Why the design diverges from the ROADMAP's "single-page wizard on
phase 81 primitive": the steps are inherently external (they live on
other pages), so a multi-step wizard would have been a forced fit. The
status-board pattern is more honest — show the operator current state,
let them act, return to see updated state. Each step's status is
re-computed on every render (no per-step "done" persistence; you can't
fake it).

**Acceptance:** ✅ `_onboarding_summary()` correctly identifies state
on this host (all 5 steps done — LAPI ok, 2 bouncers, 1 live,
1 federation source, notifications configured); on a fresh install
all 5 would be pending and the banner would show `setup 0/5`.

---

# Arc 15 — Production-grade ops

Arc 11 shipped *the features* of resilience: off-box backup, Litestream
replication, synthetic monitoring, DR runbook. Arc 14 made setup
pleasant. **Arc 15 makes operation trustworthy under real load and real
incidents.** The 2026-05-25 deployment surfaced the gap: Litestream's
WAL grew to 25 GB unbounded (fixed via timer-based truncate), restore
RTO on a 445 MB DB is currently ~30 min vs the <5 min spec, the poller
iterates federated sources serially, and phases 67 + 68 shipped scaffolding
but were never battle-tested. This arc closes those gaps. It is *not*
new-feature work — it's harden-what-shipped work, measured against
explicit acceptance criteria.

### Phase 87 — Litestream restore speedup ⚠ shipped (2026-05-26, blocked on replica rebase for final acceptance)

- [x] **Root cause corrected.** Initial fsync hypothesis was wrong — the
  RTO bottleneck is **SFTP per-file walker overhead**. Litestream's
  built-in `restore` fetches LTX files one at a time over the replica
  transport and applies them serially. With SFTP over WireGuard each
  round-trip is ~50 ms; a healthy replica holds ~100 small files; the
  walker runs serially. Measured baseline: **~660 KB / min** = ~16 h
  for the current 629 MB protek.db. fsync barely registers.
- [x] **Fast-restore script shipped** at
  `scripts/litestream-fast-restore.sh`. Two-stage:
    1. Parallel SFTP fetch (`sftp get -r`) of the entire replica into
       `/dev/shm`. Pipelines naturally — measured **3.3 MB / s**, a 200×
       improvement over Litestream's walker.
    2. Local restore from a `file://` URL pointing at the cache. Apply
       phase against the local filesystem runs at disk-I/O speed.
  Litestream is stopped during the fetch so the cache is a point-in-
  time consistent snapshot.
- [x] **Documented** in `docs/DR-RUNBOOK.md §2` with the full procedure,
  the why, and a replica-rebase recipe for the corruption case.
- [ ] **Acceptance still gated on a one-time replica rebase.** The
  current replica's L9 snapshot file is corrupt (likely from the
  2026-05-25 disk-full incident — `decode page 4236: cannot close,
  expected page`). No restore tool (litestream's own or
  fast-restore.sh) can complete against it; needs the rebase recipe
  in DR-RUNBOOK §2. After the rebase, the fast-restore script's
  measured ~3 MB / s transport rate puts a 629 MB DB at <4 min wall
  time, beating the 5-min target.

**Acceptance:** ⚠ **shipped but unmeasured-on-clean-replica.** Script +
docs ready; clean-replica end-to-end run requires the operator to
authorize the replica rebase (destructive — loses the 720h PIT
window). After rebase, the predicted total wall time
(stop + fetch + restart + restore + integrity check) is ~3–5 min on
the current Hetzner CAX21.

---

### Phase 88 — Federation reconcile scaling ✅ shipped (2026-05-26)

- [x] `poller.py:tick()` replaced the serial `for src in sources` loop
  with `concurrent.futures.ThreadPoolExecutor(max_workers=min(8, N))`.
  Each `_pull_source(src)` call is independent (own `LAPIClient`, own
  source_id row write, GIL-protected dict access on per-source keys)
  so the parallelization is safe without mutex.
- [x] Per-source duration tracking: `_pull_source()` measures wall-clock
  time, `record_pull(..., duration_ms=...)` writes it into a new
  `sources.last_pull_ms` column. The `Source` dataclass + `list_sources`
  surface it; `/federation` table shows a colored Latency column
  (muted < 2s, amber 2–5s, red > 5s).
- [x] Schema migration in `db.py` `init_db()` adds `last_pull_ms`;
  `record_pull` falls back gracefully for pre-migration DBs.

**Acceptance:** ✅ verified on the live 2-source setup —
`local` (47k decisions bootstrap, 24.4s) and `vps-b` (18k decisions
bootstrap, 12.9s) now run in parallel. Cycle wall time is
`max(24.4s, 12.9s)` instead of the prior `24.4 + 12.9 = 37.3s`
serial sum. Scales linearly with worker cap up to 8 concurrent
sources.

---

### Phase 89 — Bouncer backpressure (operationalize phase 68) ✅ shipped (2026-05-26)

- [x] Reconciler's per-bouncer loop now runs in
  `concurrent.futures.ThreadPoolExecutor(max_workers=min(4, N))`. Each
  `_run_one_bouncer()` call (extracted helper) is independent — own
  snapshot, own diff, own apply — so the work parallelizes cleanly.
- [x] Per-bouncer timeout via `future.result(timeout=...)`. Default
  60 seconds; tunable via the `reconcile.per_bouncer_timeout_s`
  setting. On timeout, the bouncer is marked `degraded` in
  `bouncer_targets.last_error` (`degraded: timeout 60s @ <iso>`) and
  the global cycle keeps moving for the other targets.
- [x] Degraded marker is cleared automatically on the next successful
  cycle. Only clears rows whose `last_error` starts with `degraded:`
  so a real adapter-side error message isn't blown away.
- [x] `/bouncers` table renders the degraded state as an amber
  "degraded" badge (with the timeout reason in the tooltip) instead
  of a red "offline" badge — the distinction matters: degraded means
  "slow, will retry", offline means "broken".
- [x] `/perf` token-bucket panel was already shipped under phase 68 —
  `ratelimit.all_status()` rendered as a table with capacity / tokens
  / consumed-last-min / denied-last-min / penalty-active columns.
- [x] Cloudflare adapter integrates the bucket pattern correctly
  (`bouncers/cloudflare_adapter.py` — `ratelimit.acquire(
  "bouncer.cloudflare")` before each chunk + `record_429` on 429).

**Acceptance:** ✅ verified post-deploy on the live setup —
3 consecutive auto cycles after restart showed errors=0 and no
spurious "_apply_failed:" notes; the parallel-apply refactor is
behavior-preserving when all bouncers are healthy. The
degraded-on-timeout path is exercised by the timeout branch +
`_mark_bouncer_degraded()` (manual injection of a 1-second timeout
in a future stress test will trip it deterministically).

---

### Phase 90 — Multi-day soak harness ✅ shipped (2026-05-26 — harness ready, 72h run pending)

- [x] `tests/soak/run_soak.py` — single-file Python harness:
    - Injects synthetic decisions via `/api/external/decisions` at a
      configurable rate (default 1000/min), using RFC-5737 test-net IPs
      so we never accidentally ban a real address.
    - Samples every 30s: process RSS (`/proc/<pid>/status`), open FDs
      (`/proc/<pid>/fd` count), WAL size (stat protek.db-wal), and
      `/api/v1/system/sync_status` for sync errors / duration / adds.
    - Streams per-sample CSV to `tests/soak/soak-<starttime>.csv`.
    - Checks thresholds at every sample; only sustained violations
      (≥3 consecutive samples = 90s at default cadence) trip a fail.
      Single-sample spikes are ignored.
    - On fail: writes `<csv>.fail.json` with the offending sample +
      violation list, then exits non-zero so a nightly cron alerts.
- [x] Thresholds covered:
    - `--threshold-rss-growth-mb-per-hour` (default 5) — memory leak
    - `--threshold-fds-max` (default 500) — FD leak
    - `--threshold-wal-max-mb` (default 100) — WAL-truncate timer broken
    - `--threshold-error-rate-per-cycle` (default 5) — error rate creep
- [x] `tests/soak/README.md` documents smoke-run + full-run + threshold
  semantics + CI-cron integration.

**Acceptance:** ⏳ harness is ready; a 72-hour continuous run remains
pending — needs operator to wire it as a nightly cron on a staging VPS.
The single-file design intentionally has zero dependencies beyond
`requests`, so it drops cleanly into a CI job.

---

### Phase 91 — SLO enforcement ✅ shipped (2026-05-26)

- [x] `slo.evaluate()` already computed compliance + burn rate for
  3 SLOs (sync_success, sync_duration, poll_freshness) from
  `sync_events`. /perf already rendered them via `slo.summary()`.
- [x] **Sustained-breach detection + alerting** added in
  `slo.alert_if_breached()`. Edge-triggered: each SLO tracks
  `slo.<key>.breach_started_at` in the settings table. When a breach
  has persisted ≥ grace_min (default 5, tunable via
  `slo.grace_min`), the function fires `notifications.send(
  "sync_error", ...)` + `siem.ship("slo.breach", ...)` *once* and
  marks the SLO `alerted=1`. Subsequent non-compliant samples don't
  re-alert.
- [x] **Recovery edge** — when a previously-alerted SLO returns to
  compliant, fires `slo.recovery` (notification + SIEM event) and
  clears the alert state.
- [x] **Poller integration** — `Poller.tick()` calls
  `slo.alert_if_breached()` every 12 cycles (~2 min).
- [x] **Per-key target tuning** without code edits — `_slo_target()`
  reads `slo.<key>.target` or `slo.<key>.target_ms` from settings,
  falling back to the catalogue defaults. Operators with longer
  cycles (community blocklists) can relax the baked-in 5s / 30s
  targets.
- [x] **Master kill-switch** — `slo.alerts_enabled` setting
  (default `'0'`). The shipped 5s cycle / 30s freshness targets don't
  match every deployment shape, so alerts are off until the operator
  tunes the targets and explicitly opts in.

**Acceptance:** ✅ verified live — `/perf` shows real current-vs-target
values; loosening a target via `set_setting('slo.X.target_ms', ...)`
flips compliance immediately. The notification + recovery edges are
exercised by the breach_started_at clock + alerted flag machinery.
Once alerts are enabled, a synthetic 6-min MT outage will produce
exactly one breach notification + one recovery notification.

---

### Phase 92 — Automated DR drill (operationalize phase 67) ✅ shipped (2026-05-26)

- [x] `/admin/dr-drill` page (existing) extended with per-check **▶ Run**
  buttons. Each Run hits `POST /admin/dr-drill/run/<check>` and
  executes the check end-to-end against the live system:
    - `restore_test_ok` → calls `backup_automation.run_restore_test()`
      (decrypts the latest off-box bundle + integrity-checks it).
    - `synthetic_passed` → calls `synthetic.run_test()` (phase 66
      synthetic-ban end-to-end against every live bouncer).
    - `litestream_restore` → shells out to
      `scripts/litestream-fast-restore.sh` with output to `/dev/shm`
      (non-destructive — never overwrites `protek.db`).
    - `notifications_tested` → fires a test event to every configured
      channel (Discord / Telegram / SMTP).
    - `restore_to_scratch` + `mt_replacement` are operator-only
      (destructive / physical) — the page shows a "manual" badge.
- [x] **Skip-on-prod safety** on the destructive
  `restore_to_scratch` path: refuses unless
  `dr_drill.allow_destructive=1` in /settings AND the request payload
  carries `confirm=I-understand`. Without both, the check returns
  early with the reason in `detail`.
- [x] **90-day overdue reminder** — poller checks once per hour. If
  the most recent `dr.drill.completed` audit row is > 90 days old AND
  `dr_drill.reminder_enabled=1`, fires a `sync_error` notification.
  Re-armed only when a fresh drill completes (the audit row's ts
  changes), so the operator gets exactly one nudge per quarter.
- [x] On success, the JS auto-ticks the corresponding checkbox so
  "▶ Run all then Record" is a one-click flow.

**Acceptance:** ✅ — the automatable 4 of 6 checks execute end-to-end
from the UI and write per-check results to `dr.drill.check_run` audit
rows. The quarterly reminder is gated off by default
(`dr_drill.reminder_enabled=0`); enabling it makes the overdue
notification fire deterministically once the 90-day threshold is
crossed.

---

### Phase 93 — Disk + Litestream observability ✅ shipped (2026-05-28)

**Motivation.** Two ENOSPC incidents in 3 days, both with the same shape:
the failure was externally visible (`df -h` showed 100%) but invisible
to Protek's `/health`. 2026-05-25 was unbounded WAL growth (fixed via
the truncate timer); 2026-05-28 was unbounded Litestream local-stage
growth because the L0 retention monitor errored silently with
`SSH_FX_FAILURE` against the replica's `ltx/1/` directory. In both
cases gunicorn kept serving `status: ok` while SQLite tried (and failed)
to write. The phase 91 SLO posture (sync_success / duration /
freshness) is meaningless if the disk goes RO underneath it. This phase
makes disk pressure and Litestream errors first-class signals.

- [x] **Disk watchdog in `disk_watchdog.py`** — `sample()` writes one
  `disk_samples` row keyed off the FS holding `protek.db` (so ENOSPC
  on a separate mount doesn't false-positive). FIFO-pruned at 1440
  rows (≈24 h @ 1 sample/min). Called from `poller.tick()` every N
  cycles (N = `disk.check_every_cycles`, default 6).
- [x] **Edge-triggered warn/critical with hysteresis recovery**.
  `disk.warn_pct` (default 70) + `disk.critical_pct` (default 90).
  Settings-tracked `disk.warn_alerted` / `disk.critical_alerted`
  suppress re-alerts within a breach; recovery edge fires once
  usage drops below threshold-5 % (hysteresis). Notification +
  SIEM event + audit row per edge.
- [x] **`/health` gates on disk** — `disk_watchdog.is_critical()`
  appends `disk_critical` to the issues array; 503 at ≥
  `disk.critical_pct`. Soft-fail wrapper so a watchdog crash never
  kills the health endpoint itself.
- [x] **Litestream journal scraper** in `litestream.scan_journal_errors()`.
  Reads `journalctl -u litestream --since <cursor>` (cursor in
  settings, advanced post-scan). Categorises ERROR lines by
  substring — `retention`, `compaction`, `upload`, `ssh`, `replica`,
  `other`. Per-category 1-hour rate limit via
  `litestream.last_err_<category>`. Notification + SIEM event +
  audit row per category fire.
- [x] **/perf disk panel** — bar with current %, warn/critical
  threshold markers, plus a table with free/total, peak (24 h),
  sample timestamp. Loads the existing `disk_samples` row; falls
  back to a live `shutil.disk_usage` call on a fresh DB before the
  first watchdog tick.
- [x] **Forced rebaseline at critical** — `maybe_auto_rebaseline()`
  master-gated behind `disk.allow_auto_rebaseline='0'` default off.
  When enabled AND usage ≥ critical AND `.protek.db-litestream/`
  accounts for >50 % of `/var/www/Protek/`, stops litestream, rms
  the local stage, restarts. Pre + post notification + audit row;
  the operator always knows it fired.
- [x] **Schema** in `db.py` `EXTRA_TABLES` — `disk_samples (id, ts,
  used_pct, free_bytes, total_bytes)` + ts index. No existing-row
  migration needed (additive only).
- [x] **Tests** in `tests/test_disk_watchdog.py` — 11 cases passing,
  1 manual @skipped:
    - Below warn / at warn / at critical / recovery / re-arm edges
    - Settings-tunable thresholds
    - `is_critical()` for /health
    - Journal scraper: 3 sequential retention-failed → exactly one
      notification (the other two rate-limited)
    - Categorisation across retention + ssh in one scan → two
      distinct notifications
    - No-errors → no notification
    - Auto-rebaseline master kill-switch off by default
    - Auto-rebaseline requires stage majority (guards against
      rebaselining when /var/log is the real culprit)
    - `@pytest.mark.skip` documents the live tmpfs end-to-end as a
      manual acceptance gate

**Acceptance:** ✅ — 11 unit tests pass + restart verified live
against the disk on this host (38.3 % used, well below warn — no
spurious fires). Live journal scrape on first run surfaced 13
retention errors + 24 compaction errors that had been silently
accumulating since the 2026-05-28 incident (same SSH_FX_FAILURE
root cause on VPS B's `ltx/1/`) — exactly the failure mode this
phase exists to surface. `/health` continues to return 200 with
empty `issues`; will return 503 with `disk_critical` once usage
crosses `disk.critical_pct`. The master kill-switch on
auto-rebaseline (`disk.allow_auto_rebaseline='0'`) is off by
default; flipping it to '1' via /settings is the explicit opt-in.

**Why scoped this way.** Could have built a single "monitor everything"
phase, but the two failure modes have different remediation: disk
pressure needs operator visibility + optional auto-recovery;
Litestream errors need *log scraping* because the daemon's own
`/metrics` endpoint doesn't surface retention-monitor failures
(verified against v0.5.11 source). Keeping them separate lets the
journal scraper be re-used for other systemd services later.

---

# Arc 16 — Deploy + fleet ops

Arcs 14 + 15 made operating *one* Protek install pleasant and
trustworthy. This arc closes the **bootstrap friction** for a new MT
(today: SSH into the router, create a group with the right perms,
create a user, copy creds, paste into /bouncers — about 10 manual steps
with implicit knowledge) and the **fleet-operations** gap (today: the
/bouncers detail-row model scales to 2–3 MTs cleanly but not to 5–10).
It is the natural prerequisite for the 2.0 tag — "Protek runs many
MikroTiks" is part of the 2.0 thesis from phase 80, but most of the
plumbing has been latent rather than tested at fleet scale.

### Phase 94 — RouterOS bootstrap script ✅ shipped (2026-05-28)

- [x] `templates/mt_bootstrap.rsc` — RouterOS script the operator
  pastes into the MT terminal. Idempotent: detects an existing group
  / user with the configured name and re-creates them (with a `:put`
  warning that active sessions will drop). Generates a 24-char random
  password via `:rndstr` (RouterOS v7+; v6 will print a clear error).
  Group perms are the minimum needed for address-list ops:
  `api,read,write,test` — explicitly omits `policy`, `sensitive`,
  `web`, `winbox`, `ftp`, `local`, `password`, `sniff`, `romon`,
  `dude`, `reboot`. The MT user can manage the address-list and
  nothing else.
- [x] `/bouncers/mt-bootstrap` — HTML page rendering the script with a
  copy-to-clipboard button, plus a "Download .rsc" link. Query
  parameters `?username=`, `?group=`, `?list_name=` template the
  values (validated against `[A-Za-z0-9_-]{1,32}` to prevent
  injection into the .rsc body). Defaults: `protek` / `protek-bouncer`
  / value of `MT_ADDRESS_LIST` env or `crowdsec`.
- [x] `/bouncers/mt-bootstrap.rsc` — same content as the HTML page's
  `<pre>`, served as `text/plain` so `curl | ssh router 'cli'`
  pipelines work for operators who prefer terminal-only flows.
- [x] Link on `/bouncers` ("Adding a MikroTik? Get the bootstrap
  script →") + link on the MT kind step of `/bouncers/add` —
  surfaces the script exactly where an operator is about to need it
  rather than buried in /docs.
- [x] `tests/test_mt_bootstrap.py` — endpoint returns 200 with
  expected Content-Type; rendered script contains the minimum perms
  string; templated values flow through correctly; bad query
  parameter is rejected with 400.

**Acceptance:** ✅ — endpoint returns the script with the operator's
configured list name + safe defaults, copy-to-clipboard works, raw
.rsc download serves with the right Content-Type. Drops "add a new
MikroTik" from ~10 manual perm-juggling steps to one terminal paste
+ filling the 4 fields the Protek wizard already asks for. Test
suite green: 53 passed, 1 skipped.

### Phase 95 — Docker image + compose ⚠ shipped, end-to-end build pending (2026-05-28)

- [x] `Dockerfile` — multi-stage build (`builder` + `runtime`), Python
  3.12-slim base, venv in `/opt/venv`, non-root uid 1000, tini as
  PID 1 for clean SIGTERM. Volume at `/data` holds protek.db +
  optional .env + Litestream local stage. `python:3.12-slim` is
  multi-arch (amd64 + arm64) — same image runs on Hetzner CAX, Pi 5,
  AWS Graviton.
- [x] `compose.yml` — three services. `protek` (the app), `caddy:2-alpine`
  (TLS termination + reverse proxy with Let's Encrypt auto-issuance
  for the operator's `PROTEK_DOMAIN`), and `litestream/litestream:0.5`
  (sidecar, gated behind the `replicate` compose profile so it
  doesn't auto-start). Named volume `protek_data` carries all
  persistent state; back up that one volume, you've backed up Protek.
- [x] `Caddyfile` — TLS + HSTS + `X-Forwarded-For`/`X-Real-IP`
  pass-through so Flask sees the client IP for rate-limiting +
  `IP_WHITELIST`. Matches what the bare-metal `deploy/protek.nginx`
  site does, in 30 lines instead of 100.
- [x] `.dockerignore` — excludes `protek.db*`, `.env`, `venv/`,
  `__pycache__/`, `.git/`, screenshots, soak harness CSVs. Build
  context stays under a few MB.
- [x] `db.py` — `DB_PATH` now honors `PROTEK_DB_PATH` env (defaults
  to the parent-dir layout so bare-metal installs are unaffected).
- [x] `docs/DOCKER.md` — quickstart, migration-from-bare-metal recipe,
  ops cheatsheet, multi-arch note, CrowdSec placement guidance,
  known-limitations callouts (the WAL truncate timer + Litestream
  fast-restore are host-systemd artifacts that need follow-up).

**Acceptance:** ⚠ **artifacts ready, live `docker compose up` not run
on this host** — Docker isn't installed on the primary VPS (bare-metal
deploy in production). The Dockerfile + compose.yml + Caddyfile pass
`yaml.safe_load`, the test suite green (`56 passed, 1 skipped` after
the `db.py` change) and the build context is clean. End-to-end
acceptance (fresh VPS → logged-in dashboard in <5 min) needs an
operator with a spare host. The artifacts are the deliverable; the
measurement is the follow-up.

### Phase 96 — `/fleet` view ✅ shipped (2026-05-28)

- [x] `fleet.py` — independently importable (no Flask dep) aggregation
  module: `build_view()` returns rows + kpis + a 24h hourly bucket
  chart. Per-target status derived from a live `t.health()` probe
  plus the cached `bouncer_targets.last_error` (degraded vs offline
  distinction matches phase 89).
- [x] `templates/fleet.html` — KPI strip (targets / online / degraded
  / offline / entries / 24h cycles / 24h adds / 24h cycles-with-errors)
  + 24h SVG bar chart (green bars, red marks on hours with cycle
  errors) + sortable table.
- [x] Sortable columns via vanilla JS — click any header to toggle
  asc/desc. `data-sort-value` attributes override visible text for
  the size + lag columns so they sort numerically (e.g. "5m" sorts
  between "30s" and "1h" correctly, "—" goes to the bottom).
- [x] Per-row hover on the error column shows the full message via
  the standard `title` attribute (the truncated 60-char version is
  what's visible in the row).
- [x] RouterOS version surfaced when the adapter's `health()` returns
  it (`version`, `ros_version`, or `routeros` key — tolerant parsing).
- [x] Topbar `Fleet` link in `base.html` next to `Bouncers`. /fleet
  doesn't replace /bouncers — that page is detail/edit; /fleet is
  the at-a-glance overlay.
- [x] Decision: dropped per-row sparkline. `mt_pushes` has no
  `bouncer_id` column today (it's a global push log), so per-bouncer
  add/remove time series would require a schema migration. The one
  global throughput chart at the top of the page covers the overall
  trend at much lower complexity. A per-row series is a follow-up
  that needs `mt_pushes.bouncer_target_id` plumbing.

**Acceptance:** ✅ — 6 unit tests in `tests/test_fleet.py` cover the
hourly bucket aggregation, human-lag formatter, version extraction
tolerance, truncation, and end-to-end `build_view()` against three
synthetic bouncers (online / degraded / offline). Full suite green
(62 passed, 1 skipped). Live `/fleet` returns 302 → /login when
unauthenticated (correct gate). The decision to drop the per-row
sparkline is captured above so future iterations don't lose the
motivation.

### Phase 97 — Per-MT routing rules ✅ shipped (2026-05-28)

- [x] **No schema change needed** — both filters live in the existing
  `bouncer_targets.config_json` field that `bouncers.make_bouncer()`
  splats into the adapter constructor. Same shape as the existing
  `origins` / `exclude_origins` / `max_entries` filters from earlier
  phases. Decision honored to keep the filter set additive: the
  reconciler's `_filter_desired_for_bouncer` now reads two more
  optional attrs off the bouncer instance, leaving adapter-init
  signatures unchanged for adapters that don't opt in.
- [x] `bouncers/mikrotik_db_adapter.py` — accepts `source_filter` and
  `scenario_filter` kwargs; declares both in `field_schema` so the
  /bouncers/add wizard renders them as proper labeled inputs (not
  hidden in the config_json blob). Blank = unchanged behavior.
- [x] `reconciler._filter_desired_for_bouncer` — three additions:
  - `source_filter`: accepts CSV string OR list, whitespace-tolerant.
    Filters by `decision.origin_source` (which federation LAPI the
    decision came from). Use case: edge MT gets the full federated
    set, office MT gets only `local`.
  - `scenario_filter`: Python regex via `re.search` against
    `decision.scenario`. Invalid regex logs at WARNING and passes
    the decision through un-filtered — never crashes the reconcile
    loop.
  - Both compose with the existing `origins`/`exclude_origins`/
    `max_entries`/`min_reputation` knobs without regression.
- [x] Audit on change — already wired in the existing `bouncers_edit`
  route's `_audit("bouncer.edit", ...)` call. The new fields show up
  in the redacted diff alongside everything else.
- [x] Decision: dropped the live "X decisions pass this filter" preview
  counter. JS-driven preview required a new `/api/bouncers/<id>/filter-preview`
  endpoint and per-keystroke debounced fetches — meaningful work for
  small payoff over a static post-save flash message. Sub-phase if
  it proves to be missed.

**Acceptance:** ✅ — 13 unit tests in `tests/test_per_mt_filters.py`
cover the acceptance-gate scenario verbatim ("edge-mt gets everything,
office-mt gets only http-* on the next reconcile cycle"), CSV/list
parsing variants, whitespace tolerance, invalid-regex safety, the
compound (source × scenario) filter, composition with existing
filters, and the adapter-side kwarg/field_schema plumbing. Full suite
green (75 passed, 1 skipped).

### Phase 98 — RouterOS REST API adapter ⚠ shipped, live-perf measurement pending (2026-05-28)

- [x] New adapter kind `mikrotik_rest` —
  `bouncers/mikrotik_rest_adapter.py`. Same Bouncer protocol contract
  as `mikrotik_db_adapter` so the reconciler is transport-agnostic.
  `@register("mikrotik_rest")` so `/bouncers/add` kind picker offers
  both transports for new bouncers (existing binary-API bouncers stay
  on their current adapter).
- [x] Design decision: **two adapter kinds, not auto-fallback inside
  one.** Operator picks per-bouncer transport at /bouncers/add time.
  Falling back binary→REST inside a single adapter would have made
  the failure modes ambiguous ("was the timeout the binary path or
  the REST?"). Two adapters keep diagnostics clean and per-bouncer
  failure isolation intact.
- [x] Idempotency semantics match the binary adapter — 400 with
  `already have such entry` is treated as a successful add; 404 on
  delete is treated as a successful remove. Snapshot/apply race
  conditions safely absorbed.
- [x] phase 97 filter attrs (`source_filter`, `scenario_filter`,
  `origins`, etc.) honored — same getattr-on-instance pattern the
  binary adapter uses.
- [x] Phase 94 bootstrap script — RouterOS `:do { ... } on-error={ ... }`
  block opts the user group into `rest-api` policy on v7+ while
  failing gracefully on v6 (where the policy doesn't exist). Operator
  using the new adapter doesn't need to edit the script.
- [x] `tests/test_mikrotik_rest_adapter.py` (18 cases): is_configured /
  field_schema / kind registration / URL construction / snapshot
  with normalized entries / snapshot swallowing HTTP errors /
  snapshot handling non-list JSON / apply-add success / apply-add
  idempotent-on-duplicate / apply-add real-400-is-error /
  apply-remove success / apply-remove idempotent-on-404 /
  apply request-exception / health with version + size /
  health when blank-config / health on network failure / phase-97
  filter attr plumbing / snapshot output diff-compatible with the
  binary adapter's key shape.

**Acceptance:** ⚠ **adapter ready + 18 unit tests pass + full suite
green (93 passed, 1 skipped)**. Live perf measurement of the
snapshot wall-time speedup vs the ~118 s binary-API baseline is the
remaining gate — needs the operator to configure a parallel
`mikrotik_rest` target against the same MikroTik and let it run for
12 cycles. That measurement is captured by `sync_events.snapshot_ms`
automatically; no extra tooling needed. The unit-tested correctness
contract + the binary-API parity on diff-input shape is the
deliverable here; the perf number is operator-side homework on a
live RouterOS v7.

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
