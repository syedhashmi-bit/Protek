# MEMORY.md — Running Log

Append-only journal of what was built, fixed, and what's pending. Update at the end of every significant session. Newest entries on top.

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
