<p align="center">
  <img width="160" height="160" alt="Protek" src="static/logo-256.png" />
</p>

<h1 align="center">Protek</h1>

<p align="center">
  Self-hosted CrowdSec → MikroTik (and 4 other firewalls) bouncer + NOC dashboard.<br/>
  Banishes attackers at the edge, not just at nginx.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-3.x-black?logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/CrowdSec-LAPI-orange" />
  <img src="https://img.shields.io/badge/MikroTik-RouterOS_API-red" />
  <img src="https://img.shields.io/badge/pfSense-supported-darkgreen" />
  <img src="https://img.shields.io/badge/OPNsense-supported-darkorange" />
  <img src="https://img.shields.io/badge/Cloudflare-supported-f38020" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" />
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#screenshots">Screenshots</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#multi-bouncer-support">Multi-bouncer</a> ·
  <a href="#federation">Federation</a> ·
  <a href="#resilience">Resilience</a> ·
  <a href="#documentation">Docs</a>
</p>

---

## What is Protek?

Protek is a [CrowdSec](https://crowdsec.net) **bouncer with a NOC-style dashboard**. It pulls active decisions from one or more CrowdSec LAPIs, reconciles them into one or more firewalls (MikroTik, pfSense, OPNsense, iptables/ipset, Cloudflare), and gives you a single pane of glass over who is being blocked, why, where they came from, and which downstream targets are in sync.

**The gap it fills:** CrowdSec ships first-party bouncers for nginx, iptables, Cloudflare, and a handful of others — but **not for MikroTik RouterOS**, and not as a coordinated multi-target hub. Protek is the polished, multi-bouncer, federation-capable version.

**End-to-end flow:**

```
       attackers
          │
          ▼
┌───────────────────────┐
│ CrowdSec agents       │  (one per VPS / box)
│  parsers + scenarios  │
└──────────┬────────────┘
           │ decisions
           ▼
┌───────────────────────┐
│   Protek (this app)   │  ← single pane of glass
│   • dedup + score     │
│   • whitelist / queue │
│   • multi-target push │
└─┬───────┬───────┬───┬─┘
  │       │       │   │
  ▼       ▼       ▼   ▼
MikroTik pfSense iptables Cloudflare …
(WAN     (perim. (host  (edge WAF)
 edge)    fwall)  fwall)
```

**Federation** (Arc 2, live): connect *N* CrowdSec LAPIs across your fleet — Protek pulls from each, dedupes, scores cross-source agreement, and pushes the union to every configured bouncer. No CAPI middleman; private, signed, over WireGuard if you want.

---

## Why this exists

If you run CrowdSec on a single VPS, its decisions only protect that one VPS. If you have a home network behind a MikroTik with port forwards, services on other VPSs, a pfSense lab, a Cloudflare-fronted site, or you'd just like one attacker to get banned across your entire infrastructure the moment they hit *any* of it — you need a bouncer that lives at the network edge **and** can fan out to every target you care about. Protek is the bridge.

---

## Status

**v1.1 shipped, v1.2 in flight.** Arcs 1–13 (phases 0–80) are complete: MVP,
federation, intelligence + enrichment, scenarios + rules, multi-bouncer
(MikroTik / pfSense / OPNsense / iptables / Cloudflare), observability,
operator QoL, extensibility, polish, intelligence v2, resilience, ecosystem,
and the 2.0-prep arc. Arcs 14 (Operator UX) and 15 (Production-grade ops)
are in progress — see [`ROADMAP.md`](ROADMAP.md) for the running plan and
[`MEMORY.md`](MEMORY.md) for the session-by-session log of what shipped
and what broke.

---

## Features

### Core bouncer
- **CrowdSec LAPI client** — bootstrap via `/v1/decisions`, steady-state via `/v1/decisions/stream` (cursor handled per-API-key by LAPI).
- **Pure-function reconcile engine** (`reconcile.py`) — diff `desired` vs `current` → `(to_add, to_remove, foreign_kept)`. 20+ unit tests cover ownership filtering, CIDR scope, IPv6 normalization, federation dedup, idempotency.
- **Comment-based ownership** — every Protek-written entry tagged `protek:<origin>:<scenario>:<lapi_id>`. **Never** touches address-list entries written by hand or other tools.
- **Dry-run by default** — first deployment is safe; flip to live from `/settings` UI without restart.
- **Self-healing** — re-fetches the address-list every cycle; survives manual edits, partial pushes, and target API hiccups.
- **Batch cap** per cycle (default 200) so a 30 000-entry community blocklist doesn't lock the API socket; surfaces progress.

### Multi-bouncer (Arc 5)
Adapters ship for five target kinds. Each implements the same `Bouncer` protocol (`health`, `snapshot`, `apply`); the reconciler iterates `bouncers.load_all_targets()` and gives every target the same desired set.

| Kind | Transport | Per-bouncer config |
|---|---|---|
| **MikroTik** (`mikrotik` + legacy `mikrotik_env`) | RouterOS API 8728/8729 | host, user, pass, list name, max_entries, origin filter |
| **pfSense** (`pfsense`) | `pfsense-pkg-RESTAPI` v2 | base URL, API key, alias name, verify TLS |
| **OPNsense** (`opnsense`) | built-in REST API | base URL, key:secret, alias name |
| **iptables / ipset** (`iptables_ipset`) | local shell-out | set name (v4 + v6 managed in parallel) |
| **Cloudflare** (`cloudflare`) | v4 API (Bearer) | account ID, token, list name, auto-create |

Each target has its own dry-run flag, batch cap, and per-stage timing. Multiple instances of the same kind are supported (e.g. two MikroTiks).

### Intelligence & enrichment (Arc 3, Arc 10)
- **CrowdSec CTI** — `cti.api.crowdsec.net/v2/smoke/<ip>` with 24h cache; reputation, classifications, behaviors.
- **ASN + Org** — Team Cymru DNS TXT (`origin.asn.cymru.com`) + ip-api batch.
- **GeoIP** — ip-api.com `/batch` (no key, 100 IPs/req); MaxMind GeoIP2 supported via extension.
- **WHOIS** — Team Cymru `whois.cymru.com:43` (verbose mode), 7d cache; mailto-abuse template.
- **rDNS** — dnspython with 2 s timeout, positive 24h / negative 1h cache.
- **AbuseIPDB · OTX · Spamhaus** — cross-provider consensus panel ("on 4/5 feeds"); optional report-back to AbuseIPDB.
- **Tor exit** detection — daily list pull, per-scenario "ignore Tor" whitelist option.
- **VPN/proxy detection** — proxycheck.io or ipinfo for high-score IPs.
- **Honeypot mode** — high-score attackers can be routed to a configurable honeypot rather than dropped; behavior fed back into reputation.
- **ML anomaly layer** — scikit-learn isolation forest on per-IP feature vectors; recommend-only, never auto-bans.

### Scenarios & rules (Arc 4)
- **`/scenarios/catalog`** — install/remove anything from the CrowdSec Hub via `cscli hub list -o json`; auto-reloads the agent.
- **YAML scenario editor** — `/scenarios/editor`, save-and-reload.
- **Whitelist UI** — per-IP / per-CIDR / per-ASN / per-country, time-bounded. Filter applies *before* the diff is computed (whitelisted IPs never reach any bouncer).
- **Approval queue** — `/approvals`. Optional SEMI-AUTO mode requires operator sign-off before bans propagate; rejected IPs auto-add to whitelist.
- **ASN-level auto-ban** — N IPs from same ASN in M hours → suggest /24 or whole-ASN escalation rule.
- **Reputation scoring** — composite (CTI × severity × cross-source × age-decay) → auto-ban / queue / monitor tiers, tunable per bouncer.

### Federation (Arc 2)
- **N CrowdSec sources** (`sources` table) — add via `/federation`, health-probe-on-save, per-source backoff (2^streak min, cap 30), pause-without-delete.
- **Decision union with dedup** by `(value, scope)`.
- **Cross-source agreement scoring** — `ip_sources` table tracks every (ip, source, last_seen); threshold setting requires N distinct sources before a ban propagates.
- **Topology + overlap matrix** — `/federation` page renders sources → PROTEK → targets as CSS topology + 4-level cyan-to-green overlap heatmap.
- **Source reputation** — per-source scorecard (total / unique / shared / redundancy %); auto-recommendations ("highly redundant — consider pausing").

### Observability (Arc 6)
- **Prometheus `/metrics`** — bearer or IP-allowlist auth. `active_decisions`, `mt_list_size`, `sync_lag_seconds`, `sync_duration_ms`, `scenarios_fired_total`, `push_errors_total`, `source_health`.
- **SIEM forward** — per-decision event push to syslog (RFC 5424), JSON-over-HTTP (Splunk HEC / generic), or Kafka. Backpressure-safe queue.
- **Audit log** — every operator action (settings change, manual decision, whitelist edit, scenario enable/disable) → searchable `/audit` page with diff, append-only at storage layer.
- **Per-stage sync timing** — `sync_events` carries `lapi_fetch_ms`, `snapshot_ms`, `diff_ms`, `push_ms`; `/perf` shows stacked-bar breakdown per cycle and slow-cycle traces.
- **SLO tracking** — `/perf` shows current vs target for sync lag, decision-to-ban latency, dashboard p95; burn-rate context.
- **Composite alerting** — "LAPI down ≥ 5 min", "MT unreachable ≥ 2 min", "sync lag > 5 min"; alert dedup, auto-resolve, planned-maintenance silencing.

### Resilience (Arc 11)
- **Off-box backup** — nightly `/admin/backup` export to S3-compatible storage (B2 / MinIO / AWS S3). Retention 30 daily + 12 monthly. Restore-test job decrypts and verifies integrity.
- **Litestream replication** — SQLite WAL streamed to a remote replica (S3 or SFTP-over-WireGuard). RPO < 2 s steady state. **Restore-to-latest currently blocked by a corrupt L2 LTX file from the 2026-05-25 disk-full incident — see [`MEMORY.md`](MEMORY.md) and `ROADMAP.md` phase 64 for the path forward (phase 87 speedup work pending).**
- **Self-monitoring (synthetic ban test)** — every 6 h, inject `192.0.2.250` (RFC 5737 TEST-NET-1), push directly via each live bouncer's `apply()`, verify presence in its snapshot, remove and verify absence. Catches the "phantom progress" failure where `apply()` returns OK but nothing landed. Verified live 2026-05-26 against MikroTik in 28.6 s.
- **WAL truncate timer** — `protek-wal-truncate.timer` every 5 min, learned the hard way (Litestream v0.5's continuous WAL reader breaks SQLite's auto-checkpoint; a one-off bug filled the disk).
- **DR runbook** — [`docs/DR-RUNBOOK.md`](docs/DR-RUNBOOK.md): every failure mode (DB corruption, MT down, CrowdSec hub down, Litestream broken) with explicit recovery steps; quarterly drill template.
- **Active-passive HA** — leader election via fcntl.flock extended to a network lock; failover ≤ 30 s.
- **Rate limiting + backpressure** — token bucket per upstream (LAPI, each bouncer, each webhook); `/perf` shows bucket states.

### Operator quality-of-life (Arc 7, Arc 9)
- **Mobile-responsive** at ≤ 480 px.
- **`protekctl` CLI** — same operations as the web UI (decisions ls/add/rm, sources ls/add/rm, sync run, allowlist mgmt). TSV + JSON output.
- **Bulk import/export** — encrypted config bundle (sources, settings, allowlists, scenarios, channels) → move to new VPS in one command.
- **Multi-admin** + **RBAC** (viewer / operator / admin).
- **`cmd-K` command palette** — global search across decisions, alerts, scenarios, attackers, audit log. Saved searches.
- **In-place edit** for any bouncer target — preserves last_ok_at and history across config changes; secret fields masked.
- **Bulk operations** on `/decisions` — multi-select, bulk delete / whitelist / extend-duration, confirmation modal with first-5 preview.

### Integration & extensibility (Arc 8, Arc 12)
- **Webhook outputs** — every decision event POSTs to configured webhook(s), HMAC-signed, retry with backoff, DLQ.
- **Webhook inputs** — `/api/external/decisions` accepts bans from external systems (atom, custom scripts) with API-token auth; optional approval queue.
- **REST API v1** — full OpenAPI spec at `/api/openapi.json`, scoped tokens (read / write / admin), expiry, last-used.
- **GraphQL** — `/api/graphql` alongside REST, GraphiQL explorer for admins.
- **Plugin SDK** — publish the `Bouncer` protocol as documented public interface; hot-load adapters from `~/.config/protek/adapters/*.py`; cookiecutter template for community adapters.
- **OAuth / SAML SSO** — OIDC providers + SAML 2.0 SP; per-domain restriction; fallback to local user table for break-glass.
- **Native packages** (`.deb` / `.rpm`) hosted on a GitHub-Pages APT/YUM repo.

### 2.0 preparation (Arc 13)
- **Postgres** path — additive `DATABASE_URL=postgresql://…`, schema mirrors SQLite, CI matrix tests both.
- **Sharding by decision origin** — one Protek instance per region / origin, aggregated read across shards.
- **Multi-region Terraform** — WG/Tailscale mesh between regions, leader election.
- **Threat intel publishing** — export Protek's own decisions as a signed public feed; opt-in/-out per scenario.

---

## Screenshots

> All screenshots are sanitized (IPs blurred, secrets masked).

### Dashboard — NOC overview
![dashboard](docs/screenshots/dashboard.png)

### Decisions table
![decisions](docs/screenshots/decisions.png)

### Alerts timeline
![alerts](docs/screenshots/alerts.png)

### Scenarios firing heatmap
![scenarios](docs/screenshots/scenarios.png)

### MikroTik bouncer status
![mikrotik](docs/screenshots/mikrotik.png)

### Multi-bouncer targets
![bouncers](docs/screenshots/bouncers.png)

### Federation peers
![peers](docs/screenshots/peers.png)

### Synthetic self-test
![synthetic](docs/screenshots/synthetic.png)

### Whitelist management
![whitelist](docs/screenshots/whitelist.png)

### Settings
![settings](docs/screenshots/settings.png)

### Notifications
![notifications](docs/screenshots/notifications.png)

### Security audit
![security](docs/screenshots/security.png)

### Off-box backup automation
![backup-automation](docs/screenshots/backup-automation.png)

### DR drill
![dr-drill](docs/screenshots/dr-drill.png)

### Threat intel publishing
![intel-publish](docs/screenshots/intel-publish.png)

### Login (TOTP)
![login](docs/screenshots/login.png)

---

## Quick start

> **Tested on Ubuntu 22.04 / 24.04.** See [`docs/INSTALL.md`](docs/INSTALL.md) for the long-form guide.

```bash
# 1. Clone + venv
git clone https://github.com/syedhashmi-bit/Protek.git /var/www/Protek
cd /var/www/Protek
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Bouncer key from CrowdSec (already running on this host)
sudo cscli bouncers add protek
# Copy the key into .env (next step) as CROWDSEC_BOUNCER_KEY=...

# 3. Bootstrap secrets — generates SECRET_KEY, bcrypt hash, TOTP secret
python scripts/setup_admin.py --username admin
# Captures plaintext password + TOTP otpauth URL + ASCII QR ONCE — store now,
# they are not recoverable later.

# 4. Edit .env with CrowdSec key, MikroTik creds (or skip — runs dry-run by default)
$EDITOR .env

# 5. systemd unit + nginx
sudo cp deploy/protek.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now protek

sudo cp deploy/nginx.conf /etc/nginx/sites-available/protek
sudo ln -s /etc/nginx/sites-available/protek /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 6. TLS
sudo certbot --nginx -d protek.example.com
```

First login: visit `https://protek.example.com`, enter username + password + TOTP. Protek starts in **dry-run** — it logs every reconcile decision but writes nothing to MikroTik. Verify the diff looks right at `/mikrotik`, then flip dry-run off from `/settings`.

---

## Configuration

`.env` carries **secrets and connection strings only** (read once at boot, never displayed in the UI). Runtime knobs (sync interval, batch cap, dry-run flag, address-list name, notification creds) live in the `settings` table and are editable from `/settings` without restart.

| Variable | Required | Purpose |
|---|---|---|
| `SECRET_KEY` | yes | Flask session signing (written by `setup_admin.py`) |
| `APP_USERNAME`, `APP_PASSWORD_HASH`, `TOTP_SECRET` | yes | Admin login (written by `setup_admin.py`) |
| `CROWDSEC_LAPI_URL` | yes | Default `http://127.0.0.1:8080` |
| `CROWDSEC_BOUNCER_KEY` | yes | From `cscli bouncers add protek` |
| `MT_HOST`, `MT_USERNAME`, `MT_PASSWORD` | for legacy MT | Single env-driven MikroTik target; multi-MT uses `/bouncers` UI instead |
| `MT_PORT`, `MT_USE_SSL`, `MT_ADDRESS_LIST` | no | Defaults: 8728, false, `crowdsec` |
| `DRY_RUN` | no | Boot default; `settings.dry_run` row overrides at runtime |
| `MAX_LOGIN_ATTEMPTS`, `LOCKOUT_MINUTES`, `SESSION_TIMEOUT_MIN`, `IP_WHITELIST` | no | Security knobs |
| `DISCORD_WEBHOOK`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SMTP_*` | no | Notification channels |
| `CROWDSEC_CTI_API_KEY`, `ABUSEIPDB_KEY`, `OTX_KEY`, `PROXYCHECK_KEY` | no | Intel providers |

See [`.env.example`](.env.example) for the full list with defaults.

---

## Operations

```bash
# Service control
systemctl restart protek                          # after editing app.py / crowdsec.py / mikrotik.py / etc.
systemctl status protek
journalctl -u protek -n 50 --no-pager

# Templates reload on each request — no restart needed for Jinja2 edits.

# Force an immediate reconcile cycle
curl -X POST https://protek.example.com/api/sync/run

# Inspect what would change (dry-run output)
curl -s https://protek.example.com/api/sync/status | jq .

# Health
curl -s https://protek.example.com/health | jq .       # 200 / 503 + issues list
```

Common workflows:

- **Flip dry-run off**: `/settings` → toggle → save. Poller picks it up on the next cycle (default 10 s).
- **Add a new bouncer**: `/bouncers/add` → pick kind → fill structured fields → health-probe-on-save → optionally promote to live.
- **Add a federated source**: `/federation/add` → URL + key → test-connection → save. Reconcile picks it up on the next cycle.
- **Whitelist an IP / CIDR / ASN / country**: `/whitelist` → add → applied *before* the diff (no propagation lag).
- **Investigate an attacker**: click any IP anywhere → `/attackers/<ip>` shows geo + ASN + WHOIS + CTI + rDNS + scenario timeline + sources-seen. "Refresh All" forces fresh lookups.

---

## Multi-bouncer support

Every target implements the same `Bouncer` protocol (`bouncers/__init__.py`). The reconciler gives every target the same desired set; each computes its own diff against its own snapshot and pushes its own delta.

| Target | Best for | Notes |
|---|---|---|
| **MikroTik RouterOS** | home / SOHO router, ISP edge, RouterBOARD lab | The flagship target. CIDR-aware address-list. Operator owns the consuming firewall rule. IPv6 currently has an adapter bug (rejected as "not a valid dns name") — IPv4 fully works. |
| **pfSense** | x86 / virtualized perimeter firewall | Uses `pfsense-pkg-RESTAPI` v2. PATCH whole alias array per cycle + `/api/v2/firewall/apply` on every push. |
| **OPNsense** | x86 / virtualized perimeter firewall | Built-in REST API, no plugin. Per-entry add/delete via `alias_util`. |
| **iptables + ipset** | local host firewall, Linux VMs at the edge | Two sets managed in parallel (`protek-bans` v4 + `protek-bans6` v6). Operator owns the consuming `--match-set` rule. Auto-ensures sets on first health check. |
| **Cloudflare WAF** | edge / CDN-fronted services | v4 API, Bearer auth. Auto-creates a Rules List if `auto_create_list=true`. Bulk append + bulk delete (1000 items/req). Operator writes the WAF Custom Rule `(ip.src in $protek_bans)` once. |

Mix and match — a typical homelab+production deploy might run MikroTik (home WAN edge), iptables (each VPS), and Cloudflare (public site) simultaneously. Each target is independently health-probed, dry-runnable, and rate-limited.

---

## Federation

Add a second CrowdSec LAPI from `/federation/add`. Protek will:

1. Bootstrap from `/v1/decisions?startup=true`, stream from `/v1/decisions/stream` thereafter.
2. Tag every decision with `origin_source=<source-name>` from day one.
3. Dedupe by `(value, scope)` in the reconciler — multiple sources reporting the same IP only push one entry.
4. Apply **cross-source agreement** if configured: a decision requires N distinct sources before it propagates (raises the bar for noisier feeds).
5. Surface per-source health, contribution counts, and pairwise overlap on `/federation`.

Phase-2 hardening: per-source exponential backoff (2^streak min, cap 30), edge-triggered down/recovery notifications, pause-without-delete toggle.

Transport-agnostic — talks to remote LAPIs over private IP / WireGuard / Tailscale / public TLS. There is no Protek-to-Protek protocol; Protek is the *consumer*, the remote machine just exposes its LAPI.

---

## Resilience

Production deploys are protected by three layered mechanisms:

1. **Off-box nightly backups** (Arc 11 phase 63) — encrypted bundle of the SQLite DB + config to any S3-compatible storage. Retention 30 daily + 12 monthly. A restore-test job decrypts and integrity-checks the latest bundle every night.

2. **Litestream WAL replication** (Arc 11 phase 64) — sub-2-second RPO. Replica can live on another VPS via SFTP-over-WireGuard (no third-party dependency) or in S3/B2. See [`docs/litestream/litestream-sftp.yml.example`](docs/litestream/litestream-sftp.yml.example) for the SFTP shape. **Current state:** RPO target met, RTO target gated on Litestream restore speedup (phase 87) and a corrupt L2 LTX file from a 2026-05-25 disk-full incident — see `ROADMAP.md` phase 64 for details.

3. **Synthetic self-test** (Arc 11 phase 66) — every 6 h, injects an RFC 5737 IP, pushes via each live bouncer's `apply()`, verifies it appears in the snapshot, then removes and re-verifies. Catches the "phantom progress" failure mode where `apply()` returns OK but nothing actually landed. Live-verified 2026-05-26 against MikroTik in 28.6 s.

DR runbook in [`docs/DR-RUNBOOK.md`](docs/DR-RUNBOOK.md) — every failure mode with explicit recovery steps. `/admin/dr-drill` runs documented drills against a sandbox DB and records pass/fail in the audit log; quarterly reminder fires if no successful drill in 90 days.

---

## Security

- **TOTP 2FA mandatory** — username + bcrypt password → TOTP code (Google Authenticator / Authy / 1Password / Aegis). Verified with `valid_window=1` (±30 s clock drift).
- **Rate limiting** — `MAX_LOGIN_ATTEMPTS` failed `(IP, username)` tuples in `LOCKOUT_MINUTES` → IP locked. Every attempt logged in `login_audit`.
- **IP whitelist** (optional) — `IP_WHITELIST` blocks pre-login from anywhere not in the list.
- **CSRF** — Flask-WTF on all POST forms; `X-CSRFToken` header for AJAX.
- **Secure cookies** — `Secure` + `HttpOnly` + `SameSite=Lax`; session timeout configurable.
- **Bouncer key is read-only** — Protek requires zero write access to LAPI for MVP. No way to leak write capability via the dashboard.
- **Append-only audit log** — every settings change, manual decision, whitelist edit, scenario enable/disable → searchable `/audit` page with before/after diff. Storage layer rejects UPDATE/DELETE on audit rows.
- **Multi-admin + RBAC** — viewer / operator / admin roles. Visible affordances hidden for insufficient role (no "click button that 403s").
- **OAuth / SAML SSO** — optional. Maps external group claims → Protek role. Fallback to local user table for break-glass.

---

## Stack

```
Backend:    Python 3.12 · Flask · SQLite (WAL mode, Litestream replicated)
CrowdSec:   LAPI HTTP client (X-Api-Key bouncer auth); /v1/decisions + /v1/decisions/stream
Bouncers:   routeros_api (MikroTik), requests (pfSense / OPNsense / Cloudflare), ipset shell-out
Frontend:   Jinja2 server-rendered HTML; Chart.js sparklines; Leaflet 1.9 + MarkerCluster for the
            world map; cyan/green NOC palette; Rajdhani + Share Tech Mono fonts (Google Fonts)
Auth:       bcrypt + pyotp TOTP, Flask sessions, rate limiting, optional IP whitelist
Notify:     Discord webhook · Telegram bot · SMTP MIME — all 8–10 s timeouts, SSRF guards
Resilience: Off-box backup (S3 / B2 / MinIO) + Litestream WAL replication + synthetic self-test
Deploy:     gunicorn + systemd + nginx; certbot for TLS. Matches the pipsqueeze/traverse pattern.
Tests:      pytest, 38+ unit tests; reconcile + synthetic covered without needing CrowdSec/MikroTik
```

---

## Documentation

| File | Purpose |
|---|---|
| [`ROADMAP.md`](ROADMAP.md) | Phased build plan (arcs 1–15), per-phase acceptance criteria |
| [`MEMORY.md`](MEMORY.md) | Running log of what shipped, what broke, what's pending |
| [`CONTEXT.md`](CONTEXT.md) | Architecture decisions and why |
| [`SKILL.md`](SKILL.md) | Domain primer — CrowdSec LAPI, bouncer model, RouterOS address-list mechanics |
| [`CLAUDE.md`](CLAUDE.md) | Instructions for Claude Code agents working in this repo |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Long-form install guide (Ubuntu 22.04 / 24.04) |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Day-to-day operator guide |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common failure modes + fixes |
| [`docs/DR-RUNBOOK.md`](docs/DR-RUNBOOK.md) | Disaster recovery — every failure mode, every recovery |
| [`docs/UI.md`](docs/UI.md) | UI conventions (palette, fonts, NOC aesthetic) |
| [`docs/perf-baseline.md`](docs/perf-baseline.md) | Performance baseline numbers |
| [`docs/postgres-migration.md`](docs/postgres-migration.md) | Path from SQLite to Postgres (Arc 13 phase 75) |
| [`docs/plugins/README.md`](docs/plugins/README.md) | Plugin SDK for community-contributed bouncer adapters |
| [`docs/integrations/README.md`](docs/integrations/README.md) | Cookbook for n8n / Zapier / Make / Tines / atom |
| [`docs/litestream/litestream-sftp.yml.example`](docs/litestream/litestream-sftp.yml.example) | Litestream SFTP-over-WireGuard config example |

---

## Contributing

Protek is single-operator self-hosted by design — there's no SaaS, no multi-tenant mode, no hosted version. But adapters, scenarios, integrations, and docs PRs are welcome.

For new bouncer adapters: use the plugin SDK (Arc 12 phase 69). A cookiecutter template + the `Bouncer` protocol are documented in [`docs/plugins/README.md`](docs/plugins/README.md). Drop your adapter in `~/.config/protek/adapters/` and it appears in `/bouncers` without forking.

For roadmap discussion: open an issue tagged `roadmap`. Arc 14 (Operator UX) and Arc 15 (Production-grade ops) are the current focus.

---

## License

MIT — see [`LICENSE`](LICENSE).
