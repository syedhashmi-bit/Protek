# CLAUDE.md

## Session Start

Always read `CONTEXT.md`, `SKILL.md`, and `MEMORY.md` at the start of every session before making any changes. `SKILL.md` is the domain primer — without it you will misuse the CrowdSec LAPI and the RouterOS address-list semantics.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

Protek — a self-hosted **CrowdSec → MikroTik bouncer** with a NOC-style dashboard on top. It pulls active decisions from one or more CrowdSec LAPIs and reconciles them into a MikroTik RouterOS `address-list` so the router drops banned traffic at the WAN edge. Built in Python/Flask, deployed on a Ubuntu VPS via gunicorn + nginx. Cross-box federation is a phase-2 add-on, not an MVP feature — but the architecture must be designed with federation in mind from day one.

## Deployment

> **⚠️ MIGRATED 2026-06-23 — Protek now runs on VPS B.** This section was originally
> written for VPS A (now pending decommission). Current truth + the full migration story
> is in **`docs/MIGRATION-VPS-B.md`** (and the 2026-06-23 entry in `MEMORY.md`). Key deltas
> from the bullets below: host is **VPS B** `5.78.147.36` (Ubuntu 26.04, Oregon); the venv
> is **uv-built 3.12** (B has no apt python3.12 — `uv` at `/root/.local/bin/uv`); the
> MikroTik is reached over the **public IP** `MT_HOST=45.248.49.159` (user `api` must be
> allowlisted at the RouterOS `/user` level); DNS + TLS already live on B.

- **Service**: `protek` (gunicorn systemd unit at `/etc/systemd/system/protek.service`, modelled after `vpn-dashboard` from pipsqueeze)
- **Project path**: `/var/www/Protek`
- **Gunicorn bind**: `127.0.0.1:8090` (other apps use 3000 atom, 5000 traverse, 8000 pipsqueeze, 8088 othoni)
- **VPS**: ~~this Ubuntu host~~ → **VPS B** (`5.78.147.36`, Ubuntu 26.04) — same box that runs CrowdSec locally
- **Python venv**: `/var/www/Protek/venv` (Python 3.12 — built with `uv`, not system python, on B)
- **Domain**: `protek.syedhashmi.trade` → nginx site `/etc/nginx/sites-available/protek`, enabled and reloaded
- **TLS**: run `sudo certbot --nginx -d protek.syedhashmi.trade` once the app is up; certbot will rewrite the nginx site to add 443 + HTTP→HTTPS redirect (same shape as pipsqueeze). *(Already issued on B, auto-renew.)*

## Service Commands

```bash
systemctl restart protek                            # restart after editing app.py, crowdsec.py, mikrotik.py
systemctl status protek                             # check running state
journalctl -u protek -n 50 --no-pager               # view recent errors
```

HTML templates take effect immediately (Jinja2 reloads on request) — no restart needed.

## Python Environment

```bash
source /var/www/Protek/venv/bin/activate
python app.py                                       # run locally for testing
pip install <package>                               # install inside venv
```

## CrowdSec — local LAPI

CrowdSec is already running on this VPS (systemd unit `crowdsec.service`).

```bash
cscli version                                       # confirm running version
cscli bouncers list                                 # list registered bouncers
cscli bouncers add protek                           # create a bouncer API key for Protek
cscli decisions list                                # current active bans
cscli alerts list                                   # underlying alerts (richer context than decisions)
```

LAPI endpoint: `http://127.0.0.1:8080` (auth header `X-Api-Key: <bouncer_key>`).
Prometheus metrics: `http://127.0.0.1:6060/metrics` (no auth on localhost).

**Never** commit the bouncer API key. It lives in `.env` only.

## Git

```bash
git remote                                          # origin → TBD
git push                                            # push to main (SSH key at ~/.ssh/id_ed25519)
```

## Stack

- **Backend**: Python 3.12, Flask, SQLite (`protek.db`, WAL mode)
- **CrowdSec client**: `crowdsec.py` — thin HTTP wrapper over LAPI, returns list of decisions
- **MikroTik**: `routeros_api` library → `mikrotik.py` (lift core connection logic from `/var/www/pipsqueeze/mikrotik_api.py`)
- **Frontend**: Jinja2 server-rendered HTML; JS only for live updates (dashboard polls every 5s), Chart.js sparklines, Leaflet.js world map
- **Auth**: Username/password + TOTP 2FA (pyotp), rate limiting, session timeout, IP whitelist
- **Notifications**: Discord webhook, SMTP email, Telegram bot — `notifications.py` (compatible with pipsqueeze's module shape)
- **Design**: Tactical dark NOC aesthetic — electric cyan `#00c8ff`, neon green `#00ff9d`, deep navy background, Rajdhani + Share Tech Mono fonts from Google Fonts. **Match pipsqueeze/traverse exactly** so the suite feels coherent.

## Architecture

### Key Files (target shape)

| File | Purpose |
|------|---------|
| `app.py` | Flask app, all routes, background reconcile thread |
| `crowdsec.py` | LAPI HTTP client — `get_decisions()`, `get_alerts()`, `add_decision()`, `delete_decision()` |
| `mikrotik.py` | RouterOS API wrapper — `connect`, `get_address_list`, `add_address`, `remove_address`, `bulk_sync` |
| `reconcile.py` | The diff engine — given (lapi_decisions, mt_address_list) → (to_add, to_remove). Pure function, fully testable. |
| `notifications.py` | Discord/Email/Telegram sender; no Flask dependency, safe to import from both routes and thread |
| `federation.py` | (phase 2) — fan-in adapter pool, one per remote CrowdSec source |
| `templates/login.html` | 2FA login page with rate limiting lockout display |
| `templates/dashboard.html` | NOC overview — live attack feed, scenarios firing, world map, KPIs |
| `templates/decisions.html` | Full decisions table — filter/sort/search, manual add/delete |
| `templates/alerts.html` | Alerts timeline — richer context per event (log line, scenario, source) |
| `templates/scenarios.html` | Scenarios firing over time, heatmap by hour |
| `templates/mikrotik.html` | Bouncer status — address-list size, sync lag, last push log, manual resync |
| `templates/federation.html` | (phase 2) — sources panel: per-source decision counts + last pull |
| `templates/security.html` | Login audit trail, locked IPs, IP whitelist info |
| `templates/notifications.html` | Discord/Email/Telegram alert channel settings |
| `templates/settings.html` | LAPI URL + key, sync interval, address-list name, dry-run toggle |
| `protek.db` | SQLite DB — **never read** (contains credentials hash + bouncer keys) |
| `.env` | All secrets — **never read** |
| `CONTEXT.md` | Architecture decisions, background, known quirks |
| `SKILL.md` | CrowdSec + RouterOS + bouncer protocol primer — read **first** every session |
| `MEMORY.md` | Running log of features built, bugs fixed, and pending work |

### Background Reconcile Thread

`_reconcile_loop()` runs every N seconds (default 10s, configurable):

1. **Pull**: fetch active decisions from local LAPI (`/v1/decisions?type=ban`)
2. **Pull** (phase 2): fetch decisions from every federated remote LAPI, merge by IP
3. **Snapshot**: fetch current MikroTik address-list (`/ip/firewall/address-list` filtered by `list=<configured-name>`)
4. **Diff**: pure function in `reconcile.py` → `(to_add, to_remove, unchanged)`
5. **Push**: batched add + remove against the address-list; **respect MikroTik API rate** (no more than ~200 ops per sync cycle, queue the rest)
6. **Record**: write a `sync_event` row with counts, duration_ms, and any errors
7. **Notify**: if added > threshold or errors > 0, fire notification

The `_known_decisions` and `_last_mt_snapshot` module-level dicts cache state across iterations to avoid full re-diff on every cycle.

### Decision Lifecycle Cache

The LAPI's stream endpoint (`/v1/decisions/stream`) returns `{new: [...], deleted: [...]}` — use it after the initial bootstrap. The first cycle uses the full `/v1/decisions` endpoint, subsequent cycles use stream for efficiency. This matches how official bouncers work; see `SKILL.md` for the protocol details.

### Dry-Run Mode

`DRY_RUN=true` in `.env` makes the reconcile loop log what it *would* do without touching MikroTik. Required for first deployment and for testing scenario changes safely. The dashboard must show a clearly visible "DRY RUN" badge in the topbar when enabled.

### Address-List Conventions

- Default list name: `crowdsec` (configurable via `MT_ADDRESS_LIST` env var)
- Each entry's `comment` field carries the decision metadata: `protek:<decision_id>:<scenario>` so we can round-trip ownership without touching entries Protek didn't create.
- **Never delete an address-list entry whose comment doesn't start with `protek:`** — the user may have other tooling writing to the same list.

### Security

- Rate limiting: `MAX_LOGIN_ATTEMPTS` failed attempts trigger lockout for `LOCKOUT_MINUTES`
- Session timeout: `SESSION_TIMEOUT_MIN` inactivity → auto-logout
- IP whitelist: `IP_WHITELIST` env var (comma-separated); blank = allow all
- All security events logged to `login_audit` table
- The bouncer API key is read-only against LAPI; Protek **does not need write access** to LAPI for MVP. Phase 2 (federation acting as a "machine") will need a separate machine credential.

### Pages & API Routes

| Route | Purpose |
|-------|---------|
| `/` | NOC dashboard — live feed, scenarios, KPIs, map |
| `/decisions` | Decisions table — filter, search, manual add/delete |
| `/alerts` | Alerts timeline with full context |
| `/scenarios` | Scenarios firing — heatmap, top-N |
| `/mikrotik` | Bouncer status, sync log, address-list inspector |
| `/federation` | (phase 2) Sources panel |
| `/security` | Login audit, locked IPs, IP whitelist |
| `/notifications` | Discord/Email/Telegram alert settings |
| `/settings` | Connection config + dry-run toggle |
| `/api/decisions` | JSON — current active decisions |
| `/api/alerts` | JSON — recent alerts (paginated) |
| `/api/sync/status` | JSON — last sync result, address-list size, lag |
| `/api/sync/run` | POST — force an immediate reconcile cycle |
| `/api/mt/health` | JSON — MikroTik API reachability |
| `/api/crowdsec/health` | JSON — LAPI reachability + version |
| `/api/sys` | JSON — CPU, RAM, disk, uptime (Protek host) |
| `/api/scenarios` | JSON — scenarios with counts over a time window |
| `/api/geo/<ip>` | JSON — cached geo lookup for map |

### Database Schema (initial)

- `decisions` — mirror of LAPI decisions we've seen (id, ip, scenario, origin, duration, created_at, expires_at, deleted_at)
- `alerts` — richer events from LAPI alerts endpoint (id, machine_id, scenario, source_ip, source_asn, source_country, events_count, created_at, raw_json)
- `sync_events` — every reconcile cycle (started_at, duration_ms, added, removed, unchanged, errors, source: "auto"|"manual")
- `mt_pushes` — per-entry push log (sync_event_id, ip, action: "add"|"remove", success, error)
- `geo_cache` — IP → (country, city, lat, lon, asn) with TTL; populated lazily from a free geo source
- `sources` — (phase 2) federated LAPI endpoints (name, url, api_key_ref, enabled, last_pull_at, last_pull_count)
- `notifications` — alert channel settings (one row: Discord/Email/Telegram config + per-event toggles)
- `login_attempts` — rate limiting records per IP
- `login_audit` — every login attempt with IP, username, result, reason
- `settings` — single-row key/value store for runtime-tunable knobs (sync interval, dry-run flag, etc.) — `.env` is source of truth for **secrets only**, `settings` is for **operational toggles**

**DB migrations**: new columns must be added to both the `CREATE TABLE` statement and the `init_db()` migration block (`ALTER TABLE ... ADD COLUMN` guarded by PRAGMA column check). Same rule as pipsqueeze.

## Environment Variables (.env)

```
# App — populated by scripts/setup_admin.py (never edit by hand)
SECRET_KEY=
APP_USERNAME=
APP_PASSWORD_HASH=                  # bcrypt, not plaintext
TOTP_SECRET=                        # base32, GAuth-compatible

# CrowdSec LAPI (this VPS)
CROWDSEC_LAPI_URL=http://127.0.0.1:8080
CROWDSEC_BOUNCER_KEY=          # generated via `cscli bouncers add protek`

# MikroTik API
MT_HOST=
MT_USERNAME=
MT_PASSWORD=
MT_PORT=8728
MT_ADDRESS_LIST=crowdsec

# Reconcile loop
SYNC_INTERVAL_SEC=10
DRY_RUN=true                   # default true until first deploy is verified

# Security (optional — have defaults)
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_MINUTES=15
SESSION_TIMEOUT_MIN=30
IP_WHITELIST=

# Notifications (optional)
DISCORD_WEBHOOK=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
SMTP_HOST=
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=
```

## Admin Credentials & Login Flow

- **Setup is one-shot**: `python scripts/setup_admin.py --username <name>` writes a fresh `SECRET_KEY`, bcrypt-hashed password, and TOTP secret into `.env` (chmod 0600). Prints plaintext password + TOTP otpauth URL + ASCII QR **once** — capture immediately, never logged or recoverable.
- **Password storage**: bcrypt only (rounds=12). The login route compares with `bcrypt.checkpw()`. There is no plaintext password anywhere — even the `.env.example` carries `APP_PASSWORD_HASH=` not `APP_PASSWORD=`.
- **TOTP is mandatory**, not optional. Login flow is: username + password → if both correct, present TOTP form → if TOTP `pyotp.TOTP(secret).verify(code, valid_window=1)` passes, set session. `valid_window=1` allows ±30s clock drift.
- **Rotation**: `scripts/setup_admin.py --password 'new'` rotates the password (keeps username + TOTP). `--rotate-totp-only` rotates just the TOTP secret. `--username new` renames the admin.
- **Session**: Flask session with `SECRET_KEY`, signed cookie, `Secure` + `HttpOnly` + `SameSite=Lax`. Timeout via `SESSION_TIMEOUT_MIN`.
- **Rate limit**: `MAX_LOGIN_ATTEMPTS` failed `(IP, username)` tuples in `LOCKOUT_MINUTES` → IP locked. Logged in `login_audit` with reason.
- **IP whitelist**: if `IP_WHITELIST` set, requests from outside that comma-separated list get a 403 before login even renders.
- **Issuer name in TOTP URI**: `Protek`. Shows up nicely in Google Authenticator / Authy / 1Password / Aegis.

## Coding Rules

- **Never read `.env` or `protek.db`** — live credentials and the bouncer API key live there.
- Always restart the service after editing `app.py`, `crowdsec.py`, `mikrotik.py`, `reconcile.py`, or `notifications.py`.
- MikroTik returns IDs as `id` or `.id` depending on API version — always use a `get_entry_id()` helper (lift from pipsqueeze's `get_peer_id`).
- **Idempotency is sacred.** Adding the same IP twice must not produce a duplicate address-list entry. Reconciliation is the diff, not the source of truth — never trust a stale local cache over MikroTik's actual state, refresh the snapshot on every cycle.
- **Comment ownership.** Only touch address-list entries whose comment starts with `protek:`. Entries written by hand or by other tools are off-limits.
- Use the LAPI **stream endpoint** (`/v1/decisions/stream`) for steady-state polling. Bootstrap from `/v1/decisions` once at start. See `SKILL.md`.
- Geo lookups must be cached aggressively (TTL ≥ 7 days). Cold lookups should never block the reconcile loop — they live in a separate worker.
- Keep the tactical dark NOC design language consistent — cyan `#00c8ff`, neon green `#00ff9d`, deep navy, Rajdhani + Share Tech Mono. Match pipsqueeze/traverse.
- `reconcile.py` must be a pure function `(decisions, current_list) -> (to_add, to_remove)`. No I/O. This is what we unit-test.
- All new DB columns go in both `CREATE TABLE` and the `init_db()` migration block.
- VSCode flags Jinja2 `{{ }}` inside `<script>` tags as JS errors — these are false positives, the code works fine.
- After any significant session, update `MEMORY.md` with what was changed.

## Federation (Phase 2 — design with this in mind)

Federation means: Protek pulls decisions from *multiple* CrowdSec LAPIs (your other VPSs, your home box), merges them, and pushes the union to MikroTik. The MVP must structure the LAPI client and reconcile loop so adding more sources is just iterating a list — not a rewrite.

Specifically:

- `crowdsec.py` must accept a `LAPIClient(url, api_key, name)` instance per call, not read from `.env` directly inside the methods.
- `reconcile.py` must accept a `list[decision]` from any number of sources, deduplicated by `(ip, scenario)`.
- The `decisions` table must have an `origin_source` column from day one so we never have to migrate it.

When phase 2 lands, all that changes is: a `sources` table is added, a settings page lets the user add remote LAPIs, and `_reconcile_loop` iterates `sources` instead of using only the local LAPI.
