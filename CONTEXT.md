# CONTEXT.md — Project Background & Architecture Decisions

## What Problem This Solves

The owner runs CrowdSec on this VPS and has a MikroTik router at the home/office edge. CrowdSec ships first-party bouncers for nginx, iptables, Cloudflare, and a handful of others — but **not** for MikroTik RouterOS. Community projects exist but are scripts, not products. Protek is the polished version, with a dashboard.

The end-to-end value: when CrowdSec on this VPS bans an attacker, that attacker should also get dropped at the WAN edge of the home/office network — blocking them from every service behind the router, not just the one CrowdSec was watching. Today, doing that means writing a glue script. Protek replaces the glue with a proper bouncer + UI.

Phase 2 extends this with **cross-box federation**: multiple CrowdSec instances across your fleet share decisions privately, Protek is the hub. The MVP only does *local LAPI → MikroTik*, but the architecture is laid out so federation is a small additive change, not a rewrite.

## Infrastructure

- **VPS** (this host): Ubuntu, runs CrowdSec (`crowdsec.service`) + Protek (`protek.service`). LAPI on `127.0.0.1:8080`.
- **MikroTik**: home/office router, RouterOS API on port 8728. Address-list name configurable, default `crowdsec`.
- **Other CrowdSec instances** (phase 2): on other VPSs, reachable from this host either over WireGuard, Tailscale, or public TLS. Each registers a bouncer credential for Protek.
- **Domain**: TBD, served behind nginx like the rest of the suite (atom, othoni, traverse, pipsqueeze).

## Architecture Decisions & Why

### Flask + SQLite (not Django, not Postgres)

Single-admin dashboard with low write rates. Even with a 10-second reconcile loop and a busy CrowdSec instance, writes are well under SQLite's WAL ceiling. Same stack as pipsqueeze/traverse — keeps the operator's mental model small across projects.

### Pull model, not LAPI subscriber

CrowdSec's LAPI offers two patterns for bouncers: pull (`GET /v1/decisions/stream` on a timer) or, for some integrations, full machine connections with event subscriptions. Bouncers are designed for the pull model and that's all we need. Pulling also makes phase-2 federation natural: each remote LAPI is just another pull source.

### Stream endpoint after bootstrap

The very first cycle uses `GET /v1/decisions?...` which returns *all* active decisions. From there, `GET /v1/decisions/stream` returns only `{new, deleted}` deltas. This is exactly how the first-party bouncers work and avoids re-diffing thousands of entries every loop on busy LAPIs.

### Reconcile as a pure function

`reconcile.py` is `(desired_state, current_state) -> (to_add, to_remove)`. No I/O. This is the only piece of logic that has to be *correct* — everything else is plumbing. Pure-function design makes it unit-testable without a MikroTik or a CrowdSec instance.

### Background thread (not Celery, not cron)

A single daemon thread polling every N seconds is the simplest viable solution for a single-server deployment. No Redis, no worker queue, no separate process to manage. Lifted directly from the pipsqueeze pattern.

### Comment-based ownership on the address-list

MikroTik address-lists are shared — the user may have other tooling writing to the same list. We tag every Protek-written entry with a comment that starts with `protek:`, and we **never** touch entries without that prefix. This is the only safe way to share a namespace without taking over the user's router.

### Dry-run mode default-on

First deployment defaults to `DRY_RUN=true`. The reconcile loop logs every add/remove it would do, but doesn't touch MikroTik. The dashboard shows a clear banner. The user verifies behavior, then flips the flag. This avoids the "Protek banned my own IP" / "Protek nuked an existing address-list" failure modes on day one.

### Geo lookups out-of-band

Geocoding an IP can take 500ms+ on a cold lookup. Doing it inside the reconcile loop would slow bans. Geo is a separate worker that drains a queue lazily; the dashboard renders without geo and fills in markers as they arrive. Cache TTL is 7 days minimum because attacker IPs don't move that often, and rate limits on free geo APIs are tight.

### Federation designed-in, not bolted-on

Even though MVP only talks to the local LAPI, the LAPI client takes a config object (`LAPIClient(url, key, name)`) instead of reading `.env` directly. The `decisions` table has an `origin_source` column from day one. When phase 2 lands, the change is: add a `sources` table + UI, iterate it in the reconcile loop. No schema migration on existing data.

### Single-page-app temptation — resisted

The other projects on this box (pipsqueeze, traverse, atom) use Jinja2 + small JS islands. Protek follows the same pattern. The NOC dashboard *looks* live (polling every 5s) but is just polling JSON endpoints into existing DOM. No build step, no framework, no client-side router.

### Why CrowdSec-only for now, not Suricata / fail2ban / etc.

CrowdSec is what's running on this box. Adding more event sources would dilute the focus before the core bouncer is solid. Phase 3+ could plug in additional sources (e.g., Pi-hole DNS-based block lists, atom's findings as a synthetic CrowdSec-shaped stream) — but only after federation is stable.

## Pages & Their Purpose

| Page | URL | Purpose |
|------|-----|---------|
| Login | `/login` | 2FA auth with rate limiting |
| Dashboard | `/` | NOC overview — live feed, scenarios, KPIs, world map |
| Decisions | `/decisions` | Full table, filter/search, manual add/delete |
| Alerts | `/alerts` | Underlying alerts with full event context |
| Scenarios | `/scenarios` | Scenarios firing — heatmap, top-N |
| MikroTik | `/mikrotik` | Bouncer status, sync log, address-list inspector |
| Federation | `/federation` | (phase 2) Sources panel — per-source decision counts |
| Security | `/security` | Login audit trail, locked IPs, whitelist |
| Notifications | `/notifications` | Discord/Email/Telegram alert settings |
| Settings | `/settings` | LAPI URL + key, MikroTik connection, sync interval, dry-run toggle |

## API Endpoints (JSON)

| Endpoint | Returns |
|----------|---------|
| `/api/decisions` | Current active decisions |
| `/api/alerts` | Recent alerts (paginated) |
| `/api/sync/status` | Last sync result, address-list size, lag |
| `/api/sync/run` (POST) | Force an immediate reconcile cycle |
| `/api/mt/health` | MikroTik API reachability |
| `/api/crowdsec/health` | LAPI reachability + version |
| `/api/sys` | CPU, RAM, disk, uptime (Protek host) |
| `/api/scenarios` | Scenarios with counts over a time window |
| `/api/geo/<ip>` | Cached geo lookup |

## Known Quirks (anticipated — to be confirmed as we build)

- MikroTik returns IDs as `id` or `.id` depending on API version — always use `get_entry_id()` helper.
- LAPI bouncer key permissions are read-only on `/v1/decisions` — that's by design. Writing decisions back to LAPI requires a *machine* credential, not a bouncer one. MVP doesn't need this; phase 2 might.
- The stream endpoint's "deleted" array references decisions by ID, but those IDs are only meaningful within a single LAPI. When we federate, IDs from different sources will collide — that's why our internal `decisions` table uses `(origin_source, lapi_id)` as the natural key, not `lapi_id` alone.
- CrowdSec community blocklist decisions show up with `origin: "lists:..."` — these are bulk, can be tens of thousands of entries. The MikroTik address-list can handle that, but the reconcile loop must batch adds (default 200/cycle) to avoid hammering the router.
- Last-handshake / state strings from RouterOS use a custom duration format (`1h2m30s`) — parsed with regex, same approach as pipsqueeze.
- VSCode flags Jinja2 `{{ }}` inside `<script>` tags as JS errors — false positives, code works fine.

## Naming

"Protek" — a play on *protect* with the same vibe as pipsqueeze/traverse/atom. Short, memorable, fits the suite's naming pattern. The directory is already named `Protek`.
