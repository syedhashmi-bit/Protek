# Protek — User Guide

> Self-hosted CrowdSec → MikroTik (and 4 other adapters) bouncer with a NOC-style dashboard.

## What it is

Protek is a **bouncer** in CrowdSec terminology: it reads the active-ban list (decisions)
from CrowdSec's local API and mirrors them into your enforcement target. The first-party
target is MikroTik RouterOS (no official bouncer exists today), with iptables/ipset,
Cloudflare, pfSense, and OPNsense as drop-in alternatives.

The dashboard adds:

- A NOC-style live feed (attack-as-it-happens), world map, scenario heatmap.
- An attacker-dossier page per IP (geo, ASN, WHOIS, rDNS, CrowdSec CTI reputation, behaviors).
- Federation — pull decisions from multiple CrowdSec instances, merge by IP.
- Whitelist + approval-queue safety rails.
- Per-decision SIEM forwarding (RFC 5424 syslog / JSON webhook).
- Composite alerting with debounce, dedup, auto-resolve, and silences.
- Operator audit log enforced append-only at the storage layer.
- Multi-admin + RBAC (viewer / operator / admin) + scoped API tokens.
- A REST API (`/api/v1/*`) and CLI client (`protekctl`).

## Daily use

Most days you just glance at the dashboard. Things to know:

| Page | When to look |
|---|---|
| `/` | "Am I being hit? From where?" Live feed updates every 5 seconds. |
| `/decisions` | Investigating a specific IP. Search/filter the active ban list. |
| `/alerts` | Reading the context behind a ban — log lines, ASN, scenario fired. |
| `/attackers/<ip>` | Full per-IP dossier. CTI reputation + behaviors + scenario timeline. |
| `/perf` | Did the last reconcile cycle take longer than usual? SLO compliance + burn rate. |
| `/alerts/rules` | What composite rules are currently firing or silenced? |
| `/siem` | Did all events ship to your SIEM? DLQ + replay. |
| `/webhooks` | Same question, for outbound webhook subscribers. |
| `/audit` | Who changed what, when. Append-only. |

## Common operations

### Whitelist your own IP (so you don't lock yourself out)

Two layers:

1. **Upstream (CrowdSec) — prevents the alert from even firing.**
   Edit `/etc/crowdsec/parsers/s02-enrich/whitelists.yaml` and add your home/admin IP under
   the `ip:` or `cidr:` blocks. Then `sudo systemctl reload crowdsec`.

2. **Protek whitelist — lets the alert fire but never pushes the IP to MT.**
   Use `/whitelist`. Supports `ip`, `cidr`, `asn`, and `country` kinds. Faster to manage
   from the UI; survives CrowdSec re-installs.

### Manually ban / unban

UI: `/decisions` → "Add manual decision" / row-level delete.

CLI:
```bash
protekctl decisions add 1.2.3.4 --reason "manual block" --duration 24h
protekctl decisions rm 1.2.3.4
```

cscli (writes directly to CrowdSec — Protek mirrors on next cycle):
```bash
sudo cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual"
sudo cscli decisions delete --ip 1.2.3.4
```

### Force an immediate reconcile cycle

UI: `/mikrotik` → "Force Sync Now".
CLI: `protekctl sync run`.
API: `POST /api/v1/sync/run` with a `write`-scope token.

### Add a second admin

`/admin/users` → fill the form → grab the one-shot TOTP secret immediately
(it's the only time it's shown). The new user can change role between viewer/operator/admin
at any time. User #1 (the env-anchored admin) can't be demoted or deleted.

### Generate an API token (for `protekctl` or a webhook)

`/admin/tokens` → name + scopes (`read`, `write`, `admin`; higher implies lower).
The plaintext token is shown ONCE. Store immediately. We only persist its sha256.

### Wire an external system to push bans

```bash
curl -X POST https://protek.yourdomain/api/external/decisions \
  -H "Authorization: Bearer pk_xxx" \
  -H "Content-Type: application/json" \
  -d '{"ip":"5.6.7.8","scope":"Ip","scenario":"my-tool/sql-probe","duration":"24h","reason":"manual"}'
```

Set `"queue": true` to require human approval before MT push (or set
`settings.approval_required=1` globally).

### Wire an outbound webhook (SIEM / Slack / custom)

`/webhooks` → name + URL + event mask (`*` for everything, or comma-separated
globs like `decision.*,auth.failure`). Capture the HMAC secret. Receiver
verifies as:

```python
expected = hmac.new(secret.encode(), f"{ts}.".encode() + raw_body, hashlib.sha256).hexdigest()
if hmac.compare_digest(expected, request.headers["X-Protek-Signature"].split("=",1)[1]):
    # signature valid
```

### Backup the config to another VPS

`/admin/backup` → enter a passphrase ≥ 12 chars → download the `.bin`.
On the new VPS: same page → upload the bundle → check "overwrite" if it's a
fresh install. Restores users, federation sources, whitelist, bouncer targets,
notification creds, webhook subscribers, API token metadata, alert silences.

The bundle is AES-256-GCM encrypted with scrypt(n=2^15) KDF. Lose the
passphrase = lose the bundle.

## Keyboard shortcuts

- `cmd-K` (or `ctrl-K` / `/`) — Command palette. Type any page name, action, or keyword.
- In the palette: `↑`/`↓` nav, `⏎` open, `esc` close.

## Notifications

Edit `/notifications`. Credentials for Discord webhook / Telegram bot+chat /
SMTP server can be pasted directly in the UI (secrets are masked + write-only;
leave the field blank on save to keep the current value). Per-event toggles
let you pick which channels fire for `new_ban`, `sync_error`, `lapi_down`, etc.

The composite alerting layer (`/alerts/rules`) also goes through the same
channels. Silences support glob patterns (`mt_*` mutes every MT-related rule)
with an expiry.

## RBAC quick reference

| Role     | Can | Cannot |
|----------|-----|--------|
| viewer   | Browse everything | Any write action |
| operator | Everything below + writes | Manage users, tokens, backups |
| admin    | All of the above | (the env-anchored admin is always admin) |

The role pill in the topbar shows the current session's role. The Admin
section of the sidebar is hidden for non-admins.

## Intelligence v2 (Arc 10 features)

### ASN escalation queue (`/asn-escalations`)
When 10+ distinct IPs from the same ASN get banned within 24h, the detector
queues a suggestion. Approve to mirror an AS-scope decision (operator
typically converts this to a real `cscli decisions add --range <prefix>` rule
for each of the ASN's BGP prefixes); reject to suppress for 48h.
Thresholds tunable via settings (`asn_detector.min_ips`,
`asn_detector.window_hours`, `asn_detector.cooldown_hours`).

### Reputation scoring
Every active IP gets a 0–100 composite score (CTI × scenario severity ×
cross-source agreement × age × CTI behaviors). Surfaces on
`/attackers/<ip>` as a colored tier pill (auto / queue / monitor).
Per-bouncer filter: add `"min_reputation": 50` to a bouncer's
`config_json` to push only IPs scoring ≥ 50 — perfect for CF's 10k cap.
Tunable thresholds: `reputation.auto_threshold` (default 80),
`reputation.queue_threshold` (default 50).

### Intel providers
Five providers in `intel_providers.py`, all optional + gated on their env
key. AbuseIPDB and proxycheck.io need keys (`ABUSEIPDB_API_KEY`,
`PROXYCHECK_API_KEY`); OTX, Spamhaus DROP/EDROP, and Tor exit list need
none. Refreshed daily (no-op until 20h since last). Matching IPs get
tagged in `ip_tags` — surface on `/attackers/<ip>` as colored badges.

### Honeypot routing
Opt-in: set `honeypot.enabled=1` in the settings table. Then every ~2 min
the poller tags qualifying high-reputation IPs as `honeypot-bound`.
A CF Worker / nginx auth_request / etc. polls
`GET /api/v1/honeypot/targets` (token: read) and decides what to do
with them (redirect to operator's honeypot, slow-walk, etc.). Operator's
honeypot reports back via `POST /api/external/honeypot/callback`
(token: write) → tags the IP `honeypot-confirmed`.

### ML anomaly layer
`GET /api/v1/ml/anomalies?n=50` returns the top-N anomalous IPs from an
Isolation Forest trained on per-IP feature vectors (scenario count,
source count, lifetime, recent hits, CTI score, ASN size, CAPI vs local
binary). Recommend-only — never auto-bans. Useful for reviewing "what
weird IPs did CrowdSec miss?" once a week.

## Troubleshooting

See `docs/INSTALL.md` for the install + first-deploy story, and
`docs/TROUBLESHOOTING.md` for known issues.
