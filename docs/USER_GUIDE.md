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

## Troubleshooting

See `docs/INSTALL.md` for the install + first-deploy story, and
`docs/TROUBLESHOOTING.md` for known issues.
