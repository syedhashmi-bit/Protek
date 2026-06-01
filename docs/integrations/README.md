# Integrating external systems into Protek

Protek accepts ban requests via `POST /api/external/decisions` from any
system that can speak HTTP + Bearer auth. This page shows the common
payload shapes — copy, paste, fill in your token, and you're banning.

## Get a token first

Dashboard → **API Tokens** (admin only) → "Add new token", scope = `write`.
Save the displayed token immediately (it's shown once). Future-you only
sees the prefix.

## Test your payload shape

Before sending real bans, hit `/api/external/introspect` with your
candidate JSON. Protek echoes back what it parsed and which field it
would use as the IP — without persisting anything.

```bash
curl -X POST https://protek.example.com/api/external/introspect \
  -H "Authorization: Bearer protek_xxxxxxxxxxxx" \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4", "scenario": "my-app/auth-failure", "duration": "2h"}'
```

If `detected_ip` matches what you expect and `parsed_keys` looks right —
swap the URL to `/api/external/decisions` and you're shipping bans.

## Canonical payload

```json
{
  "ip":       "1.2.3.4",
  "scope":    "Ip",
  "scenario": "my-app/auth-failure",
  "origin":   "my-app",
  "duration": "4h",
  "reason":   "5x login fail from this IP in 60s",
  "queue":    false
}
```

- `ip` — required. Either a single IP or a CIDR block (`scope=Range`).
- `scope` — optional. `Ip` (default) or `Range`.
- `scenario` — optional. Free-text label that shows up on `/decisions`.
- `origin` — optional. Used as `origin_source` so federation peers can filter.
- `duration` — optional. Go-style duration (`4h`, `30m`, `1d`). Default 4h.
- `reason` — optional. Free-text — shows in audit log.
- `queue` — if `true` and Protek is in SEMI-AUTO mode, the decision lands in `/approvals` instead of going live.

## Cookbook

### n8n

1. Drop an **HTTP Request** node:
   - Method: `POST`
   - URL: `https://protek.example.com/api/external/decisions`
   - Authentication: `Generic Credentials` → `Header Auth`
   - Header Name: `Authorization`, Value: `Bearer {{ $env.PROTEK_TOKEN }}`
   - Body Content Type: `JSON`
   - Body: `={ "ip": $json.ip, "scenario": "n8n/" + $json.alert_name, "duration": "8h" }`

### Zapier

Use the **Webhooks by Zapier → POST** action:
- URL: as above
- Payload type: `JSON`
- Data: map your trigger fields onto `ip`, `scenario`, `duration`
- Headers: `Authorization: Bearer protek_xxxxxxxxxxxx`

### Make (Integromat)

Module: **HTTP → Make a request**
- URL, method, headers same as Zapier
- Body type: `Raw` → Content type `application/json`
- Request content: render JSON with your variables

### Tines

Action: **HTTP Request**
- URL, method, headers same
- Payload: `{ "ip": "<<event.ip>>", "scenario": "tines/<<story.name>>", "duration": "4h" }`

### atom (suite integration)

If you've also got our `atom` security app on the same VPS — the simplest
path is `atom`'s own outbound webhook (Settings → Integrations → Protek).
It already knows the bearer-token + endpoint shape and ships findings as
bans automatically.

### Generic curl one-liner (for shell scripts / cron)

```bash
curl -fsS -X POST "https://protek.example.com/api/external/decisions" \
  -H "Authorization: Bearer $PROTEK_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"$1\",\"scenario\":\"$(basename $0)\",\"duration\":\"4h\"}"
```

## HMAC signing for inbound webhooks (optional, recommended)

When you create a webhook *subscriber* on Protek (outbound, `/webhooks`),
you get an HMAC secret. The *inverse* — verifying a payload Protek
*receives* — is also supported: include the same headers your subscriber
side does, and Protek validates them when the token's metadata has an
`hmac_secret` set.

```
X-Protek-Timestamp: 1716291847
X-Protek-Signature: <hex sha256-hmac of "timestamp.body" with token's hmac_secret>
```

Replay window: ±300s on the timestamp. Signature mismatch → 401.

## Rate limiting (phase 68)

Per-token rate limiting via the global token bucket. Default 600/min, 120
burst. Tunable in `/settings` → key `ratelimit.external.<token_name>.tokens_per_min`.
When exhausted, requests get `429 Too Many Requests` with `Retry-After`.
