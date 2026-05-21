# SKILL.md — Domain Primer

> Read this **before** writing any CrowdSec or MikroTik code. The two systems each have a quirk-laden protocol that you will get wrong if you don't understand the model first.

This file documents what you need to know about:

1. The **CrowdSec bouncer model** — how decisions flow from LAPI to a bouncer
2. The **CrowdSec LAPI** — endpoints, auth, the stream protocol
3. The **MikroTik RouterOS API** — address-list semantics, batching, IDs
4. The **reconciliation pattern** — the diff algorithm and idempotency rules
5. **CrowdSec terminology** — words that sound alike but mean different things

---

## 1. The CrowdSec Bouncer Model

CrowdSec separates **detection** from **remediation**:

```
┌──────────────────────────────────────────────────────────────┐
│                          DETECTION                            │
│                                                              │
│  log files → parsers → scenarios → alerts → DECISIONS        │
│                                                  │           │
└──────────────────────────────────────────────────┼───────────┘
                                                   │
                                                   ▼
                                            LAPI (storage)
                                                   │
                                                   │ pull
                                                   ▼
┌──────────────────────────────────────────────────────────────┐
│                        REMEDIATION                            │
│                                                              │
│   BOUNCER ←── reads decisions ──── enforces ban on its       │
│              from LAPI                  protected resource    │
└──────────────────────────────────────────────────────────────┘
```

- **Agent** = the process that reads logs, runs scenarios, and writes decisions to LAPI. (`crowdsec.service`.)
- **LAPI** = the local API. It is the source of truth for decisions. (`http://127.0.0.1:8080`.)
- **Bouncer** = a remediation component. It does not detect anything; it only reads decisions and enforces them on whatever it's protecting (nginx, iptables, MikroTik, Cloudflare, …).
- **Console** = CrowdSec's optional cloud dashboard. Unrelated to bouncers.

**Protek is a bouncer.** It does not detect attacks. It reads decisions and writes them to a MikroTik address-list.

### What "enforcement" means for Protek

Protek's enforcement is **mirroring decisions into a MikroTik `address-list`**. The MikroTik firewall then has a drop rule like:

```
/ip firewall filter add chain=input  src-address-list=crowdsec action=drop comment="protek"
/ip firewall filter add chain=forward src-address-list=crowdsec action=drop comment="protek"
```

Protek does **not** write the firewall rules. Those are the operator's responsibility — Protek owns the list contents, the operator owns the rules that consume the list. The dashboard should remind the user of this in setup.

---

## 2. The CrowdSec LAPI

### Auth

Every bouncer has its own API key. Create one with:

```bash
sudo cscli bouncers add protek
# prints a key — store it in .env as CROWDSEC_BOUNCER_KEY
```

Send it as the `X-Api-Key` header on every request. **Bouncer keys are read-only** against decisions — they can't write decisions back. That's a separate credential type called a *machine* (`cscli machines add ...`). MVP only needs a bouncer key.

### The three endpoints we care about

#### `GET /v1/decisions`

Full snapshot. Use this **once at startup** to bootstrap. Returns an array of decisions:

```json
[
  {
    "id": 42,
    "origin": "crowdsec",
    "scenario": "crowdsecurity/http-probing",
    "type": "ban",
    "value": "1.2.3.4",
    "scope": "Ip",
    "duration": "3h59m12s",
    "until": "2026-05-20T18:42:01Z"
  }
]
```

Query params worth knowing:
- `type=ban` — filter to bans (there are also captcha/throttle types)
- `scope=Ip` — we care about IP scope; CrowdSec also has `Range`, `Country`, etc.
- `origins=...` — filter by origin (e.g. `crowdsec`, `lists:firehol_cruzit_web_attacks`, …)

#### `GET /v1/decisions/stream`

The **steady-state** endpoint. Returns deltas:

```json
{
  "new":     [ { /* same shape as above */ } ],
  "deleted": [ { "id": 17, "value": "5.6.7.8", "scope": "Ip" } ]
}
```

The trick: the first call to `/stream` with no prior state returns *all currently active decisions* in `new` and an empty `deleted`. Subsequent calls return only what changed since the previous call. The LAPI tracks the per-bouncer cursor by API key — you don't need to pass a cursor yourself.

**Therefore the bootstrap-vs-stream distinction is mostly an implementation detail of how *we* think about it; the LAPI handles cursoring transparently.** We still distinguish them in code because the bootstrap path also seeds our `decisions` table from scratch, while the stream path applies deltas.

Pass `?startup=true` on the *first* call after Protek (re)starts. This tells the LAPI to send the full active set rather than only changes since the last call (which it might have already discarded if Protek was down a long time).

#### `GET /v1/alerts`

Alerts are richer than decisions — they carry the **events** that triggered the scenario (log lines, source ASN, etc.). One alert may produce zero or many decisions depending on configuration. We mirror alerts into a local table so the dashboard can show context per banned IP. Alerts are read for the UI; **the bouncer never makes decisions from alerts**.

### Decision shapes worth noting

- **`origin`** tells you who created the decision:
  - `crowdsec` — generated by our local agent's scenarios
  - `cscli` — manually added by the operator via CLI
  - `lists:<name>` — from a community blocklist subscription
  - `console` — pushed from the CrowdSec Console
- **`scope`** is `Ip`, `Range`, `Country`, `AS`, etc. MVP supports `Ip` and `Range` (a CIDR block). MikroTik address-list handles both naturally.
- **`duration`** is a Go duration string (`"3h59m12s"`). `until` is the absolute expiry timestamp — prefer using `until` for "is this still active" math.
- **`id`** is a LAPI-local integer. Not globally unique across federated LAPIs. Store as `(origin_source, lapi_id)` from day one.

---

## 3. The MikroTik RouterOS API

### Connection

We use `routeros_api` (the same library as pipsqueeze). Default port 8728, plaintext API. (Port 8729 is API-SSL — operator's choice, we should support both via `MT_PORT` + a `MT_USE_SSL` flag.)

### Address-list operations

The address-list lives under `/ip/firewall/address-list`. Each entry has:

- `.id` — RouterOS internal handle (used for delete/update). **Critically:** the field is `.id` with a leading dot. Some client libraries strip it to `id`. Always use the `get_entry_id()` helper to read it regardless of which form is returned.
- `list` — the list name (we filter on `list=<MT_ADDRESS_LIST>`)
- `address` — IP or CIDR
- `comment` — free text. **We encode ownership here:** `protek:<lapi_origin>:<scenario>:<lapi_id>`
- `disabled` — boolean
- `creation-time`, `dynamic` — RouterOS metadata

### CRUD via the API

```python
res = api.get_resource("/ip/firewall/address-list")
res.add(list="crowdsec", address="1.2.3.4", comment="protek:crowdsec:http-probing:42")
res.remove(id="<.id>")
res.get(list="crowdsec")        # always filter by list
```

### Batching & rate

MikroTik will happily accept thousands of operations, but it processes them serially over the API socket. A community blocklist can have 30k+ entries; pushing them all at once on first run will take minutes and block the API socket from anything else.

Rules of thumb:

- **Batch cap per reconcile cycle**: 200 ops (configurable). Excess goes back into the queue for the next cycle.
- **Initial bootstrap**: special-case — push as fast as the router accepts, but log progress every 100 ops, and surface "initial sync in progress, X/Y done" on the dashboard.
- **Connection pool**: keep one long-lived connection in the reconcile thread, reconnect on `RouterOsApiError`.

### Address-list size considerations

A few thousand entries is fine. Tens of thousands works but slows firewall traversal slightly — RouterOS uses a hash structure so it's still O(1)-ish per packet, but rule-traversal overhead per address-list grows. If we ever ship 100k+ entries (e.g., aggressive community blocklists), warn the user in the UI.

### Comment ownership — the rule that must not be broken

When reconciling deletions, **only delete entries whose `comment` starts with `protek:`**. If the user (or another tool) has added entries to the same list manually, Protek must leave them alone. The reconcile diff must therefore filter the "current state" snapshot to *Protek-owned entries only* before computing `to_remove`.

```python
mt_owned = [e for e in mt_snapshot if (e.get("comment") or "").startswith("protek:")]
```

---

## 4. The Reconciliation Pattern

```python
def reconcile(desired_decisions, current_mt_entries):
    """
    Pure function. No I/O.

    desired_decisions: list of dicts from LAPI — what SHOULD be in the address-list
    current_mt_entries: list of dicts from MikroTik — what IS in the address-list,
                        already filtered to Protek-owned entries (comment starts with "protek:")

    Returns: (to_add, to_remove)
      to_add:    list of (address, comment) tuples to insert
      to_remove: list of mt .id values to delete
    """
    desired_by_addr = { d["value"]: d for d in desired_decisions }
    current_by_addr = { e["address"]: e for e in current_mt_entries }

    to_add = [
        (addr, build_comment(d))
        for addr, d in desired_by_addr.items()
        if addr not in current_by_addr
    ]
    to_remove = [
        e[".id"]
        for addr, e in current_by_addr.items()
        if addr not in desired_by_addr
    ]
    return to_add, to_remove
```

### Idempotency invariants

- Calling reconcile twice with the same inputs must produce the same outputs.
- Re-running a `to_add` against MikroTik that already has the address must be a no-op or silently succeed (MikroTik will return an error on duplicate — catch and ignore the specific "already exists" error).
- The reconcile loop *never trusts a cached MT snapshot*. It re-fetches the address-list on every cycle. (Cheap — a few KB.) This is what makes it self-healing if someone edits the address-list out from under us.

### Failure modes & recovery

- **LAPI down**: skip the cycle, log, retry next interval. Don't touch MikroTik.
- **MikroTik down**: skip the cycle, log, retry. Decisions queue up locally; when MT comes back, the next reconcile catches up via the same diff.
- **Partial push success**: log per-op success/failure in `mt_pushes`. The next reconcile will retry whatever didn't land.
- **Clock skew**: never required — we use the LAPI's `until` timestamp and trust whatever LAPI thinks is currently active.

---

## 5. CrowdSec Terminology Cheat Sheet

| Term | What it means |
|------|---------------|
| **Agent** | The CrowdSec daemon that detects (parses logs, runs scenarios) |
| **LAPI** | Local API — stores decisions, machines, bouncers; lives in the agent process by default |
| **Bouncer** | Remediation component (this project) — *reads* decisions, enforces them |
| **Machine** | A credential type for things that *write* decisions to LAPI (agents themselves, or another agent in a multi-LAPI setup). Not us. |
| **Decision** | A single ban/captcha/throttle for a target (IP, range, country). What we sync to MikroTik. |
| **Alert** | The richer event that produced one or more decisions. Carries the log lines / context. |
| **Scenario** | A YAML rule that turns parsed events into alerts (e.g. "10 nginx 403s from one IP in 60s") |
| **Parser** | A YAML rule that turns raw log lines into structured events |
| **Collection** | A bundle of parsers + scenarios for a given service (the "crowdsecurity/nginx" collection, etc.) |
| **Origin** | Where a decision came from: `crowdsec` (local agent), `cscli` (manual), `lists:...` (community blocklist), `console` (CrowdSec cloud) |
| **Scope** | What kind of target: `Ip`, `Range`, `Country`, `AS`, etc. |
| **CTI** | CrowdSec's Threat Intelligence — separate cloud API for IP reputation lookup. Optional, has a free tier. |
| **Console** | CrowdSec's cloud dashboard. Unrelated to bouncers, unrelated to Protek's dashboard. |
| **Hub** | The community repository of parsers, scenarios, and collections. `cscli hub list` / `cscli collections install ...` |

---

## 6. Useful commands while developing

```bash
# Create the bouncer key (do this once)
sudo cscli bouncers add protek

# Confirm the bouncer is registered after Protek starts pulling
cscli bouncers list

# Add a test decision manually (good for testing the reconcile loop)
sudo cscli decisions add --ip 198.51.100.1 --reason "test" --duration 10m

# Remove that test
sudo cscli decisions delete --ip 198.51.100.1

# See what's currently banned
cscli decisions list

# See the alert behind a decision
cscli alerts list
cscli alerts inspect <id>

# Check what scenarios fired in the last hour
cscli metrics

# Test the LAPI directly
curl -H "X-Api-Key: $KEY" http://127.0.0.1:8080/v1/decisions
curl -H "X-Api-Key: $KEY" "http://127.0.0.1:8080/v1/decisions/stream?startup=true"
```

```bash
# MikroTik — peek at the address-list (via API, from the VPS)
# Easier during dev: SSH or Winbox to the router
/ip firewall address-list print where list=crowdsec
/ip firewall address-list remove [find list=crowdsec comment~"^protek:"]   # nuke for testing
```

---

## 7. Things that will trip you up

- **`.id` vs `id`** in routeros_api responses — always use the helper.
- **Stream cursor is per-API-key** — if you test with two different keys, each maintains its own cursor; don't confuse the two.
- **`?startup=true` is critical after a restart** — otherwise the LAPI assumes you're caught up and you'll miss any decisions that happened during your downtime.
- **Decision `until` is UTC** — MikroTik doesn't care about expiry; we drive expiry through reconcile (decision falls out of `desired_decisions` → MT entry gets removed on next diff). Do NOT set the MT entry's own timeout — that would have RouterOS expire it independently and we'd get drift.
- **CIDR scope vs IP scope** — both are valid `address` values for the MT address-list. Don't try to expand a /24 into 256 individual entries; let MikroTik handle the range natively.
- **Community blocklists are huge** — first sync after subscribing to one can be 30k+ adds. Batch, surface progress, don't crash the reconcile thread.
- **Don't pollute the address-list** during testing. Use a dedicated list name like `protek-dev` and override via `MT_ADDRESS_LIST` so you can `address-list remove [find list=protek-dev]` to nuke without touching production.
