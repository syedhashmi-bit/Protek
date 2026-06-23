# Migration: Protek moved from VPS A → VPS B (2026-06-23)

> **Read this if you are a future Claude session.** Protek's production host changed.
> The old `CLAUDE.md`/`CONTEXT.md` prose describing "this VPS" was written for VPS A.
> As of 2026-06-23 **Protek runs on VPS B**. VPS A is pending decommission.

## Why

Operator is retiring **VPS A** (the original Germany/Hetzner host that was the WireGuard
hub + the box Protek/CrowdSec ran on). Protek was relocated to **VPS B** so A can be
destroyed. This inverts the old phase-2 federation story (B used to be a *remote source*;
B is now the *primary and only* host).

## New topology (current truth)

- **Host**: VPS B — Hetzner US/Oregon, hostname `ubuntu-2gb-hil-1`, **Ubuntu 26.04**.
  - Public IPv4 `5.78.147.36`, public IPv6 `2a01:4ff:1f0:3eae::1`.
  - Has its **own WireGuard hub `wg1` = `10.9.0.1/24`** (independent of A's old wg0).
  - Still has a leftover wg0 client iface `10.8.0.5/32` that dies with A.
- **Python**: B's apt only ships **3.14**; there is **no `python3.12`**. The venv is built
  with **`uv`** (`uv python install 3.12`; uv at `/root/.local/bin/uv`). Do **not** assume
  a system python3.12 — `/var/www/Protek/venv` is the uv-built 3.12.13.
- **CrowdSec LAPI**: local, bound to **`127.0.0.1:8080`** (rebound from the old federation
  bind `10.8.0.5:8080`; the `crowdsec.service.d/wg-dep.conf` wg0 boot-dep drop-in was
  removed). `CROWDSEC_LAPI_URL=http://127.0.0.1:8080`, bouncer `protek-local`.
- **MikroTik**: reached over the **public IP**, NOT a tunnel.
  `MT_HOST=45.248.49.159`, `MT_PORT=8728`, user `api`, no SSL. Router is RouterOS
  **7.23**, name `syed-home`, address-list `crowdsec`.
- **DNS**: `protek.syedhashmi.trade` → B (A `5.78.147.36` + AAAA `2a01:4ff:1f0:3eae::1`,
  Cloudflare **grey-cloud / DNS-only**). TLS via `certbot --nginx` (auto-renew, exp 2026-09-21).
- **Federation**: collapsed to local-only. The old `vps-b` federated source is gone;
  Protek reads its own `127.0.0.1` CrowdSec.

## How B reaches the MikroTik (important gotcha)

A reached the MT fine; B was blocked at **three** independent layers — all had to be opened
with B's IP `5.78.147.36`:
1. firewall/service path to port 8728,
2. `/ip service` address restriction,
3. **`/user set [find name=api] address=…`** — the RouterOS *user* allowed-address. This
   was the last blocker; symptom was `not allowed to login from this address (9)` *after*
   TCP already connected. If a future box can TCP-connect but login fails with error (9),
   it's this user-level allowlist.

> `routeros_api` echoes `MT_PASSWORD` in plaintext in its login-failure error string —
> avoid logging those errors verbatim. **Rotate the MT `api` password** (pending).

## What was deliberately NOT migrated

- **Fresh DB on B** — A's 3.7 GB `protek.db` was *not* copied. Config/secrets came via the
  `.env` (scp'd from A, then patched). Live decisions re-bootstrap from CrowdSec.
- **A's CrowdSec decisions** — turned out to be a no-op: A had **0 active local-origin**
  bans; its 48k were CAPI + FireHOL lists (ephemeral, self-regenerating). No
  `cscli decisions import` was done. The durable item was the **blocklist subscription**,
  handled by enrolling B in the CrowdSec console and subscribing the FireHOL lists.

## Cutover outcome

A's `protek` stopped+disabled; B flipped `DRY_RUN=false`; `/health` ok. B is the sole
MikroTik writer. One-time convergence drains A's ~43k stale `protek:` entries at the
documented 200-ops/cycle cap (do NOT raise above ~200 — CLAUDE.md rate limit; a bump was
correctly blocked).

## STILL PENDING before VPS A can be destroyed (separate session)

- **Migrate atom** — `atom.syedhashmi.trade`, port 3000, still on A.
- **Migrate pipsqueeze** — `pipsqueeze.syedhashmi.trade`, port 8000 (nginx site is named
  `vpn-dashboard`, unit `vpn-dashboard.service`), still on A.
- **traverse** — already on B; just disable/remove A's stale `traverse.service`.
- **WG peers** — re-home A's wg0 personal peers `10.8.0.2/3/4` onto B's `wg1` via
  Traverse-on-B (briefly disconnects laptop/phone).
- **B cleanup** — delete the stale `protek-from-vps-a` bouncer from B's CrowdSec; rotate
  the MT `api` password (`MT_PASSWORD` in B's `.env`).
- **Blocklist backfill** — ~6.2k FireHOL IPs land on B on CrowdSec's community-tier
  delivery schedule (PAPI is 402 on community — that's normal; free lists come via CAPI).
