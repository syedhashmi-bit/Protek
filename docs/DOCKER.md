# Protek on Docker

Arc 16 phase 95 — `docker compose up -d` to a logged-in dashboard
on a fresh VPS, no manual nginx / certbot / systemd dance.

The bare-metal install (via `install.sh` + `scripts/setup_admin.py` +
systemd + nginx) is still fully supported and is what runs the
primary VPS. Docker is the option-B path for new operators who would
rather ship containers.

## Quickstart — fresh host

Prerequisites: `docker` ≥ 24, `docker compose` v2 (bundled with
recent Docker installs), and a DNS record pointing your chosen
domain at the host.

```bash
# 1. Clone the repo into any directory (no /var/www required).
git clone https://github.com/syedhashmi-bit/Protek.git
cd Protek

# 2. Set your domain. Caddy uses it for Let's Encrypt issuance.
echo "PROTEK_DOMAIN=protek.example.com" > .env

# 3. Build + start the stack.
docker compose up -d --build

# 4. First-run admin setup — captures one-shot password + TOTP URI.
#    (Pipe the output to a notes app or screenshot it; it never reprints.)
docker compose exec protek python scripts/setup_admin.py --username admin

# 5. Visit https://protek.example.com/ and log in.
```

Caddy auto-issues a Let's Encrypt cert on the first HTTPS request.
For local dev (`PROTEK_DOMAIN=localhost`), Caddy serves a self-signed
internal cert instead — your browser will warn but the login flow
works.

## What's running

| Service | Container | Image | Purpose |
|---------|-----------|-------|---------|
| `protek` | `protek` | Built from `Dockerfile` | Flask app + reconcile thread |
| `caddy` | `protek-caddy` | `caddy:2-alpine` | TLS termination + reverse proxy |
| `litestream` | `protek-litestream` | `litestream/litestream:0.5` | WAL replication (opt-in) |

The `litestream` service is gated behind the `replicate` Docker Compose
profile so it doesn't start by default:

```bash
# Enable Litestream replication
docker compose --profile replicate up -d
```

Drop your `litestream.yml` into the `protek_data` volume before the
sidecar starts. See `docs/litestream/litestream-sftp.yml.example` for
a starter config keyed to an SFTP replica over WireGuard (matches the
shape from phase 64).

## State lives on one volume

Everything Protek persists — `protek.db`, the Litestream local LTX
stage, the operator's `.env` if they keep it there — lives in a single
named volume `protek_data`. Back up that one volume; you've backed up
Protek.

```bash
# Snapshot the volume to a tarball on the host
docker run --rm -v protek_data:/data -v $PWD:/backup alpine \
    tar czf /backup/protek-backup-$(date +%F).tgz -C /data .

# Restore
docker run --rm -v protek_data:/data -v $PWD:/backup alpine \
    tar xzf /backup/protek-backup-2026-05-28.tgz -C /data
```

The `backup.py` automation (phase 63) is still available inside the
container and writes to the same volume — they're complementary, not
duplicate.

## Migrating from bare-metal

```bash
# On the bare-metal host
sudo systemctl stop protek litestream
sudo tar czf /tmp/protek-state.tgz -C /var/www/Protek protek.db .env
scp /tmp/protek-state.tgz docker-host:/tmp/

# On the docker host
cd Protek                               # repo root
docker compose up -d --build            # creates the volume
docker compose stop protek              # quiesce for the restore
docker run --rm -v protek_data:/data -v /tmp:/src alpine \
    tar xzf /src/protek-state.tgz -C /data
docker compose start protek
```

The DB schema is shared — bare-metal and container builds run the
same migrations. The `PROTEK_DB_PATH` env var in `compose.yml` points
at `/data/protek.db` so the existing-bare-metal file works in place
without rename.

## Operating

```bash
# Live logs (Protek + Caddy + Litestream interleaved)
docker compose logs -f

# Just Protek
docker compose logs -f protek

# Drop into the container (for the rare manual sqlite poke)
docker compose exec protek bash

# Reload Caddy after editing the Caddyfile (no full restart)
docker compose exec caddy caddy reload --config /etc/caddy/Caddyfile

# Restart Protek without touching Caddy / Litestream
docker compose restart protek

# Tear down — keeps the volume + cert state
docker compose down

# Tear down + delete state (DESTRUCTIVE — full wipe)
docker compose down -v
```

## Multi-architecture

The `python:3.12-slim` base ships for both `linux/amd64` and
`linux/arm64`. The same `compose.yml` runs on:

- Hetzner CAX21 / CAX11 (arm64)
- AWS Graviton (arm64)
- Raspberry Pi 5 / 4 (arm64)
- Any x86 VPS (amd64)

No `--platform` flag needed unless you're cross-building from a
different arch.

## CrowdSec placement

CrowdSec **doesn't run in this compose file** because the typical
deployment runs it on the host parsing host logs (nginx access,
auth, syslog). Two options:

- **Host-side CrowdSec (recommended)**: install via the official APT
  repo on the host. Add `extra_hosts: ["host.docker.internal:host-gateway"]`
  to the `protek` service and set `CROWDSEC_LAPI_URL=http://host.docker.internal:8080`
  in `.env`.
- **Container-side CrowdSec**: add `crowdsec` as another service in
  `compose.yml`. Bind-mount `/var/log` from the host into the
  container so it can parse the right logs. Out of scope for this
  template — see the upstream `crowdsecurity/crowdsec` image docs.

## Limitations vs the bare-metal install

- **Service control via systemd doesn't apply.** `systemctl restart
  protek` becomes `docker compose restart protek`.
- **The WAL truncate timer from phase 64 follow-up (`protek-wal-truncate.timer`)
  is a host systemd timer.** Inside Docker, the same logic must run
  inside the container — the `poller.py` PASSIVE checkpoint every
  6 cycles still works, but the full TRUNCATE-with-stop dance does
  not. For Docker deployments with Litestream enabled, this is a
  known follow-up — track it as a phase 95 second-iteration item.
- **Phase 92's `litestream-fast-restore.sh`** assumes shell + SFTP on
  the host. Run it from outside the container (the volume is
  bind-mountable).
