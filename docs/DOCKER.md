# Protek on Docker

Arc 16 phase 95 — `docker compose up -d` to a logged-in dashboard
on a fresh VPS, no manual nginx / certbot / systemd dance.

The bare-metal install (via `install.sh` + `scripts/setup_admin.py` +
systemd + nginx) is still fully supported and is what runs the
primary VPS. Docker is the option-B path for new operators who would
rather ship containers.

## Quickstart — fresh host

Prerequisites: `docker` ≥ 24, `docker compose` v2 (bundled with
recent Docker installs), a DNS record pointing your chosen domain at
the host, and CrowdSec running on the host with its LAPI reachable
from containers (see [CrowdSec placement](#crowdsec-placement) — do
that first).

```bash
# 1. Clone the repo into any directory (no /var/www required).
git clone https://github.com/syedhashmi-bit/Protek.git
cd Protek

# 2. Your settings go in ./.env. Caddy uses PROTEK_DOMAIN for Let's Encrypt.
echo "PROTEK_DOMAIN=protek.example.com" > .env
echo "CROWDSEC_BOUNCER_KEY=$(sudo cscli bouncers add protek -o raw)" >> .env
# Add MT_HOST / MT_USERNAME / MT_PASSWORD here too, or leave them out and
# Protek runs in dry-run.
chmod 600 .env

# 3. Build the image.
docker compose build

# 4. First-run admin setup — captures one-shot password + TOTP URI.
#    (Screenshot it or paste it into a password manager; it never reprints.)
#    Must run before `up`: Protek refuses to start without the SECRET_KEY
#    this writes. It lands in /data/.env on the volume, so it survives
#    rebuilds.
docker compose run --rm protek python scripts/setup_admin.py --username admin

# 5. Start the stack, then visit https://protek.example.com/ and log in.
docker compose up -d
```

There are two `.env` files, on purpose: **`./.env`** next to
`compose.yml` is yours to edit (domain, CrowdSec key, MikroTik
credentials, Google sign-in); **`/data/.env`** on the volume holds the
generated secrets and is written only by `setup_admin.py`. When a key
is in both, `./.env` wins. After editing `./.env`, run
`docker compose up -d` to recreate the container with the new values.

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
stage, and the generated secrets in `/data/.env` — lives in a single
named volume, `protek_data`. Back up that one volume (plus your
`./.env`); you've backed up Protek.

Compose prefixes the volume with the project name (the repo
directory, so usually `protek_protek_data`). The commands below go
through `docker compose run`, which resolves the right volume for you.

```bash
# Snapshot the volume to a tarball on the host
docker compose run --rm --no-deps --user root -v "$PWD":/backup protek \
    tar czf /backup/protek-backup-$(date +%F).tgz -C /data .

# Restore (stop Protek first; the chown keeps the files writable by the
# container's non-root user)
docker compose stop protek
docker compose run --rm --no-deps --user root -v "$PWD":/backup protek \
    sh -c 'tar xzf /backup/protek-backup-2026-05-28.tgz -C /data && chown -R protek:protek /data'
docker compose start protek
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
echo "PROTEK_DOMAIN=protek.example.com" > .env
docker compose build
docker compose run --rm --no-deps --user root -v /tmp:/src protek \
    sh -c 'tar xzf /src/protek-state.tgz -C /data && chown -R protek:protek /data'
docker compose up -d
```

The DB schema is shared — bare-metal and container builds run the
same migrations. `PROTEK_DB_PATH` and `PROTEK_ENV_FILE` in
`compose.yml` point at `/data/protek.db` and `/data/.env`, so the
bare-metal files work in place without rename. The bare-metal `.env`'s
`CROWDSEC_LAPI_URL=http://127.0.0.1:8080` is overridden by
`compose.yml` (see below); set `CROWDSEC_LAPI_URL` in `./.env` if your
LAPI is elsewhere.

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
  repo on the host. `compose.yml` already maps `host.docker.internal`
  to the host and defaults `CROWDSEC_LAPI_URL` to
  `http://host.docker.internal:8080`. Two host-side changes make it
  reachable:

  1. CrowdSec's LAPI listens on `127.0.0.1:8080` by default, which a
     container can't reach. Widen it in
     `/etc/crowdsec/config.yaml.local` (create it if missing), then
     restart CrowdSec with `sudo systemctl restart crowdsec`:

     ```yaml
     api:
       server:
         listen_uri: 0.0.0.0:8080
     ```

  2. Keep port 8080 off the internet, but let Docker's bridge
     networks in. With ufw (which denies incoming by default):

     ```bash
     sudo ufw allow from 172.16.0.0/12 to any port 8080 proto tcp
     ```

     Without a host firewall, block 8080 at your provider instead.
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
