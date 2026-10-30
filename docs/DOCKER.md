# Protek on Docker

Arc 16 phase 95 — `docker compose up -d` to a logged-in dashboard
on a fresh VPS, no manual nginx / certbot / systemd dance.

The bare-metal install (via `install.sh` + `scripts/setup_admin.py` +
systemd + nginx) is still fully supported and is what runs the
primary VPS. Docker is the option-B path for new operators who would
rather ship containers.

**Easiest:** run the guided installer and pick **Docker** — it installs
Docker if needed, asks the questions in
[INSTALL.md](INSTALL.md#one-command-install), writes `./.env`, creates
the admin, and starts the stack:

```bash
curl -fsSL https://raw.githubusercontent.com/syedhashmi-bit/Protek/main/install.sh | sudo bash
```

The rest of this page is the same thing by hand.

## Quickstart — fresh host

Prerequisites: `docker` ≥ 24, `docker compose` 2.24+ (bundled with
recent Docker installs), a DNS record pointing your chosen domain at
the host, and CrowdSec (see [CrowdSec placement](#crowdsec-placement)).

```bash
# 1. Clone the repo into any directory (no /var/www required).
git clone https://github.com/syedhashmi-bit/Protek.git
cd Protek

# 2. Your settings go in ./.env. Caddy uses PROTEK_DOMAIN for Let's Encrypt;
#    COMPOSE_PROFILES=proxy starts Caddy; COMPOSE_FILE adds the host-network
#    override so Protek can reach CrowdSec on this host.
echo "PROTEK_DOMAIN=protek.example.com" > .env
echo "COMPOSE_PROFILES=proxy" >> .env
echo "COMPOSE_FILE=compose.yml:compose.hostnet.yml" >> .env
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

### Dashboard access

Set in `./.env`, then `docker compose up -d`:

| Access | `./.env` |
|--------|----------|
| Public domain, HTTPS | `PROTEK_DOMAIN=protek.example.com` · `COMPOSE_PROFILES=proxy` |
| LAN, plain HTTP | `PROTEK_DOMAIN=:80` · `COMPOSE_PROFILES=proxy` · `COOKIE_INSECURE=1` |
| This machine only | leave `COMPOSE_PROFILES` empty (no Caddy) · `COOKIE_INSECURE=1` · `TRUSTED_PROXY_HOPS=0` — then `http://127.0.0.1:8090`, or `ssh -L 8090:127.0.0.1:8090` from elsewhere |

`COOKIE_INSECURE=1` is needed whenever the dashboard is served over
plain HTTP — otherwise the browser drops the HTTPS-only session cookie
and login silently fails. Never use it on the public internet.

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
printf 'PROTEK_DOMAIN=protek.example.com\nCOMPOSE_PROFILES=proxy\n' > .env
# CrowdSec on this host too? Add: COMPOSE_FILE=compose.yml:compose.hostnet.yml
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
  repo on the host and add the host-network override to `./.env`:

  ```bash
  COMPOSE_FILE=compose.yml:compose.hostnet.yml
  ```

  [`compose.hostnet.yml`](../compose.hostnet.yml) puts Protek and Caddy
  on the host's network, so Protek reaches the LAPI at
  `127.0.0.1:8080` and CrowdSec stays loopback-only — no config change
  on the CrowdSec side. Gunicorn binds to `127.0.0.1:8090` there, and
  Caddy proxies to it. The installer does this for you.

- **Remote CrowdSec**: set `CROWDSEC_LAPI_URL=http://<lapi-host>:8080`
  and `CROWDSEC_BOUNCER_KEY` in `./.env` and leave `COMPOSE_FILE`
  unset. The remote LAPI must listen on an address this host can reach.

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
