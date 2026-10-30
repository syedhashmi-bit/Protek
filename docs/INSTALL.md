# Install Guide

For Ubuntu 22.04, 24.04 and 26.04. Other Debian-derived distros likely fine. RHEL not supported.

Protek needs **Python 3.12**. Ubuntu 24.04 packages it as `python3.12`; 22.04
ships 3.10 and 26.04 a newer 3.x, so there the installer fetches 3.12 with
[uv](https://docs.astral.sh/uv/) instead. Prefer containers? See
[`DOCKER.md`](DOCKER.md).

## One-command install

```bash
curl -fsSL https://raw.githubusercontent.com/syedhashmi-bit/Protek/main/install.sh | sudo bash
```

The installer asks a few questions first and changes nothing until you
confirm the summary:

| Question | Choices |
|----------|---------|
| How should Protek run? | **Bare metal** (systemd service, nginx when needed) or **Docker** (compose + Caddy; installs Docker if missing) |
| Who can open the dashboard? | **This machine only** (`http://127.0.0.1:8090`, reach it over an SSH tunnel), **LAN** (plain HTTP on the machine's LAN address), or a **public domain with HTTPS** (Let's Encrypt) |
| Which CrowdSec? | The one **on this machine** (or **install it** if missing), or a **remote LAPI** — URL + bouncer key, checked on the spot |
| Connect MikroTik now? | Router address, API port, user, password and address list — the connection is tested after install. Or skip and edit `.env` later |
| Admin username, firewall | Default `admin`; ufw stays off unless you say yes, and then it opens the port sshd really uses |

It also explains **dry-run**: Protek starts out computing what it *would*
push to the router without touching it, and you turn that off in
Settings once the numbers on `/mikrotik` look right.

LAN mode is for a home or office network. If the machine's address is
public (a VPS), the installer warns you, since LAN mode would serve the
login page over plain HTTP to the internet.

**Unattended:** every answer can be preset as an environment variable
(`PROTEK_METHOD`, `PROTEK_ACCESS`, `PROTEK_DOMAIN`, `PROTEK_CROWDSEC`,
`MT_HOST`, …, listed at the top of `install.sh`), with `PROTEK_YES=1`
to skip the confirmation. `PROTEK_PLAN_ONLY=1` just prints the summary.

It then installs everything those answers need — CrowdSec, a Python 3.12
venv or the Docker image, the admin account (password + TOTP shown once),
the bouncer key, the service, and nginx/certbot or Caddy. Safe to re-run:
the admin is only created the first time, and changed answers are written
to `.env`.

It does **not** add the MikroTik firewall drop rule (below), enroll in the
CrowdSec Console, or turn dry-run off.

## Manual install (for the cautious)

```bash
# 1. Deps
sudo apt-get update
sudo apt-get install -y git nginx certbot python3-certbot-nginx sqlite3 build-essential
sudo apt-get install -y python3.12 python3.12-venv   # Ubuntu 24.04 only — see step 3

# 2. CrowdSec
curl -s https://install.crowdsec.net | sudo bash
sudo apt-get install -y crowdsec
sudo systemctl enable --now crowdsec

# 3. Clone + venv
sudo git clone https://github.com/syedhashmi-bit/Protek.git /var/www/Protek
cd /var/www/Protek
sudo python3.12 -m venv venv
# No python3.12 package (22.04, 26.04)? Use uv instead of the line above. The
# interpreter goes under /opt because the systemd unit mounts /root read-only:
#   curl -LsSf https://astral.sh/uv/install.sh | sudo env UV_INSTALL_DIR=/usr/local/bin sh
#   sudo env UV_PYTHON_INSTALL_DIR=/opt/uv/python uv venv --seed --python 3.12 venv
sudo ./venv/bin/pip install -r requirements.txt

# 4. Admin bootstrap (creates .env from .env.example, chmod 0600;
#    captures password + TOTP once)
sudo ./venv/bin/python scripts/setup_admin.py --username admin

# 5. Bouncer key
sudo cscli bouncers add protek                # paste into .env as CROWDSEC_BOUNCER_KEY

# 6. systemd
sudo cp deploy/protek.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now protek

# 7. nginx + TLS
sudo cp deploy/nginx.conf /etc/nginx/sites-available/protek
sudo sed -i 's/your.domain/protek.example.com/' /etc/nginx/sites-available/protek
sudo ln -sf /etc/nginx/sites-available/protek /etc/nginx/sites-enabled/protek
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d protek.example.com
```

## Connecting MikroTik

1. **Create a dedicated API user on the router** (recommended — don't reuse `admin`):
   ```
   /user group add name=protek policy=api,read,write,policy
   /user add name=protek-api password=<long-random> group=protek
   ```
2. **Open the API port** (default 8728 plaintext, 8729 SSL):
   ```
   /ip service set api address=<protek-vps-ip>/32 disabled=no
   ```
3. **Drop the credentials into `.env`**:
   ```
   MT_HOST=<router-ip-or-hostname>
   MT_USERNAME=protek-api
   MT_PASSWORD=<...>
   MT_PORT=8728
   MT_USE_SSL=false
   MT_ADDRESS_LIST=crowdsec
   ```
4. **Add the firewall rules on the router** — Protek populates the address-list,
   but only YOUR firewall rules turn that into actual blocking:
   ```
   /ip firewall filter add chain=input  src-address-list=crowdsec action=drop comment="protek-bouncer" place-before=0
   /ip firewall filter add chain=forward src-address-list=crowdsec action=drop comment="protek-bouncer" place-before=0
   ```
   `chain=input` drops banned IPs hitting the router itself. `chain=forward`
   drops banned IPs heading to anything behind the router (the main protection).
5. **Restart Protek** so it picks up the env vars: `sudo systemctl restart protek`.
6. **Verify in the UI**: visit `/mikrotik` — should show "connected" + the address-list size.

## CrowdSec Console (recommended)

The Console (https://app.crowdsec.net) gives you a cloud dashboard view of
your alerts and a CTI API key for Protek's `/intel` enrichment.

```bash
# 1. Sign up at app.crowdsec.net → click "Add Instance" → copy the enroll key
sudo cscli console enroll <enroll-key>

# 2. Accept the new machine in the Console UI

# 3. Reload
sudo systemctl reload crowdsec

# 4. Get a CTI API key from Console → Settings → API keys
# 5. Add it to .env as CROWDSEC_CTI_API_KEY
sudo systemctl restart protek
```

## Machine credentials (enables the /alerts page)

Bouncer keys are read-only on decisions only. The richer `/alerts` view needs
a machine credential:

```bash
sudo cscli machines add protek-machine --auto
# Pastes machine_id + password into .env as:
#   CROWDSEC_MACHINE_LOGIN=protek-machine
#   CROWDSEC_MACHINE_PASSWORD=<...>
sudo systemctl restart protek
```

## Flipping out of dry-run

First deploy defaults to `DRY_RUN=true` — the reconcile loop computes the diff
each cycle but never writes to MikroTik. Watch a few cycles in `/mikrotik`:

- `to_add` should equal your active decision count (rising as CrowdSec catches things)
- `to_remove` should be 0 (or small)
- Cycle duration should be sub-second once the dry-run diff has converged

When you're satisfied: `/settings` → uncheck Dry Run → Save. The poller
re-reads this on every cycle so no restart needed.

The initial sync writes ~200 entries per cycle (the default `BATCH_CAP`),
so a 19k-decision backfill takes ~16-60 minutes depending on router latency.
Watch progress on `/mikrotik`.

## Suite integrations

Set `ATOM_URL` and `OTHONI_URL` in `.env` (or via `/settings`) to enable
cross-app links from attacker pages and to let `othoni` render Protek's tile.
