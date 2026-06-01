# Install Guide

Tested on Ubuntu 22.04 + 24.04. Other Debian-derived distros likely fine. RHEL not supported.

## One-command install

```bash
curl -fsSL https://raw.githubusercontent.com/syedhashmi-bit/Protek/main/install.sh | sudo bash
```

This handles: system deps, CrowdSec (via APT), Python venv, requirements,
admin bootstrap, bouncer key generation, systemd unit, nginx site, TLS via certbot.

It does **not** handle: MikroTik wiring (you provide creds + firewall rules),
CrowdSec Console enrollment (one extra step), flipping out of dry-run.

## Manual install (for the cautious)

```bash
# 1. Deps
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv git nginx certbot \
    python3-certbot-nginx sqlite3 build-essential

# 2. CrowdSec
curl -s https://install.crowdsec.net | sudo bash
sudo apt-get install -y crowdsec
sudo systemctl enable --now crowdsec

# 3. Clone + venv
sudo git clone https://github.com/syedhashmi-bit/Protek.git /var/www/Protek
cd /var/www/Protek
sudo python3.12 -m venv venv
sudo ./venv/bin/pip install -r requirements.txt

# 4. Admin bootstrap (captures password + TOTP once; chmod 0600 on .env)
sudo cp .env.example .env
sudo chmod 0600 .env
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
sudo certbot --nginx -d your.domain
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
