#!/usr/bin/env bash
# install.sh — one-command install for a fresh Ubuntu 22.04/24.04 VPS.
#
# Usage:
#   curl -fsSL https://protek.example/install.sh | sudo bash
#   sudo bash install.sh
#
# What it does (idempotent — safe to re-run):
#   1. Installs system deps: python3.12, python3.12-venv, nginx, certbot, ufw,
#      git, sqlite3, build-essential, and CrowdSec (via official APT repo).
#   2. Clones (or pulls) Protek into /var/www/Protek.
#   3. Creates the venv + installs requirements.txt.
#   4. Bootstraps the admin via scripts/setup_admin.py (interactive — captures
#      one-shot password + TOTP).
#   5. Generates a CrowdSec bouncer key and wires it into .env.
#   6. Drops in a systemd unit + nginx site (operator picks domain).
#   7. Runs `certbot --nginx` for TLS (operator picks email + agrees ToS).
#
# Things it does NOT do (deliberate — too contextual):
#   - Configure your MikroTik. Add MT_HOST/USERNAME/PASSWORD to .env and add
#     the firewall drop rules per docs/INSTALL.md.
#   - Subscribe to CrowdSec Console. Run `cscli console enroll <key>` after.
#   - Flip DRY_RUN to false. Verify dry-run cycles first.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "install.sh: must run as root (try: sudo bash install.sh)" >&2
  exit 1
fi

PROTEK_DIR=/var/www/Protek
PROTEK_USER=root  # gunicorn worker runs as root for MT API socket + cscli access
GUNICORN_BIND=127.0.0.1:8090
REPO_URL="${PROTEK_REPO_URL:-https://github.com/syedhashmi-bit/Protek.git}"

say() { printf "\n\033[1;36m[install]\033[0m %s\n" "$*"; }
ask() { local prompt="$1" default="${2-}" reply; read -rp "$prompt${default:+ [$default]}: " reply; echo "${reply:-$default}"; }

# ── 1. System deps ──────────────────────────────────────────────────────────
say "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates lsb-release \
    python3.12 python3.12-venv python3-pip git sqlite3 \
    nginx certbot python3-certbot-nginx ufw build-essential

# CrowdSec from official repo (if not already installed)
if ! command -v cscli >/dev/null 2>&1; then
  say "Installing CrowdSec"
  curl -s https://install.crowdsec.net | bash
  apt-get install -y -qq crowdsec
fi
systemctl enable --now crowdsec

# ── 2. Source ───────────────────────────────────────────────────────────────
if [[ -d "$PROTEK_DIR/.git" ]]; then
  say "Pulling latest Protek source"
  git -C "$PROTEK_DIR" pull --ff-only
else
  say "Cloning Protek into $PROTEK_DIR"
  mkdir -p "$(dirname "$PROTEK_DIR")"
  git clone "$REPO_URL" "$PROTEK_DIR"
fi

# ── 3. venv + requirements ──────────────────────────────────────────────────
say "Setting up Python virtualenv"
cd "$PROTEK_DIR"
if [[ ! -d venv ]]; then
  python3.12 -m venv venv
fi
./venv/bin/pip install --quiet --upgrade pip
./venv/bin/pip install --quiet -r requirements.txt

# ── 4. .env + admin ─────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  say "Bootstrapping .env from .env.example"
  cp .env.example .env
  chmod 0600 .env
fi
if ! grep -q '^APP_PASSWORD_HASH=.\+' .env; then
  ADMIN_USER=$(ask "Admin username" "admin")
  say "Creating admin (captures password + TOTP — see one-shot output)"
  ./venv/bin/python scripts/setup_admin.py --username "$ADMIN_USER"
fi

# ── 5. CrowdSec bouncer key ─────────────────────────────────────────────────
if ! grep -q '^CROWDSEC_BOUNCER_KEY=.\+' .env; then
  say "Generating CrowdSec bouncer key for Protek"
  if cscli bouncers list -o json | grep -q '"name": *"protek"'; then
    echo "  (bouncer 'protek' already registered — delete & re-add: cscli bouncers delete protek)"
    BOUNCER_KEY=$(ask "Paste existing bouncer key for 'protek'")
  else
    BOUNCER_KEY=$(cscli bouncers add protek -o raw)
    echo "  Generated key for bouncer 'protek'."
  fi
  sed -i "s|^CROWDSEC_BOUNCER_KEY=.*|CROWDSEC_BOUNCER_KEY=${BOUNCER_KEY}|" .env
fi

# ── 6. systemd ──────────────────────────────────────────────────────────────
say "Installing systemd unit"
cat >/etc/systemd/system/protek.service <<UNIT
[Unit]
Description=Protek — CrowdSec to MikroTik bouncer + NOC dashboard
After=network-online.target crowdsec.service
Wants=crowdsec.service

[Service]
User=$PROTEK_USER
WorkingDirectory=$PROTEK_DIR
Environment="PATH=$PROTEK_DIR/venv/bin"
EnvironmentFile=$PROTEK_DIR/.env
ExecStart=$PROTEK_DIR/venv/bin/gunicorn -w 3 -b $GUNICORN_BIND --timeout 60 app:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now protek

# ── 7. nginx + TLS ──────────────────────────────────────────────────────────
DOMAIN=$(ask "Domain name (blank to skip nginx/TLS — bind directly on $GUNICORN_BIND)" "")
if [[ -n "$DOMAIN" ]]; then
  say "Writing nginx site for $DOMAIN"
  cat >/etc/nginx/sites-available/protek <<SITE
server {
  listen 80;
  listen [::]:80;
  server_name $DOMAIN;

  location / {
    proxy_pass http://$GUNICORN_BIND;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 60s;
  }
}
SITE
  ln -sf /etc/nginx/sites-available/protek /etc/nginx/sites-enabled/protek
  nginx -t && systemctl reload nginx

  EMAIL=$(ask "Email for Let's Encrypt notifications")
  certbot --nginx --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" || \
    echo "  (TLS step failed — re-run later: certbot --nginx -d $DOMAIN)"
fi

# ── 8. ufw (optional) ───────────────────────────────────────────────────────
if command -v ufw >/dev/null && ! ufw status | grep -q "Status: active"; then
  say "Enabling ufw with HTTP/HTTPS + SSH"
  ufw allow 22/tcp
  ufw allow 80/tcp
  ufw allow 443/tcp
  ufw --force enable
fi

# ── done ────────────────────────────────────────────────────────────────────
cat <<DONE

==============================================================
  Protek installed.
==============================================================
  Service:    systemctl status protek
  URL:        ${DOMAIN:+https://$DOMAIN  /  }http://$GUNICORN_BIND
  Edit env:   $PROTEK_DIR/.env  (then: systemctl restart protek)

  Next steps:
    1. Read docs/USER_GUIDE.md
    2. Add MT_HOST / MT_USERNAME / MT_PASSWORD to .env
    3. Add MikroTik firewall drop rules per docs/INSTALL.md
    4. Enroll in CrowdSec Console:  cscli console enroll <key>
    5. Browse to the dashboard, log in with the password + TOTP from earlier
    6. Verify dry-run cycles look right, THEN flip dry_run to false in /settings
==============================================================

DONE
