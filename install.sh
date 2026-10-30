#!/usr/bin/env bash
# install.sh — guided installer for Protek on Ubuntu 22.04 / 24.04 / 26.04.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/syedhashmi-bit/Protek/main/install.sh | sudo bash
#   sudo bash install.sh
#
# It asks everything up front, shows a summary, and changes nothing until you
# confirm:
#   1. How to run Protek — bare metal (systemd + nginx) or Docker (compose + Caddy)
#   2. Who can open the dashboard — this machine only, your LAN (plain HTTP),
#      or a public domain with HTTPS
#   3. CrowdSec — use or install it on this machine, or point at a remote LAPI
#   4. MikroTik — router address + API user (optional; tested after install)
#   5. Admin username, and whether to turn on the ufw firewall
# Protek always starts in dry-run; the installer explains what that means.
#
# Python: Protek needs 3.12. Bare metal uses the distro's python3.12 where it
# exists (Ubuntu 24.04), otherwise fetches 3.12 with uv into /opt/uv.
#
# Unattended: any answer can be given ahead of time as an environment variable,
# and PROTEK_YES=1 skips the confirmation. For example:
#   sudo PROTEK_METHOD=docker PROTEK_ACCESS=domain PROTEK_DOMAIN=protek.example.com \
#        PROTEK_CROWDSEC=local PROTEK_MIKROTIK=skip PROTEK_UFW=n PROTEK_YES=1 \
#        bash install.sh
#   PROTEK_METHOD      baremetal | docker
#   PROTEK_ACCESS      local | lan | domain
#   PROTEK_DOMAIN, PROTEK_LE_EMAIL          (domain access; email is bare metal only)
#   PROTEK_CROWDSEC    local | install | remote
#   CROWDSEC_LAPI_URL, CROWDSEC_BOUNCER_KEY (remote CrowdSec)
#   PROTEK_MIKROTIK    configure | skip
#   MT_HOST, MT_PORT, MT_USERNAME, MT_PASSWORD, MT_ADDRESS_LIST
#   PROTEK_ADMIN_USER, PROTEK_UFW (y | n)
#   PROTEK_PLAN_ONLY=1 asks the questions, prints the summary, and stops.
#
# Idempotent — safe to re-run. The admin password + TOTP are only generated
# the first time; re-running applies changed answers to .env.
#
# Not done here (see docs/INSTALL.md): the MikroTik firewall drop rule,
# CrowdSec Console enrollment, and turning dry-run off.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "install.sh: must run as root (try: sudo bash install.sh)" >&2
  exit 1
fi

PROTEK_DIR=/var/www/Protek
REPO_URL="${PROTEK_REPO_URL:-https://github.com/syedhashmi-bit/Protek.git}"

say()  { printf "\n\033[1;36m[install]\033[0m %s\n" "$*"; }
note() { printf "  %s\n" "$*" >&2; }
warn() { printf "\n\033[1;33m[install]\033[0m %s\n" "$*" >&2; }
die()  { printf "\n\033[1;31m[install]\033[0m %s\n" "$*" >&2; exit 1; }

# Prompts read from /dev/tty, not stdin: under `curl ... | sudo bash` stdin IS
# this script, so a plain `read` would swallow the script's own next lines.
# With no terminal at all, every question takes its default (or the value
# preset in the environment).
TTY=0
if { : </dev/tty; } 2>/dev/null; then TTY=1; fi

# ask VAR "prompt" [default] — sets VAR. A value already in the environment
# counts as the answer; that is how unattended installs work.
ask() {
  local __var="$1" prompt="$2" default="${3-}" reply=""
  [[ -n "${!__var-}" ]] && return 0
  if (( TTY )); then
    read -rp "  $prompt${default:+ [$default]}: " reply </dev/tty || true
  fi
  printf -v "$__var" '%s' "${reply:-$default}"
}

ask_secret() {
  local __var="$1" prompt="$2" reply=""
  [[ -n "${!__var-}" ]] && return 0
  if (( TTY )); then
    read -rsp "  $prompt: " reply </dev/tty || true
    echo >&2
  fi
  printf -v "$__var" '%s' "$reply"
}

# require VAR "what" — dies if VAR ended up empty (no terminal, no preset).
require() {
  [[ -n "${!1-}" ]] || die "$2 is required. Set $1=... and re-run."
}

# choose VAR "question" default key1 "label1" key2 "label2" ...
choose() {
  local __var="$1" question="$2" default="$3"; shift 3
  local keys=() labels=() i reply
  while (( $# )); do keys+=("$1"); labels+=("$2"); shift 2; done
  if [[ -n "${!__var-}" ]]; then
    for i in "${!keys[@]}"; do [[ "${keys[$i]}" == "${!__var}" ]] && return 0; done
    die "$__var=${!__var} is not one of: ${keys[*]}"
  fi
  printf "\n  %s\n" "$question" >&2
  local def_n=1
  for i in "${!keys[@]}"; do
    [[ "${keys[$i]}" == "$default" ]] && def_n=$((i + 1))
    printf "    %d) %s\n" $((i + 1)) "${labels[$i]}" >&2
  done
  while :; do
    reply=""
    if (( TTY )); then read -rp "  Choose [$def_n]: " reply </dev/tty || true; fi
    reply="${reply:-$def_n}"
    if [[ "$reply" =~ ^[0-9]+$ ]] && (( reply >= 1 && reply <= ${#keys[@]} )); then
      printf -v "$__var" '%s' "${keys[$((reply - 1))]}"
      return 0
    fi
    note "Please enter a number from 1 to ${#keys[@]}."
  done
}

# yesno VAR "question" default(y|n) — sets VAR to y or n.
yesno() {
  local __var="$1" question="$2" default="$3" reply=""
  if [[ -z "${!__var-}" ]]; then
    if (( TTY )); then
      local hint="y/N"; [[ "$default" == y ]] && hint="Y/n"
      read -rp "  $question [$hint]: " reply </dev/tty || true
    fi
    printf -v "$__var" '%s' "${reply:-$default}"
  fi
  case "${!__var}" in [Yy]*) printf -v "$__var" y ;; *) printf -v "$__var" n ;; esac
}

# set_env FILE KEY VALUE — replace or append KEY in a .env file. User-supplied
# values are single-quoted: systemd's EnvironmentFile=, python-dotenv and
# Compose's env_file all read single quotes literally ('#', '$', spaces safe).
set_env() {
  local file="$1" key="$2" value="$3"
  [[ "$value" == *"'"* || "$value" == *$'\n'* ]] && \
    die "$key can't contain a single quote or newline — set it in $file by hand."
  touch "$file"; chmod 0600 "$file"
  ENV_FILE="$file" ENV_KEY="$key" ENV_VALUE="'$value'" python3 -c '
import os, re
path, key, value = os.environ["ENV_FILE"], os.environ["ENV_KEY"], os.environ["ENV_VALUE"]
lines = open(path).read().splitlines()
pat = re.compile(r"^" + re.escape(key) + r"=")
for i, line in enumerate(lines):
    if pat.match(line):
        lines[i] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
open(path, "w").write("\n".join(lines) + "\n")
'
}

env_has() { grep -qs "^$2=.\+" "$1"; }

lan_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit }}'
}

# True for RFC 1918, CGNAT (100.64/10) and link-local addresses.
is_private_ip() {
  local a b
  IFS=. read -r a b _ _ <<<"$1"
  [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ ]] || return 1
  (( a == 10 )) || (( a == 192 && b == 168 )) || (( a == 172 && b >= 16 && b <= 31 )) ||
    (( a == 100 && b >= 64 && b <= 127 )) || (( a == 169 && b == 254 ))
}

# ════════════════════════════════════════════════════════════════════════════
#  Questions — nothing on the box changes in this section.
# ════════════════════════════════════════════════════════════════════════════
say "Protek installer — a few questions first. Nothing changes until you confirm."
if (( ! TTY )); then
  note "No terminal: using defaults and PROTEK_* / CROWDSEC_* / MT_* from the environment."
fi

# ── 1. Install method ──────────────────────────────────────────────────────
choose PROTEK_METHOD "How should Protek run?" baremetal \
  baremetal "Bare metal — a systemd service, plus nginx when needed (simplest to debug)" \
  docker    "Docker — a compose stack with Caddy (installs Docker if it's missing)"

# ── 2. Dashboard access ────────────────────────────────────────────────────
choose PROTEK_ACCESS "Who should be able to open the dashboard?" local \
  local  "Only this machine — http://127.0.0.1:8090 (from elsewhere, use an SSH tunnel)" \
  lan    "My local network — http://<this machine's LAN IP> (plain HTTP; never expose it to the internet)" \
  domain "A public domain with HTTPS — needs a DNS record pointing here and ports 80/443 open"

LAN_IP=""
case "$PROTEK_ACCESS" in
  lan)
    LAN_IP=$(lan_ip)
    if [[ -z "$LAN_IP" ]]; then
      LAN_IP="<this machine's IP>"
    elif ! is_private_ip "$LAN_IP"; then
      # A VPS has no LAN: its "LAN" address is the public one, so this would
      # serve the login page over plain HTTP to the whole internet.
      warn "This machine's address, $LAN_IP, is public — not a LAN address. LAN mode would serve the dashboard over plain HTTP to the internet. On a VPS, choose a domain with HTTPS, or this machine only."
      yesno LAN_PUBLIC_OK "Use LAN mode anyway?" n
      [[ "$LAN_PUBLIC_OK" == y ]] || die "Stopped — re-run and pick another access option."
    fi
    ;;
  domain)
    ask PROTEK_DOMAIN "Domain name (e.g. protek.example.com)"
    require PROTEK_DOMAIN "A domain name"
    [[ "$PROTEK_DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]] || die "'$PROTEK_DOMAIN' doesn't look like a domain name."
    if [[ "$PROTEK_METHOD" == baremetal ]]; then
      ask PROTEK_LE_EMAIL "Email for Let's Encrypt expiry notices"
      require PROTEK_LE_EMAIL "An email for Let's Encrypt"
    fi
    ;;
esac

# ── 3. CrowdSec ────────────────────────────────────────────────────────────
if command -v cscli >/dev/null 2>&1; then
  choose PROTEK_CROWDSEC "Which CrowdSec should Protek read bans from?" local \
    local  "The CrowdSec already running on this machine" \
    remote "A CrowdSec LAPI on another server"
  [[ "$PROTEK_CROWDSEC" == install ]] && PROTEK_CROWDSEC=local
else
  choose PROTEK_CROWDSEC "CrowdSec isn't installed here. Where should Protek read bans from?" install \
    install "Install CrowdSec on this machine (official APT repo)" \
    remote  "A CrowdSec LAPI on another server"
  [[ "$PROTEK_CROWDSEC" == local ]] && die "PROTEK_CROWDSEC=local, but cscli isn't installed on this machine."
fi

if [[ "$PROTEK_CROWDSEC" == remote ]]; then
  note "On the CrowdSec server, create a key with:  sudo cscli bouncers add protek"
  note "Its LAPI must listen on an address this machine can reach (api.server.listen_uri)."
  ask CROWDSEC_LAPI_URL "LAPI URL (e.g. http://10.0.0.5:8080)"
  require CROWDSEC_LAPI_URL "The remote LAPI URL"
  CROWDSEC_LAPI_URL="${CROWDSEC_LAPI_URL%/}"
  ask_secret CROWDSEC_BOUNCER_KEY "Bouncer API key"
  require CROWDSEC_BOUNCER_KEY "The bouncer API key"
  code=$(curl -s -o /dev/null -m 10 -w '%{http_code}' \
         -H "X-Api-Key: $CROWDSEC_BOUNCER_KEY" "$CROWDSEC_LAPI_URL/v1/decisions" || true)
  case "$code" in
    200) note "✓ Reached the LAPI and the key works." ;;
    401|403) warn "The LAPI answered but rejected the key (HTTP $code)." ;;
    *) warn "Couldn't reach $CROWDSEC_LAPI_URL (HTTP ${code:-none}). Check the URL and that its port is open to this machine." ;;
  esac
  if [[ "$code" != 200 ]]; then
    yesno LAPI_CONTINUE "Continue anyway and fix it in .env later?" n
    [[ "$LAPI_CONTINUE" == y ]] || die "Stopped. Re-run once the LAPI is reachable."
  fi
fi

# ── 4. MikroTik ────────────────────────────────────────────────────────────
# Without a terminal there's nobody to type router details, so default to later.
MT_DEFAULT=configure; (( TTY )) || MT_DEFAULT=skip
choose PROTEK_MIKROTIK "Connect your MikroTik router now?" "$MT_DEFAULT" \
  configure "Yes — I have the router's address and an API user for Protek" \
  skip      "Later — I'll add MT_HOST / MT_USERNAME / MT_PASSWORD to .env myself"
if [[ "$PROTEK_MIKROTIK" == configure ]]; then
  note "The router needs the API service on, and a user Protek can log in as."
  note "docs/INSTALL.md → \"Connecting MikroTik\" has the RouterOS commands."
  ask MT_HOST "Router address (IP or hostname)"
  require MT_HOST "The router address"
  ask MT_PORT "API port (8728 plain, 8729 TLS)" 8728
  [[ "$MT_PORT" =~ ^[0-9]+$ ]] || die "MT_PORT must be a number."
  ask MT_USERNAME "API username"
  require MT_USERNAME "The API username"
  ask_secret MT_PASSWORD "API password"
  require MT_PASSWORD "The API password"
  ask MT_ADDRESS_LIST "Address list to manage" crowdsec
fi

# ── 5. Admin + firewall ────────────────────────────────────────────────────
if env_has "$PROTEK_DIR/.env" APP_PASSWORD_HASH; then
  ADMIN_NOTE="(already set up — kept)"
else
  ask PROTEK_ADMIN_USER "Admin username" admin
  ADMIN_NOTE="$PROTEK_ADMIN_USER"
fi
PROTEK_UFW="${PROTEK_UFW-}"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  PROTEK_UFW=active
else
  yesno PROTEK_UFW "Turn on the ufw firewall (allows SSH and what Protek needs)?" n
fi

# ── Dry-run, summary, confirm ──────────────────────────────────────────────
cat >&2 <<'DRYRUN'

  ┌─ About dry-run ────────────────────────────────────────────────────────┐
  │ Protek starts in DRY-RUN. It reads CrowdSec's bans and works out       │
  │ exactly what it would add to and remove from the MikroTik address      │
  │ list, and shows that on the /mikrotik page — but it changes nothing    │
  │ on the router, so nothing is blocked yet.                              │
  │                                                                        │
  │ Once the numbers look right (and the router has a firewall rule that   │
  │ drops traffic from the address list), turn it off in Settings → Dry    │
  │ run. You can turn it back on at any time.                              │
  └────────────────────────────────────────────────────────────────────────┘
DRYRUN

case "$PROTEK_ACCESS" in
  local)  ACCESS_DESC="this machine only — http://127.0.0.1:8090" ;;
  lan)    ACCESS_DESC="LAN — http://$LAN_IP (plain HTTP)" ;;
  domain) ACCESS_DESC="https://$PROTEK_DOMAIN" ;;
esac
case "$PROTEK_CROWDSEC" in
  local)   CS_DESC="CrowdSec on this machine" ;;
  install) CS_DESC="install CrowdSec on this machine" ;;
  remote)  CS_DESC="remote LAPI at $CROWDSEC_LAPI_URL" ;;
esac
if [[ "$PROTEK_MIKROTIK" == configure ]]; then
  MT_DESC="$MT_USERNAME@$MT_HOST:$MT_PORT, list '$MT_ADDRESS_LIST'"
else
  MT_DESC="later (edit .env)"
fi
case "$PROTEK_UFW" in active) UFW_DESC="already on — leaving it" ;; y) UFW_DESC="turn on" ;; *) UFW_DESC="leave off" ;; esac
if [[ "$PROTEK_METHOD" == docker ]]; then METHOD_DESC="Docker (compose)"; else METHOD_DESC="bare metal (systemd)"; fi

{
  printf "\n  Summary\n  ───────\n"
  printf "    Install method   %s\n" "$METHOD_DESC"
  printf "    Dashboard        %s\n" "$ACCESS_DESC"
  printf "    CrowdSec         %s\n" "$CS_DESC"
  printf "    MikroTik         %s\n" "$MT_DESC"
  printf "    Admin user       %s\n" "$ADMIN_NOTE"
  printf "    Firewall (ufw)   %s\n" "$UFW_DESC"
  printf "    Location         %s\n" "$PROTEK_DIR"
  printf "    Mode             dry-run (nothing is pushed to the router yet)\n\n"
} >&2

if [[ "${PROTEK_PLAN_ONLY:-}" == 1 ]]; then
  note "PROTEK_PLAN_ONLY=1 — stopping before making any changes."
  exit 0
fi
if [[ "${PROTEK_YES:-}" != 1 ]]; then
  (( TTY )) || die "No terminal to confirm on. Set PROTEK_YES=1 to install unattended."
  yesno GO "Install with these settings?" y
  [[ "$GO" == y ]] || die "Cancelled — nothing was changed."
fi

# ════════════════════════════════════════════════════════════════════════════
#  Install
# ════════════════════════════════════════════════════════════════════════════

# Proxy and cookie settings follow from the access mode. "local" is reached
# straight on gunicorn, so no proxy hop is trusted; local + LAN are plain HTTP,
# so the session cookie can't be HTTPS-only (browsers would drop it).
if [[ "$PROTEK_ACCESS" == local ]]; then PROXY_HOPS=0; else PROXY_HOPS=1; fi
if [[ "$PROTEK_ACCESS" == domain ]]; then COOKIE_INSECURE=0; else COOKIE_INSECURE=1; fi

say "Installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates gnupg git sqlite3 python3 iproute2

if [[ "$PROTEK_CROWDSEC" == install ]]; then
  say "Installing CrowdSec"
  curl -s https://install.crowdsec.net | bash
  apt-get install -y -qq crowdsec
  systemctl enable --now crowdsec
fi

if [[ -d "$PROTEK_DIR/.git" ]]; then
  say "Pulling latest Protek source"
  git -C "$PROTEK_DIR" pull --ff-only
else
  say "Cloning Protek into $PROTEK_DIR"
  mkdir -p "$(dirname "$PROTEK_DIR")"
  git clone "$REPO_URL" "$PROTEK_DIR"
fi
cd "$PROTEK_DIR"
ENV=$PROTEK_DIR/.env

# Local CrowdSec: create (or reuse) the bouncer key Protek reads with.
local_bouncer_key() {
  env_has "$ENV" CROWDSEC_BOUNCER_KEY && return 0
  if cscli bouncers list -o json | grep -q '"name": *"protek"'; then
    note "A bouncer named 'protek' already exists in CrowdSec."
    note "Paste its key, or leave blank and run: cscli bouncers delete protek; then re-run."
    ask_secret CROWDSEC_BOUNCER_KEY "Existing key for 'protek'"
    require CROWDSEC_BOUNCER_KEY "The bouncer key"
  else
    CROWDSEC_BOUNCER_KEY=$(cscli bouncers add protek -o raw)
    note "Generated a CrowdSec bouncer key for 'protek'."
  fi
  set_env "$ENV" CROWDSEC_BOUNCER_KEY "$CROWDSEC_BOUNCER_KEY"
}

write_settings() {
  set_env "$ENV" COOKIE_INSECURE "$COOKIE_INSECURE"
  set_env "$ENV" TRUSTED_PROXY_HOPS "$PROXY_HOPS"
  if [[ "$PROTEK_CROWDSEC" == remote ]]; then
    set_env "$ENV" CROWDSEC_LAPI_URL "$CROWDSEC_LAPI_URL"
    set_env "$ENV" CROWDSEC_BOUNCER_KEY "$CROWDSEC_BOUNCER_KEY"
  else
    local_bouncer_key
  fi
  if [[ "$PROTEK_MIKROTIK" == configure ]]; then
    set_env "$ENV" MT_HOST "$MT_HOST"
    set_env "$ENV" MT_PORT "$MT_PORT"
    set_env "$ENV" MT_USERNAME "$MT_USERNAME"
    set_env "$ENV" MT_PASSWORD "$MT_PASSWORD"
    set_env "$ENV" MT_ADDRESS_LIST "$MT_ADDRESS_LIST"
    if [[ "$MT_PORT" == 8729 ]]; then set_env "$ENV" MT_USE_SSL true; fi
  fi
}

# Prints the result of MikroTik.health(); $1 is the python command to use.
MT_CHECK='import json, mikrotik
h = mikrotik.MikroTik().health()
if h.get("ok"):
    print("  ✓ Connected to %s (RouterOS %s)." % (h.get("name") or "router", h.get("version") or "?"))
else:
    print("  ✗ Could not log in to the router: %s" % h.get("error"))
    raise SystemExit(1)'

check_mikrotik() {
  [[ "$PROTEK_MIKROTIK" == configure ]] || return 0
  say "Testing the MikroTik connection"
  if ! "$@"; then
    warn "Protek is installed, but can't reach the router yet. Check MT_* in $ENV, that the API service is on (port $MT_PORT), and that the router allows this machine's IP. Then restart Protek."
  fi
}

# ── Bare metal ─────────────────────────────────────────────────────────────
install_baremetal() {
  local pkgs=(build-essential)
  [[ "$PROTEK_ACCESS" != local ]] && pkgs+=(nginx)
  [[ "$PROTEK_ACCESS" == domain ]] && pkgs+=(certbot python3-certbot-nginx)
  apt-get install -y -qq "${pkgs[@]}"

  # Python 3.12 from the distro when it packages it (Ubuntu 24.04).
  if apt-cache show python3.12-venv >/dev/null 2>&1; then
    apt-get install -y -qq python3.12 python3.12-venv
  fi

  say "Setting up the Python 3.12 virtualenv"
  if [[ ! -x venv/bin/python ]]; then
    if command -v python3.12 >/dev/null 2>&1 && python3.12 -c 'import ensurepip' 2>/dev/null; then
      python3.12 -m venv venv
    else
      # No distro 3.12: let uv fetch one. The interpreter goes under /opt, not
      # /root/.local, because the systemd unit mounts /root read-only and a venv
      # whose python symlinks into a hidden home fails with status=203/EXEC.
      say "No distro python3.12 — fetching Python 3.12 with uv"
      export UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1
      export UV_PYTHON_INSTALL_DIR=/opt/uv/python
      command -v uv >/dev/null 2>&1 || curl -LsSf https://astral.sh/uv/install.sh | sh
      uv venv --seed --managed-python --python 3.12 venv
    fi
  fi
  ./venv/bin/pip install --quiet --upgrade pip
  ./venv/bin/pip install --quiet -r requirements.txt

  if ! env_has "$ENV" APP_PASSWORD_HASH; then
    say "Creating the admin account — the password and TOTP below are shown ONCE"
    ./venv/bin/python scripts/setup_admin.py --username "$PROTEK_ADMIN_USER"
    if (( TTY )); then
      read -rp "  Saved the password and added the TOTP to your authenticator? Press Enter to continue. " _ </dev/tty || true
    fi
  fi
  write_settings

  say "Installing the systemd service"
  install -m 0644 deploy/protek.service /etc/systemd/system/protek.service
  systemctl daemon-reload
  systemctl enable protek
  systemctl restart protek

  case "$PROTEK_ACCESS" in
    lan)
      say "Serving the dashboard on this machine's LAN address (port 80)"
      install -m 0644 deploy/nginx.conf /etc/nginx/sites-available/protek
      sed -i -e 's/server_name your\.domain;/server_name _;/' \
             -e 's/listen 80;/listen 80 default_server;/' \
             -e 's/listen \[::\]:80;/listen [::]:80 default_server;/' \
             /etc/nginx/sites-available/protek
      # The stock "Welcome to nginx" site also claims default_server.
      if [[ "$(readlink -f /etc/nginx/sites-enabled/default 2>/dev/null)" == /etc/nginx/sites-available/default ]]; then
        rm /etc/nginx/sites-enabled/default
      fi
      ln -sf /etc/nginx/sites-available/protek /etc/nginx/sites-enabled/protek
      nginx -t && systemctl reload nginx
      ;;
    domain)
      say "Setting up nginx + HTTPS for $PROTEK_DOMAIN"
      install -m 0644 deploy/nginx.conf /etc/nginx/sites-available/protek
      sed -i "s/your\.domain/$PROTEK_DOMAIN/" /etc/nginx/sites-available/protek
      ln -sf /etc/nginx/sites-available/protek /etc/nginx/sites-enabled/protek
      nginx -t && systemctl reload nginx
      certbot --nginx --non-interactive --agree-tos -m "$PROTEK_LE_EMAIL" -d "$PROTEK_DOMAIN" || \
        warn "HTTPS setup failed (is DNS pointing here, and port 80 open?). Re-run later: certbot --nginx -d $PROTEK_DOMAIN"
      ;;
  esac

  check_mikrotik timeout 30 ./venv/bin/python -c \
    "from dotenv import load_dotenv; load_dotenv('.env'); $MT_CHECK"
}

# ── Docker ─────────────────────────────────────────────────────────────────
install_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    say "Installing Docker (get.docker.com)"
    curl -fsSL https://get.docker.com | sh
  fi
  local v
  v=$(docker compose version --short 2>/dev/null | sed 's/^v//') || true
  [[ -n "$v" ]] || die "The docker compose plugin is missing. Install docker-compose-plugin and re-run."
  if [[ "$(printf '%s\n' 2.24.0 "$v" | sort -V | head -1)" != 2.24.0 ]]; then
    die "docker compose $v is too old (need 2.24+). Upgrade Docker and re-run."
  fi

  # ./.env next to compose.yml: your settings, plus Compose's own switches.
  # The generated secrets go to /data/.env on the volume (setup_admin.py).
  case "$PROTEK_ACCESS" in
    local)  set_env "$ENV" COMPOSE_PROFILES "" ;;
    lan)    set_env "$ENV" COMPOSE_PROFILES proxy; set_env "$ENV" PROTEK_DOMAIN ":80" ;;
    domain) set_env "$ENV" COMPOSE_PROFILES proxy; set_env "$ENV" PROTEK_DOMAIN "$PROTEK_DOMAIN" ;;
  esac
  # CrowdSec on this machine listens on 127.0.0.1 only. Rather than widen it,
  # run the containers on the host network so 127.0.0.1 is the host's.
  if [[ "$PROTEK_CROWDSEC" == remote ]]; then
    set_env "$ENV" COMPOSE_FILE compose.yml
  else
    set_env "$ENV" COMPOSE_FILE compose.yml:compose.hostnet.yml
  fi
  write_settings

  say "Building the Protek image (a few minutes the first time)"
  docker compose build

  if ! docker compose run --rm --no-deps -T protek sh -c 'grep -qs "^APP_PASSWORD_HASH=." /data/.env'; then
    say "Creating the admin account — the password and TOTP below are shown ONCE"
    docker compose run --rm --no-deps -T protek python scripts/setup_admin.py --username "$PROTEK_ADMIN_USER"
    if (( TTY )); then
      read -rp "  Saved the password and added the TOTP to your authenticator? Press Enter to continue. " _ </dev/tty || true
    fi
  fi

  say "Starting the stack"
  docker compose up -d --wait
  check_mikrotik timeout 30 docker compose exec -T protek python -c "$MT_CHECK"
}

if [[ "$PROTEK_METHOD" == docker ]]; then install_docker; else install_baremetal; fi

# ── Firewall ───────────────────────────────────────────────────────────────
# Opt-in, and it allows the port sshd really listens on — enabling ufw with
# only 22 open locks out anyone who runs SSH elsewhere.
if [[ "$PROTEK_UFW" == y ]]; then
  say "Turning on ufw"
  command -v ufw >/dev/null 2>&1 || apt-get install -y -qq ufw
  SSH_PORTS=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u)
  for p in ${SSH_PORTS:-22}; do ufw allow "$p/tcp"; done
  [[ "$PROTEK_ACCESS" != local ]] && ufw allow 80/tcp
  [[ "$PROTEK_ACCESS" == domain ]] && ufw allow 443/tcp
  ufw --force enable
elif [[ "$PROTEK_UFW" == active && "$PROTEK_ACCESS" == lan ]]; then
  note "ufw is already on — if port 80 isn't allowed yet: ufw allow 80/tcp"
elif [[ "$PROTEK_UFW" == active && "$PROTEK_ACCESS" == domain ]]; then
  note "ufw is already on — if ports 80/443 aren't allowed yet: ufw allow 80/tcp && ufw allow 443/tcp"
fi

# ── Done ───────────────────────────────────────────────────────────────────
case "$PROTEK_ACCESS" in
  local)
    URL_LINES="  On this machine:  http://127.0.0.1:8090
  From your laptop: ssh -L 8090:127.0.0.1:8090 <user>@<this machine>
                    then open http://localhost:8090" ;;
  lan)    URL_LINES="  Open: http://$LAN_IP  (from any device on your network)" ;;
  domain) URL_LINES="  Open: https://$PROTEK_DOMAIN" ;;
esac
if [[ "$PROTEK_METHOD" == docker ]]; then
  OPS="  Logs:      cd $PROTEK_DIR && docker compose logs -f protek
  Settings:  $ENV  (then: docker compose up -d)"
else
  OPS="  Service:   systemctl status protek   ·   journalctl -u protek -f
  Settings:  $ENV  (then: systemctl restart protek)"
fi

cat <<DONE

==============================================================
  Protek is installed — in dry-run.
==============================================================
$URL_LINES
  Log in with the admin password + TOTP code from above.

$OPS

  Next steps:
    1. Watch a few cycles on /mikrotik — the diff Protek would push.
    2. Add the drop rule on the router (docs/INSTALL.md → "Connecting MikroTik").
    3. Turn dry-run off in Settings → Dry run.
    4. Optional: CrowdSec Console — cscli console enroll <key>
    5. Read docs/USER_GUIDE.md
==============================================================

DONE
