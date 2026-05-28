# Native packages — phase 71

Closes phase 71 (`.deb` + `.rpm`). The bare-metal `install.sh` and the
Docker image (phase 95) remain the primary deploy paths; native
packages are for operators whose policy mandates dpkg/rpm or who run
configuration management (Ansible, Salt, Puppet) that talks to the
host package manager directly.

## Layout

```
packaging/
├── build.sh            # one-stop builder — `./packaging/build.sh [deb|rpm]`
├── debian/             # debhelper / dh-python deb scaffolding
│   ├── control
│   ├── changelog
│   ├── rules
│   ├── install
│   ├── postinst
│   ├── prerm
│   ├── protek.service
│   └── source/format
└── rpm/
    └── protek.spec
```

## Build

### .deb (Debian 12+ / Ubuntu 22.04+)

```bash
sudo apt install -y build-essential debhelper dh-python \
                    python3-all python3-setuptools devscripts
./packaging/build.sh deb
```

Output: `../protek_2.1.0-1_all.deb`

### .rpm (Fedora / RHEL / Rocky / Alma)

```bash
sudo dnf install -y rpm-build rpmdevtools systemd-rpm-macros
./packaging/build.sh rpm
```

Output: `~/rpmbuild/RPMS/noarch/protek-2.1.0-1.*.noarch.rpm`

## Install

### Debian/Ubuntu

```bash
sudo apt install ./protek_2.1.0-1_all.deb
sudo -u protek /usr/lib/protek/venv/bin/python \
    /usr/share/protek/scripts/setup_admin.py --username admin
# Edit /etc/protek/.env (MT host, CrowdSec bouncer key, etc.)
sudo systemctl start protek
```

### Fedora/RHEL

```bash
sudo dnf install ./protek-2.1.0-1.*.noarch.rpm
sudo -u protek /usr/lib64/protek/venv/bin/python \
    /usr/share/protek/scripts/setup_admin.py --username admin
sudo systemctl start protek
```

## Layout on disk after install

| Path | Owner | Purpose |
|------|-------|---------|
| `/usr/share/protek/` | root | Code + templates + static + scripts + docs (read-only) |
| `/usr/lib/protek/venv/` (deb) or `/usr/lib64/protek/venv/` (rpm) | root | Python venv with pinned deps |
| `/etc/protek/.env` | root:protek 0640 | All secrets + config |
| `/var/lib/protek/` | protek:protek 0750 | `protek.db`, `.protek.db-litestream/` |
| `/var/log/protek/` | protek:protek 0750 | Reserved for ad-hoc logs (gunicorn writes to stdout, journal captures) |
| `/lib/systemd/system/protek.service` | root | systemd unit |

## What the postinst does

1. Creates the `protek` system user/group if absent (idempotent).
2. Creates `/var/lib/protek`, `/var/log/protek`, `/etc/protek`.
3. Seeds `/etc/protek/.env` from the template if missing.
4. Builds the Python venv at `/usr/lib/protek/venv` (one-time, skipped
   on upgrades unless missing).
5. `systemctl daemon-reload` + enables the unit (does NOT start —
   `.env` is empty by default; starting would fail).

## Why noarch despite a Python venv

The package itself is pure Python — there's no binary content to
arch-lock. The venv built in postinst uses the host's `python3`
binary, so it gets the right ABI for whatever arch the host runs.
Result: one `.deb` works on amd64 + arm64 hosts, one `.rpm` works on
x86_64 + aarch64.

## Not in the package

- **CrowdSec.** `Recommends:` in the control file; install separately via
  the official CrowdSec APT/DNF repo. Protek doesn't bundle scenarios.
- **nginx site config + TLS.** The package suggests nginx as a
  dependency but doesn't drop a site or run certbot — those are
  deployment-specific. Use `install.sh` if you want the full bare-metal
  flow, or `docker compose` for Caddy auto-TLS.
- **MikroTik bootstrap script.** Available at the live URL
  `/bouncers/mt-bootstrap` after first start (phase 94).

## Limitations

- The deb's `architecture: all` means the venv is built per-host. If you
  build the venv on host A and rsync to host B with a different Python
  patch version, native extensions in dependencies (bcrypt, lxml if
  added later) may break. Always let postinst build the venv on each
  target.
- Upgrades retain `/etc/protek/.env` and `/var/lib/protek/protek.db`.
  A `dpkg --purge protek` removes the user but explicitly *keeps* the
  config + state for re-install — to wipe, also remove
  `/etc/protek/` and `/var/lib/protek/` manually.
