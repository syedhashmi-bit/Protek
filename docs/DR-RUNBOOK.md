# Protek — Disaster Recovery Runbook

> **Audience:** the operator (you) at 03:00 with a broken VPS.
> **Goal:** known good state restored in under 30 min for any scenario.
>
> Every section follows: **symptom → impact → recovery steps → verify → notify**.
> Quarterly drill log lives at `/admin/dr-drill` (writes to audit_log).

---

## 0. Pre-flight (do this once, not in an incident)

- [ ] `BACKUP_PASSPHRASE` written down in a password manager. **Without it, all
      bundles are unreadable.** Don't store it only on the VPS being backed up.
- [ ] Off-box backup destination reachable from a fresh machine (B2 / S3 console
      login works, you know the bucket name).
- [ ] A second machine (laptop, secondary VPS) with `boto3`, `cryptography`,
      `python3.12`, `sqlite3` ready to decrypt + inspect a bundle if needed.
- [ ] DNS provider login bookmarked (Hetzner / Cloudflare / wherever
      `protek.syedhashmi.trade` resolves from).
- [ ] MikroTik router admin password retrievable from the same password manager
      that holds `BACKUP_PASSPHRASE`.

---

## 1. VPS lost (Hetzner outage, accidentally destroyed, suspended)

**Symptom:** `https://protek.syedhashmi.trade` returns ConnectionError /
SSH fails. Hetzner dashboard shows server stopped/destroyed.

**Impact:** dashboard unavailable, but **the MikroTik router keeps enforcing
the last address-list it received** — existing bans stay in force, new bans
stop appearing. CrowdSec on this VPS also went away, so no new detections
either.

**Recovery (target: <30 min):**

1. **Provision a fresh Ubuntu 22.04+ VPS** (Hetzner CPX21 or larger).
   Note the new IP.
2. **Repoint DNS**: `protek.syedhashmi.trade` A record → new IP. TTL the
   suite uses is 300s.
3. **Install base packages**:
   ```bash
   apt update && apt install -y python3.12-venv nginx certbot \
       python3-certbot-nginx sqlite3
   ```
4. **Install CrowdSec** (if you want the full local-detection stack restored;
   otherwise skip and run as bouncer-only):
   ```bash
   curl -s https://install.crowdsec.net | sudo sh
   apt install -y crowdsec
   ```
5. **Restore Protek code**:
   ```bash
   cd /var/www && git clone https://github.com/syedhashmi/Protek.git Protek
   cd Protek && python3.12 -m venv venv
   venv/bin/pip install -r requirements.txt
   ```
6. **Restore `.env` + `protek.db` from the latest backup bundle** (see §6
   "Restore a backup bundle to a fresh VPS" below).
7. **Restore systemd unit + nginx site**:
   ```bash
   # systemd
   cat > /etc/systemd/system/protek.service <<'EOF'
   [Unit]
   Description=Protek - CrowdSec to MikroTik bouncer + NOC dashboard
   After=network-online.target crowdsec.service
   Wants=network-online.target

   [Service]
   Type=simple
   User=root
   WorkingDirectory=/var/www/Protek
   ExecStart=/var/www/Protek/venv/bin/gunicorn -w 3 -b 127.0.0.1:8090 \
       --access-logfile - --error-logfile - app:app
   Restart=on-failure
   RestartSec=3s

   [Install]
   WantedBy=multi-user.target
   EOF
   systemctl daemon-reload && systemctl enable --now protek

   # nginx
   # Copy /etc/nginx/sites-available/protek from your bundle's env-extras
   # or re-create with the same shape as the pipsqueeze/atom sites.
   ```
8. **Re-issue TLS**:
   ```bash
   certbot --nginx -d protek.syedhashmi.trade
   ```

**Verify:**
- [ ] `curl https://protek.syedhashmi.trade/health` → 200 with `dry_run` matching
      your last setting.
- [ ] Login at the dashboard succeeds with the *same* TOTP (because the
      `users` table + `TOTP_SECRET` env var were restored).
- [ ] `/mikrotik` page shows current address-list (router never lost it).
- [ ] **Watch the next 60s** for `poller.last_at` to update on `/api/health`.

**Notify:**
- [ ] Disable any external alerting tied to the old IP (Discord / Telegram /
      uptime monitor).

---

## 2. SQLite DB corruption

**Symptom:** dashboard 500s; `journalctl -u protek` shows
`sqlite3.DatabaseError: database disk image is malformed` or
`PRAGMA integrity_check` returns anything but `ok`.

**Impact:** no UI, no reconcile cycles, MikroTik keeps last state.

**Current deployed shape** (live as of 2026-05-25): Litestream v0.5.x streaming
the WAL from VPS A to VPS B (`<vps-b-wg-ip>`) over the Traverse-managed WireGuard
tunnel via SFTP. Config: `/etc/litestream.yml`. Service:
`systemctl status litestream`. Replica path on VPS B:
`/home/litestream/protek/ltx/`. RPO observed in steady state: <2 seconds
(sync-interval=1s). RTO depends on DB size — see "Recovery time notes" below.

**Recovery (target: <5 min using the phase-87 fast-restore script):**

```bash
systemctl stop protek

# RECOMMENDED — fast-restore via parallel SFTP + local cache.
# ~3–5 min wall time on a 600 MB DB (vs ~16 hours for raw litestream restore).
# See "Why fast-restore" below.
sudo /var/www/Protek/scripts/litestream-fast-restore.sh /tmp/protek.db.restored

# After integrity_check passes:
mv /var/www/Protek/protek.db /var/www/Protek/protek.db.corrupt
mv /tmp/protek.db.restored /var/www/Protek/protek.db
chown -R root:root /var/www/Protek/protek.db*

# OR (if you must) the slow path — works but takes hours on a >500 MB DB:
# litestream restore -o /var/www/Protek/protek.db /var/www/Protek/protek.db

# If Litestream itself is broken — restore from the latest backup bundle
# (RPO = last daily, up to 24h):
cd /tmp && mkdir restore && cd restore
python3 /var/www/Protek/scripts/restore_backup.py \
    --bundle /path/to/protek-YYYYMMDDTHHMMSSZ.bin \
    --out /var/www/Protek/protek.db

systemctl start protek
```

### Why fast-restore (phase 87)

Litestream's built-in `restore` fetches LTX files one at a time over the
replica's transport and applies them. With SFTP over WireGuard each
round-trip is ~50 ms; a healthy replica holds ~100 small files; the walker
runs serially. Measured baseline: ~660 KB / min. A 629 MB protek.db
extrapolates to ~16 hours.

`scripts/litestream-fast-restore.sh` does the same work in two passes:

1. **Parallel SFTP fetch** (`sftp get -r`) of the entire replica to a
   `/dev/shm` cache. Pipelines naturally — measured 3.3 MB / s, ~200x
   faster than Litestream's walker.
2. **Local restore** from a `file://` URL pointing at the cache. The
   apply phase against a local filesystem runs at disk-I/O speed.

Litestream is stopped during the fetch so the cache is a point-in-time
consistent snapshot (live writes during fetch produce inconsistent LTX
chains).

### Replica corruption — recovery via rebase

If `litestream restore` errors with `decode page N: cannot close` /
`nonsequential page numbers` / `has size 0 bytes`, the LTX chain on the
replica is broken. **L1 always carries the same txn range as the L2
above it**, so 0-byte L2 files are cleaned automatically by
`/usr/local/bin/protek-wal-truncate.sh` every 5 min. But corruption at
the L9 (snapshot) level breaks restore entirely.

Recovery: rebase the replica from the current healthy local DB.

```bash
# 1. Confirm the local DB itself is healthy (it almost always is — only
#    the replica suffers from the stop-time SFTP truncation bug).
sqlite3 /var/www/Protek/protek.db 'PRAGMA integrity_check;'   # → ok

# 2. Wipe the broken replica and let Litestream baseline a clean chain.
systemctl stop litestream
sftp -i /etc/litestream/id_ed25519 litestream@<vps-b-wg-ip> <<EOF
rm -r /home/litestream/protek/ltx/0
rm -r /home/litestream/protek/ltx/1
rm -r /home/litestream/protek/ltx/2
rm -r /home/litestream/protek/ltx/3
rm -r /home/litestream/protek/ltx/9
EOF
systemctl start litestream

# 3. Watch the first snapshot land (default snapshot-interval=6h, but the
#    first one is immediate after a missing baseline).
journalctl -u litestream -f --since "1 minute ago"

# 4. After the baseline snapshot, the fast-restore script works again.
```

Lost when you rebase: the 720h retention window of point-in-time
recovery snapshots. Off-box nightly backups (phase 63) still cover
daily-grain PIT recovery.

**Point-in-time recovery** (e.g. "give me the DB as of 5 minutes before the
bad UPDATE statement landed"):

```bash
# Restore to a specific timestamp (UTC, RFC3339)
litestream restore -timestamp 2026-05-25T03:15:00Z \
    -o /var/www/Protek/protek.db.pit \
    /var/www/Protek/protek.db

# Or to a specific transaction ID — list available txids first
litestream snapshots /var/www/Protek/protek.db
litestream restore -txid 0000000000000010 \
    -o /var/www/Protek/protek.db.pit \
    /var/www/Protek/protek.db
```

**Verify:**
- [ ] `sqlite3 /var/www/Protek/protek.db 'PRAGMA integrity_check'` → `ok`.
- [ ] Login still works.
- [ ] `/api/sync/status` shows fresh reconcile cycle.

**Recovery time notes:**

Restore wall time scales with the *output DB size*, not the network. The
remote replica is small (~5 MB compressed LTX for our ~445 MB DB), but
Litestream has to materialize every page back into the local SQLite file,
which is bottlenecked by local fsync. Expect roughly 30s–2 min per 100 MB
of restored DB on typical NVMe-backed VPS storage. Tune `vm.dirty_*`
sysctls or restore to a tmpfs first and `mv` into place if you need to
beat 5-minute RTO on a multi-GB DB.

**Common pitfalls** (learned during the 2026-05-25 deployment):

1. **SSH host key algorithm** — Litestream's `host-key:` field must match
   the algorithm the remote sshd actually negotiates. OpenSSH defaults
   to ECDSA over ED25519. If you pin `ssh-ed25519 ...` and the server
   answers with `ecdsa-sha2-nistp256 ...`, Litestream rejects the
   handshake with `ssh: host key mismatch`. Get the right one via:
   ```bash
   ssh-keyscan -t ecdsa <vps-b-wg-ip>
   ```

2. **SFTP URL path is absolute, not relative to the user's home.**
   `sftp://litestream@<vps-b-wg-ip>:22/protek` tries to write at `/protek`
   (root) and fails with `permission denied`. Use the full path:
   `sftp://litestream@<vps-b-wg-ip>:22/home/litestream/protek`.

3. **DNS via the WG client config** — if Traverse's peer wizard set
   `DNS=` in `wg0.conf` to an internal-only resolver, apt/curl will
   fail with `Temporary failure resolving` after `wg-quick up`. Strip
   the `DNS=` line from the WG client config or set it to `1.1.1.1`.

4. **Service ordering** — Litestream tries to bind/connect at boot
   before WireGuard is up. Drop-in at
   `/etc/systemd/system/litestream.service.d/wg-dep.conf` adds
   `After=wg-quick@wg0.service` so it waits. Without this, the first
   sync attempts fail until the next polling cycle.

---

## 3. MikroTik router dies / replaced

**Symptom:** `/mikrotik` shows red panel; `mt_down` notifications fire;
sync_events rows pile up with `errors > 0`.

**Impact:** no edge enforcement — attackers can hit your services again.
Existing protek-owned address-list entries lost with the router.

**Recovery:**

1. **Bring up a replacement router** (or restore the existing one from RouterOS
   backup if you have one).
2. **Re-create the protek bouncer user** on the new router:
   ```
   /user group add name=protek-api policy=read,write,api
   /user add name=protek group=protek-api password=<new-strong-password>
   ```
3. **Re-create the address-list drop rules** (Protek doesn't own these):
   ```
   /ip firewall filter add chain=input  src-address-list=crowdsec action=drop comment="protek"
   /ip firewall filter add chain=forward src-address-list=crowdsec action=drop comment="protek"
   ```
4. **Update Protek's `.env`** (`MT_HOST`, `MT_USERNAME`, `MT_PASSWORD`).
   For multi-router (`bouncer_targets`), edit at `/bouncers/edit/<id>`.
5. `systemctl restart protek`. The next reconcile cycle re-pushes the **entire**
   active decision set as one bulk add — this is by design (the reconciler
   always diffs against actual snapshot).

**Verify:**
- [ ] `/mikrotik` shows green LAPI Active count ≈ MT address-list size.
- [ ] `/synthetic` test passes against the new router (run manually).

---

## 4. CrowdSec hub / community blocklists down

**Symptom:** `cscli hub list` errors; new community-list decisions stop arriving.

**Impact:** local CrowdSec scenarios still detect; only community-bootstrapped
blocks stop refreshing. Existing community decisions remain in LAPI until their
`until` expires.

**Recovery:** wait. Hub outages are rare and short. No action required by Protek
itself. If extended (>24h), pin the most recent community blocklist snapshot
manually:

```bash
# Pull the firehol_cruzit list to a local file, then add as a manual scope:
curl -o /tmp/firehol.list https://iplists.firehol.org/files/firehol_cruzit_web_attacks.netset
# (then either: rebuild as scenarios, or cscli decisions add --range for each line)
```

---

## 5. Cloudflare / external bouncer API rate-limit storm

**Symptom:** `bouncer_targets.last_error` shows `429` / `rate exceeded` for a
specific kind; `/perf` shows token bucket exhausted for that kind (Arc 11
phase 68).

**Impact:** that one bouncer falls behind; other bouncers unaffected; MikroTik
adapter (local API) unaffected.

**Recovery:**

1. Open `/perf`, identify which bucket is empty.
2. If it's a deliberate test of CF rate limits: nothing to do — token bucket
   will refill at the configured rate, reconcile catches up over the next
   N cycles.
3. If sustained: edit the per-kind bucket size in `/settings` (search for
   `ratelimit.<kind>.tokens_per_min`) — raise it if your CF plan allows, OR
   reduce it temporarily to back off harder.
4. As a last resort, disable the affected target at `/bouncers` until the
   storm passes.

---

## 6. Restore a backup bundle to a fresh VPS

The off-box bundles (`backup.py` / `/admin/backup-automation`) are encrypted
with `BACKUP_PASSPHRASE` and contain:

- `protek.db` — full SQLite snapshot
- `env` — verbatim copy of `.env`
- `scenarios/` — anything under `/etc/crowdsec/scenarios/`
- `manifest.json` — sha256 of each member

**Decrypt + extract manually** (if you don't have the convenience script):

```python
# /tmp/decrypt_bundle.py
import sys, os, hashlib, io, tarfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PROTEKBK"
passphrase = os.environ["BACKUP_PASSPHRASE"]
blob = open(sys.argv[1], "rb").read()
assert blob.startswith(MAGIC)
body = blob[8:]
salt, nonce, ct = body[:16], body[16:28], body[28:]
key = hashlib.scrypt(passphrase.encode(), salt=salt,
                    n=2**15, r=8, p=1, dklen=32, maxmem=128*1024*1024)
tar_bytes = AESGCM(key).decrypt(nonce, ct, None)
tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz").extractall(sys.argv[2])
print("extracted to", sys.argv[2])
```

```bash
mkdir /tmp/restored
BACKUP_PASSPHRASE='your-passphrase-here' \
    python3 /tmp/decrypt_bundle.py /path/to/bundle.bin /tmp/restored
ls /tmp/restored
# protek.db  env  scenarios/  manifest.json

# Then drop into place:
cp /tmp/restored/protek.db /var/www/Protek/protek.db
cp /tmp/restored/env        /var/www/Protek/.env
chmod 0600 /var/www/Protek/.env
mkdir -p /etc/crowdsec/scenarios
cp -r /tmp/restored/scenarios/* /etc/crowdsec/scenarios/ 2>/dev/null || true
```

---

## 7. Compromise / suspected key leak

**Symptom:** unfamiliar IPs in `/security` audit log; `/admin/tokens` shows a
token you didn't create; suspicious bouncer_targets rows.

**Impact:** depends on what leaked. Assume the worst until proven otherwise.

**Recovery:**

1. **Rotate everything**:
   ```bash
   cd /var/www/Protek
   venv/bin/python scripts/setup_admin.py --password "$(openssl rand -base64 24)" --rotate-totp-only
   # then re-pair TOTP from the printed otpauth URI
   ```
2. **Revoke all API tokens** at `/admin/tokens` (revoke button on each row).
3. **Re-issue the CrowdSec bouncer key**:
   ```bash
   cscli bouncers delete protek
   cscli bouncers add protek
   # paste new key into .env as CROWDSEC_BOUNCER_KEY
   ```
4. **Rotate router admin password** if MikroTik creds may have leaked. Update
   `.env` / `bouncer_targets`.
5. **Rotate `BACKUP_PASSPHRASE`** and re-run a backup (the old bundles remain
   readable only by the old passphrase — that's fine; what matters is the
   *next* bundle).
6. **Rotate `SECRET_KEY`** (signs Flask sessions — invalidates everyone):
   ```bash
   python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" \
       >> /var/www/Protek/.env
   # delete the OLD SECRET_KEY line manually after appending
   systemctl restart protek
   ```
7. **Audit `audit_log`** for the last 90 days: `sqlite3 protek.db "SELECT * FROM audit_log ORDER BY id DESC LIMIT 500"`.

---

## 8. Quarterly drill template

Run this checklist once a quarter. Time each step; if any exceeds the target,
investigate and update this runbook with what actually happened.

| Drill | Target | Notes |
|-------|--------|-------|
| Restore latest bundle to a scratch VPS (don't repoint DNS) | <30 min | §1 + §6 |
| Verify backup bundle decrypts + integrity_check passes | <5 min | `/admin/backup-automation` → "Run restore-test" |
| Synthetic ban test passes against current live bouncers | <2 min | `/synthetic` → "Run test now" |
| Litestream restore + Protek start to fresh DB | <5 min | §2 with litestream |
| Notification channels reach you (test each) | <1 min | `/notifications` → "Test" per channel |
| MikroTik replacement re-push from cold | <10 min | Don't actually swap router; redirect MT_HOST to a test instance |

When complete, mark the drill done at `/admin/dr-drill` — appends a row to
`audit_log` with timestamp + per-row pass/fail. The audit log is append-only,
so the drill history is tamper-evident.
