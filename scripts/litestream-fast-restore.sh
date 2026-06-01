#!/bin/bash
# litestream-fast-restore.sh — phase 87 RTO speedup.
#
# Litestream's `restore` subcommand fetches LTX files from the replica
# one-at-a-time over the replica's transport, walks each through its
# pipeline, and applies them in order. With an SFTP replica this is
# painfully slow: each round-trip is ~50 ms over WireGuard and even a
# modest replica holds tens of small files. Measured baseline: ~660 KB/min
# — a 629 MB DB extrapolates to ~16 hours. Far outside the phase 64
# 5-minute RTO target.
#
# This script does the same restore in two stages:
#
#   1. **Parallel SFTP fetch** (`sftp get -r`) of the entire replica to
#      a local tmpfs cache. Modern OpenSSH SFTP pipelines well — we
#      observed 3.3 MB/s vs 11 KB/s for litestream's own walker (~200x).
#
#   2. **Local restore** from a `file://` replica URL pointing at the
#      cache. Litestream's apply phase against a local filesystem has
#      no per-file network round-trips, so it runs at disk-I/O speed.
#
# Litestream is stopped during the fetch to ensure the cache is a
# consistent point-in-time snapshot — live writes during fetch can
# produce inconsistent LTX chains.
#
# Usage:
#   sudo /var/www/Protek/scripts/litestream-fast-restore.sh [output_path]
#
# Default output_path: /var/www/Protek/protek.db.restored
# (operator promotes it into place after verification).
#
# Limits: assumes the SFTP replica path matches /etc/litestream.yml
# (sftp://litestream@<vps-b-wg-ip>:22/home/litestream/protek by default).
# Override via $LITESTREAM_REPLICA_URL and $SFTP_FETCH_PATH if needed.

set -euo pipefail

DB=/var/www/Protek/protek.db
OUT=${1:-/var/www/Protek/protek.db.restored}
CACHE=/dev/shm/litestream-fast-restore-cache
SFTP_KEY=${SFTP_KEY:-/etc/litestream/id_ed25519}
SFTP_DEST=${SFTP_DEST:-litestream@<vps-b-wg-ip>}
SFTP_PATH=${SFTP_PATH:-/home/litestream/protek}
LOG_TAG=litestream-fast-restore

t_total=$(date +%s)

log() {
    local msg="$1"
    logger -t "$LOG_TAG" "$msg"
    echo "[fast-restore] $msg"
}

# 1. Stop litestream so the replica is a consistent snapshot during fetch.
log "stopping litestream for consistent fetch"
t0=$(date +%s)
systemctl stop litestream
log "litestream stopped (took $(( $(date +%s) - t0 ))s)"

# 2. Parallel SFTP fetch of the replica to tmpfs.
log "fetching replica via SFTP (recursive)"
t0=$(date +%s)
rm -rf "$CACHE"
mkdir -p "$CACHE"
sftp -i "$SFTP_KEY" -o StrictHostKeyChecking=no "$SFTP_DEST" <<EOF >/dev/null 2>&1
lcd $CACHE
get -r $SFTP_PATH
EOF
size=$(du -sh "$CACHE" | awk '{print $1}')
log "fetched $size to $CACHE in $(( $(date +%s) - t0 ))s"

# 3. Restart litestream so replication resumes immediately.
log "restarting litestream"
systemctl start litestream

# 4. Restore from the local cache. The directory under $CACHE matches the
#    remote path's last component (e.g. .../protek/), so the file:// URL
#    points at that.
local_replica_root="$CACHE/$(basename "$SFTP_PATH")"
log "restoring from file://$local_replica_root → $OUT"
t0=$(date +%s)
rm -f "$OUT"
if ! litestream restore -o "$OUT" "file://$local_replica_root" 2>&1 \
        | tee /tmp/${LOG_TAG}.log; then
    log "ERROR: restore failed — see /tmp/${LOG_TAG}.log"
    log "common cause: replica chain has a corrupt LTX file. Inspect with"
    log "  litestream ltx file://$local_replica_root"
    log "Recovery: rebase the replica by stopping litestream, rm'ing the"
    log "remote path, and restarting. The next snapshot creates a clean chain."
    exit 1
fi
log "restored in $(( $(date +%s) - t0 ))s"

# 5. Integrity check.
if command -v sqlite3 >/dev/null 2>&1; then
    log "running PRAGMA integrity_check"
    integ=$(sqlite3 "$OUT" "PRAGMA integrity_check;" | head -1)
    log "integrity_check: $integ"
    if [ "$integ" != "ok" ]; then
        log "WARNING: restored DB failed integrity check"
        exit 2
    fi
fi

size_out=$(du -h "$OUT" | awk '{print $1}')
log "DONE: $OUT ($size_out) total wall time $(( $(date +%s) - t_total ))s"
log "promote with: systemctl stop protek && mv $OUT $DB && systemctl start protek"
