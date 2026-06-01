#!/bin/bash
# protek-wal-truncate.sh — bound Litestream-blocked WAL growth + repair
# corrupt-on-stop LTX files.
#
# Install to /usr/local/bin/protek-wal-truncate.sh + the matching
# protek-wal-truncate.service / .timer units under /etc/systemd/system/.
#
# 1. WAL truncation
#    Litestream v0.5 holds a continuous WAL reader to replicate frames as
#    they land. SQLite can checkpoint frames into the main DB while that
#    reader is active, but it cannot truncate the WAL FILE — slots stay
#    claimed by the reader, so new transactions append rather than
#    overwrite, and the file grows unboundedly. Observed:
#    5 MB → 25 GB → ENOSPC in ~8 hours.
#    The fix is to briefly release the reader (stop litestream), TRUNCATE
#    the WAL (shrinks the file to ~0 bytes), and restart the daemon.
#
# 2. Stop-time corruption repair (added 2026-05-26)
#    When systemctl stops litestream mid-L2-compaction, the destination LTX
#    file on the replica can land as 0 bytes — the SFTP upload started but
#    didn't finish before SIGTERM drained. Litestream's restore tool then
#    errors with "has size 0 bytes (minimum 100)" instead of falling back
#    to the equivalent L1 file (which always has the same range intact).
#    We saw 3 such files in 24 h on a single host.
#    After each truncate cycle, scan the remote replica for 0-byte LTX
#    files and rm them. Safe — L1 always has the same txn range and
#    Litestream's restore will fall through to it once the broken L2 is
#    gone.
#
# Runs as a systemd timer every 5 minutes. Brief replication pause; RPO
# stays under the 60s phase-64 spec.

set -euo pipefail

# All paths/destinations are env-overridable so this script is portable and
# carries no host-specific addresses. Set these in an EnvironmentFile for the
# systemd unit (see protek-wal-truncate.service), e.g. /etc/protek/wal-truncate.env:
#   LITESTREAM_SFTP_DEST=litestream@replica-host
#   LITESTREAM_SFTP_PATH=/home/litestream/protek
# If LITESTREAM_SFTP_DEST is unset, the local WAL truncate still runs; the
# remote 0-byte-LTX repair step is skipped.
DB="${PROTEK_DB:-/var/www/Protek/protek.db}"
LOG_TAG=protek-wal-truncate
SFTP_KEY="${LITESTREAM_SFTP_KEY:-/etc/litestream/id_ed25519}"
SFTP_DEST="${LITESTREAM_SFTP_DEST:-}"
SFTP_PATH="${LITESTREAM_SFTP_PATH:-/home/litestream/protek}"

logger -t "$LOG_TAG" "starting WAL truncate cycle (WAL was $(stat -c %s "$DB-wal" 2>/dev/null || echo 0) bytes)"

# Stop Litestream — releases its WAL read lock so TRUNCATE can shrink the file.
systemctl stop litestream

# Best-effort: TRUNCATE merges remaining frames + shrinks file to 0.
# If sqlite3 isn't installed for some reason, the script keeps moving.
if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB" 'PRAGMA wal_checkpoint(TRUNCATE);' || true
fi

# Scan & repair: find any 0-byte LTX files on the remote replica and
# delete them. The corruption arises specifically when systemctl stop
# interrupts an in-flight L2 compaction upload (see header comment).
# L1 always has the same txn range intact, so deletion is non-destructive.
if [ -n "$SFTP_DEST" ] && [ -f "$SFTP_KEY" ]; then
    bad_files=$(sftp -i "$SFTP_KEY" \
                     -o StrictHostKeyChecking=no \
                     -o ConnectTimeout=10 \
                     -b - "$SFTP_DEST" <<EOF 2>/dev/null
ls -la $SFTP_PATH/ltx/0/
ls -la $SFTP_PATH/ltx/1/
ls -la $SFTP_PATH/ltx/2/
ls -la $SFTP_PATH/ltx/3/
EOF
    )
    # Extract paths of 0-byte .ltx files. ls -la rows look like:
    #   -rw-rw-r--    ? user user        0 May 26 01:10 /path/to/file.ltx
    empties=$(printf '%s\n' "$bad_files" \
              | awk '/^-/ && $5 == 0 && /\.ltx$/ { print $NF }')
    if [ -n "$empties" ]; then
        n=$(printf '%s\n' "$empties" | wc -l)
        logger -t "$LOG_TAG" "removing $n empty LTX file(s) from replica"
        rm_batch=$(printf 'rm %s\n' $empties)
        printf '%s\n' "$rm_batch" | sftp -i "$SFTP_KEY" \
                                          -o StrictHostKeyChecking=no \
                                          -o ConnectTimeout=10 \
                                          -b - "$SFTP_DEST" >/dev/null 2>&1 \
            || logger -t "$LOG_TAG" "warning: some empty-file removals failed"
    fi
fi

# Resume replication. Litestream picks up from its last successful LTX.
systemctl start litestream

logger -t "$LOG_TAG" "done (WAL now $(stat -c %s "$DB-wal" 2>/dev/null || echo 0) bytes)"
