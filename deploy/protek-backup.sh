#!/usr/bin/env bash
# Protek nightly backup — install as /usr/local/bin/protek-backup.sh, run by
# protek-backup.timer (deploy/protek-backup.{service,timer}).
#
# Each run:
#   1. backup.run_backup("daily") — encrypted (AES-256-GCM) bundle of protek.db
#      + .env + custom scenarios, written to /var/backups/protek/daily/, and, when
#      an off-box bucket is set up (Backup (off-box) page, or BACKUP_S3_* in
#      .env), copied there too with the size checked and the same retention.
#      An off-box failure is reported but doesn't fail the local backup.
#   2. backup.restore_test() — decrypt the newest local bundle, PRAGMA
#      integrity_check, core tables present.
#   3. Weekly: the same restore test on the newest off-box copy.
#
# Exit codes: 1 backup failed, 2 restore-test failed, 3 off-box copy or its
# restore-test failed (the local backup is fine).
set -euo pipefail

cd /var/www/Protek

/var/www/Protek/venv/bin/python - <<'PY'
import sys
from dotenv import load_dotenv
load_dotenv("/var/www/Protek/.env")

import backup

run = backup.run_backup("daily")
if run.get("status") != "ok":
    print(f"protek-backup: daily FAILED: {run.get('error', 'unknown')}", file=sys.stderr)
    sys.exit(1)

test = backup.restore_test()
if test.get("status") != "ok":
    print(f"protek-backup: daily stored but restore-test FAILED: {test.get('error', 'unknown')}", file=sys.stderr)
    sys.exit(2)

print(f"protek-backup: ok {run['dest']} ({run['size_bytes']} bytes, verified)")

off = run.get("offsite")
if off is None:
    print("protek-backup: off-box copy not set up")
    sys.exit(0)
if off.get("status") != "ok":
    print(f"protek-backup: off-box copy FAILED (local copy is fine): {off.get('error', 'unknown')}", file=sys.stderr)
    sys.exit(3)
print(f"protek-backup: off-box ok {off['dest']} ({off['size_bytes']} bytes, size checked)")

if backup.offsite_due():
    t = backup.offsite_restore_test()
    if t.get("status") != "ok":
        print(f"protek-backup: off-box restore-test FAILED: {t.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(3)
    print(f"protek-backup: off-box restore-test ok {t.get('dest', '')}")
PY
