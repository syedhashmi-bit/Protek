"""
backup.py — Arc 11 phase 63. Off-box backup automation.

Distinct from `bundle.py` (Arc 7 phase 41), which is an operator-driven
config-only export. This module produces a *full DB snapshot* on a schedule
and ships it off-box:

  - Daily snapshot via SQLite's online `.backup()` API (atomic, no lock).
  - Bundles snapshot + .env + /etc/crowdsec/scenarios/ into a tar.gz.
  - Encrypts the tarball with AES-256-GCM, key derived from a passphrase
    held in `.env` (`BACKUP_PASSPHRASE`) via scrypt(n=2^15) — same crypto
    primitives as bundle.py.
  - Uploads via a pluggable backend: LocalBackend (default,
    /var/backups/protek/) or S3Backend (Backblaze B2 / AWS S3 / MinIO,
    selected by `backup.backend = s3` in settings + credentials in .env).
  - Retention: keeps last N daily (default 30) + N monthly (default 12).
    The first daily of the month is promoted to a "monthly" pin so it
    survives daily eviction.
  - Restore-test: weekly, downloads the latest bundle, decrypts in a temp
    dir, runs `PRAGMA integrity_check` on the snapshot, deletes the temp
    dir. Confirms the backup is restorable without touching production.
  - `backup_runs` table journals every run (daily / monthly / test) with
    status + size + error.

Why a separate module from bundle.py: the threat models differ. bundle.py
optimises for "I'm migrating to a fresh VPS, give me back my CONFIG without
my decision history". backup.py optimises for "the VPS is gone, I need the
full DB back including every decision and audit row I had". Both are useful;
neither replaces the other.

Failure mode design: every run records to `backup_runs` even when it fails,
and fires the `backup_failed` notification event. Silent backup loss is the
worst failure mode — better to spam the operator on every cycle than to
fail closed.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import sqlite3
import tarfile
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from db import DB_PATH, get_conn, get_setting, set_setting

log = logging.getLogger("protek.backup")

MAGIC = b"PROTEKBK"  # distinct from bundle.py's PROTEK01 so file types don't mix
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

DEFAULT_LOCAL_PATH = "/var/backups/protek"
SCENARIOS_PATH = Path("/etc/crowdsec/scenarios")
ENV_PATH = Path(__file__).resolve().parent / ".env"


# ── envelope crypto ─────────────────────────────────────────────────────────

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                          dklen=KEY_LEN, maxmem=128 * 1024 * 1024)


def encrypt(plaintext: bytes, passphrase: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ct


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("not a protek backup bundle (bad magic)")
    body = blob[len(MAGIC):]
    salt, nonce, ct = body[:SALT_LEN], body[SALT_LEN:SALT_LEN+NONCE_LEN], body[SALT_LEN+NONCE_LEN:]
    key = _derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"decrypt failed (wrong passphrase?): {e}") from e


# ── snapshot building ───────────────────────────────────────────────────────

def _sqlite_snapshot(dest_path: Path) -> None:
    """Online .backup() copy of protek.db — atomic, no read lock on prod."""
    src = sqlite3.connect(str(DB_PATH), timeout=30.0)
    try:
        dst = sqlite3.connect(str(dest_path))
        try:
            src.backup(dst)  # one-shot full copy
        finally:
            dst.close()
    finally:
        src.close()


def _gather_scenarios() -> list[tuple[str, bytes]]:
    """Return [(arcname, bytes)] for every *.yaml under /etc/crowdsec/scenarios."""
    out = []
    if not SCENARIOS_PATH.exists():
        return out
    try:
        for p in SCENARIOS_PATH.rglob("*.yaml"):
            try:
                rel = p.relative_to(SCENARIOS_PATH)
                out.append((f"scenarios/{rel}", p.read_bytes()))
            except Exception as e:  # noqa: BLE001
                log.debug("scenario read failed for %s: %s", p, e)
    except Exception as e:  # noqa: BLE001
        log.debug("scenario walk failed: %s", e)
    return out


def build_snapshot_blob(passphrase: str) -> tuple[bytes, dict[str, Any]]:
    """Build the encrypted bundle. Returns (ciphertext, manifest)."""
    with tempfile.TemporaryDirectory(prefix="protek-bk-") as tmp:
        tmpd = Path(tmp)
        snap = tmpd / "protek.db"
        _sqlite_snapshot(snap)

        files: list[tuple[str, bytes]] = []
        snap_bytes = snap.read_bytes()
        files.append(("protek.db", snap_bytes))
        if ENV_PATH.exists():
            try:
                files.append(("env", ENV_PATH.read_bytes()))
            except Exception as e:  # noqa: BLE001
                log.warning("could not include .env: %s", e)
        files.extend(_gather_scenarios())

        manifest = {
            "version": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hostname": os.uname().nodename,
            "files": [
                {"name": n, "bytes": len(b),
                 "sha256": hashlib.sha256(b).hexdigest()}
                for n, b in files
            ],
        }
        files.insert(0, ("manifest.json",
                         json.dumps(manifest, indent=2).encode()))

        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w:gz") as tar:
            for arcname, blob in files:
                info = tarfile.TarInfo(name=arcname)
                info.size = len(blob)
                info.mtime = int(datetime.now(timezone.utc).timestamp())
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(blob))
        tar_bytes = tar_buf.getvalue()

    return encrypt(tar_bytes, passphrase), manifest


# ── storage backends ────────────────────────────────────────────────────────

class BackupBackend(ABC):
    name = "abstract"

    @abstractmethod
    def put(self, key: str, data: bytes) -> str:
        """Store `data` under `key`. Return a backend-local URI we record."""

    @abstractmethod
    def get(self, key: str) -> bytes:
        ...

    @abstractmethod
    def list_keys(self, prefix: str = "") -> list[str]:
        ...

    @abstractmethod
    def delete(self, key: str) -> None:
        ...


class LocalBackend(BackupBackend):
    name = "local"

    def __init__(self, base: str | Path = DEFAULT_LOCAL_PATH):
        self.base = Path(base)
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)

    def put(self, key: str, data: bytes) -> str:
        p = self.base / key
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        p.write_bytes(data)
        os.chmod(p, 0o600)
        return f"file://{p}"

    def get(self, key: str) -> bytes:
        return (self.base / key).read_bytes()

    def list_keys(self, prefix: str = "") -> list[str]:
        if not self.base.exists():
            return []
        out = []
        for p in self.base.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(self.base))
                if rel.startswith(prefix):
                    out.append(rel)
        return sorted(out)

    def delete(self, key: str) -> None:
        try:
            (self.base / key).unlink(missing_ok=True)
        except Exception as e:  # noqa: BLE001
            log.debug("local delete swallowed: %s", e)


class S3Backend(BackupBackend):
    name = "s3"

    def __init__(self):
        try:
            import boto3  # type: ignore  # noqa: F401
        except ImportError as e:
            raise RuntimeError("boto3 not installed — `pip install boto3`") from e
        import boto3
        endpoint = _envstr("BACKUP_S3_ENDPOINT") or None  # B2/MinIO; omit for AWS
        region = _envstr("BACKUP_S3_REGION") or "us-east-1"
        self.bucket = _envstr("BACKUP_S3_BUCKET")
        if not self.bucket:
            raise RuntimeError("BACKUP_S3_BUCKET not set")
        key = _envstr("BACKUP_S3_KEY")
        secret = _envstr("BACKUP_S3_SECRET")
        if not (key and secret):
            raise RuntimeError("BACKUP_S3_KEY / BACKUP_S3_SECRET not set")
        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=key,
            aws_secret_access_key=secret,
        )

    def put(self, key: str, data: bytes) -> str:
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=data,
                           ServerSideEncryption="AES256")
        return f"s3://{self.bucket}/{key}"

    def get(self, key: str) -> bytes:
        obj = self.s3.get_object(Bucket=self.bucket, Key=key)
        return obj["Body"].read()

    def list_keys(self, prefix: str = "") -> list[str]:
        out: list[str] = []
        token = None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": prefix}
            if token:
                kw["ContinuationToken"] = token
            resp = self.s3.list_objects_v2(**kw)
            for it in resp.get("Contents", []) or []:
                out.append(it["Key"])
            if not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")
        return sorted(out)

    def delete(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=key)


def _envstr(name: str) -> str:
    return (os.environ.get(name, "") or "").split("#", 1)[0].strip()


def get_backend() -> BackupBackend:
    kind = (get_setting("backup.backend") or "local").lower()
    if kind == "s3":
        return S3Backend()
    base = get_setting("backup.local_path") or DEFAULT_LOCAL_PATH
    return LocalBackend(base)


# ── runs journal ────────────────────────────────────────────────────────────

def _ensure_runs_table() -> None:
    conn = get_conn()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_runs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                kind          TEXT NOT NULL,
                started_at    TEXT NOT NULL,
                completed_at  TEXT DEFAULT NULL,
                status        TEXT NOT NULL DEFAULT 'running',
                size_bytes    INTEGER DEFAULT 0,
                dest          TEXT DEFAULT '',
                backend       TEXT DEFAULT '',
                error         TEXT DEFAULT ''
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_runs_started "
                     "ON backup_runs (started_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_runs_kind "
                     "ON backup_runs (kind, started_at)")
    finally:
        conn.close()


def _record_start(kind: str) -> int:
    _ensure_runs_table()
    conn = get_conn()
    try:
        cur = conn.execute(
            "INSERT INTO backup_runs (kind, started_at, status) VALUES (?, ?, 'running')",
            (kind, datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid
    finally:
        conn.close()


def _record_finish(rid: int, status: str, *, size: int = 0, dest: str = "",
                   backend: str = "", error: str = "") -> None:
    conn = get_conn()
    try:
        conn.execute(
            """
            UPDATE backup_runs
               SET completed_at = ?, status = ?, size_bytes = ?, dest = ?,
                   backend = ?, error = ?
             WHERE id = ?
            """,
            (datetime.now(timezone.utc).isoformat(), status, int(size or 0),
             dest, backend, error[:400], rid),
        )
    finally:
        conn.close()


def list_runs(limit: int = 30) -> list[dict[str, Any]]:
    _ensure_runs_table()
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM backup_runs ORDER BY id DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def latest_successful() -> dict[str, Any] | None:
    _ensure_runs_table()
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM backup_runs "
            "WHERE status = 'ok' AND kind IN ('daily','monthly','manual') "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ── run flows ───────────────────────────────────────────────────────────────

def _key_for(kind: str, ts: datetime) -> str:
    return f"{kind}/protek-{ts.strftime('%Y%m%dT%H%M%SZ')}.bin"


def _passphrase_or_die() -> str:
    p = _envstr("BACKUP_PASSPHRASE")
    if not p:
        raise RuntimeError("BACKUP_PASSPHRASE not set in .env")
    if len(p) < 12:
        raise RuntimeError("BACKUP_PASSPHRASE too short (need ≥12 chars)")
    return p


def _notify_failed(kind: str, err: str) -> None:
    try:
        import notifications
        notifications.send(
            "sync_error",
            f"Backup ({kind}) failed: {err[:200]}",
            subject=f"[Protek] Backup {kind} failed",
        )
    except Exception:  # noqa: BLE001
        pass
    try:
        import siem
        siem.ship("backup.failed", {"kind": kind, "error": err[:400]}, severity=3)
    except Exception:  # noqa: BLE001
        pass


def run_backup(kind: str = "daily") -> dict[str, Any]:
    """Build + ship a backup. Returns the run row dict."""
    rid = _record_start(kind)
    try:
        passphrase = _passphrase_or_die()
        backend = get_backend()
        blob, manifest = build_snapshot_blob(passphrase)
        ts = datetime.now(timezone.utc)
        key = _key_for(kind, ts)
        dest = backend.put(key, blob)
        _record_finish(rid, "ok", size=len(blob), dest=dest, backend=backend.name)
        if kind == "daily":
            set_setting("backup.last_daily_at", ts.isoformat())
        elif kind == "monthly":
            set_setting("backup.last_monthly_at", ts.isoformat())
        set_setting("backup.last_run_id", str(rid))
        log.info("backup %s ok: %s (%d bytes, %d files)",
                 kind, dest, len(blob), len(manifest["files"]))
        try:
            apply_retention(backend)
        except Exception as e:  # noqa: BLE001
            log.warning("retention sweep failed: %s", e)
        try:
            import siem
            siem.ship("backup.completed",
                      {"kind": kind, "size": len(blob),
                       "dest": dest, "files": len(manifest["files"])},
                      severity=6)
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        _record_finish(rid, "failed", error=msg)
        log.exception("backup %s failed: %s", kind, msg)
        _notify_failed(kind, msg)
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM backup_runs WHERE id = ?", (rid,)).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def apply_retention(backend: BackupBackend | None = None) -> dict[str, int]:
    backend = backend or get_backend()
    daily_keep = int(get_setting("backup.daily_keep") or "30")
    monthly_keep = int(get_setting("backup.monthly_keep") or "12")
    removed = {"daily": 0, "monthly": 0, "test": 0}
    for prefix, keep in (("daily/", daily_keep),
                        ("monthly/", monthly_keep),
                        ("test/", 7)):
        keys = backend.list_keys(prefix=prefix)
        if len(keys) > keep:
            # Sorted ascending by name → oldest first (timestamps in filenames).
            for k in keys[:-keep]:
                backend.delete(k)
                removed[prefix.rstrip("/")] += 1
    return removed


def restore_test() -> dict[str, Any]:
    """Download latest backup, decrypt, verify SQLite integrity. No import."""
    rid = _record_start("test")
    try:
        passphrase = _passphrase_or_die()
        backend = get_backend()
        # Look across daily / monthly / manual prefixes — most recent wins.
        candidates = []
        for prefix in ("daily/", "monthly/", "manual/"):
            candidates.extend(backend.list_keys(prefix=prefix))
        if not candidates:
            raise RuntimeError("no backups present to test")
        latest = max(candidates)  # filenames are ISO-ish so lexical max = newest
        blob = backend.get(latest)
        tar_bytes = decrypt(blob, passphrase)
        with tempfile.TemporaryDirectory(prefix="protek-rt-") as tmp:
            tmpd = Path(tmp)
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
                # Safe-extract: reject absolute or parent-traversing arcnames.
                for m in tar.getmembers():
                    if m.name.startswith("/") or ".." in Path(m.name).parts:
                        raise RuntimeError(f"unsafe tar arcname: {m.name}")
                tar.extractall(tmpd)
            snap = tmpd / "protek.db"
            if not snap.exists():
                raise RuntimeError("bundle missing protek.db")
            c = sqlite3.connect(str(snap))
            try:
                result = c.execute("PRAGMA integrity_check").fetchone()[0]
                if result != "ok":
                    raise RuntimeError(f"integrity_check failed: {result}")
                # Sanity: there should be at least the settings + decisions
                # tables. Counts are informational; presence is what we check.
                tables = {r[0] for r in c.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()}
                if "settings" not in tables or "decisions" not in tables:
                    raise RuntimeError("bundle missing core tables")
            finally:
                c.close()
        _record_finish(rid, "ok", size=len(blob),
                       dest=f"verified:{latest}", backend=backend.name)
        set_setting("backup.last_test_at", datetime.now(timezone.utc).isoformat())
        set_setting("backup.last_test_ok", "1")
        log.info("restore-test ok: %s (%d bytes)", latest, len(blob))
        try:
            import siem
            siem.ship("backup.restore_test_ok",
                      {"source": latest, "size": len(blob)}, severity=6)
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        _record_finish(rid, "failed", error=msg)
        set_setting("backup.last_test_ok", "0")
        log.exception("restore-test failed: %s", msg)
        _notify_failed("restore-test", msg)
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM backup_runs WHERE id = ?", (rid,)).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


# ── scheduler hook (called from poller) ─────────────────────────────────────

def maybe_run_scheduled() -> None:
    """Cheap to call every cycle. Internally no-ops until due."""
    if (get_setting("backup.enabled") or "0") != "1":
        return
    now = datetime.now(timezone.utc)

    # Daily: due if ≥24h since last successful daily.
    last_daily = get_setting("backup.last_daily_at")
    daily_due = True
    if last_daily:
        try:
            d = datetime.fromisoformat(last_daily.replace("Z", "+00:00"))
            daily_due = (now - d) >= timedelta(hours=24)
        except Exception:  # noqa: BLE001
            daily_due = True

    # Monthly: due if ≥28d since last monthly (also bootstrap if never run
    # and it's the first of the month).
    last_monthly = get_setting("backup.last_monthly_at")
    monthly_due = False
    if not last_monthly:
        monthly_due = now.day == 1
    else:
        try:
            d = datetime.fromisoformat(last_monthly.replace("Z", "+00:00"))
            monthly_due = (now - d) >= timedelta(days=28)
        except Exception:  # noqa: BLE001
            monthly_due = True

    # Run monthly first if both due (so it doesn't double-bill the snapshot
    # work — the daily that would have run today gets skipped because the
    # monthly is "fresher").
    if monthly_due:
        run_backup("monthly")
        set_setting("backup.last_daily_at",
                    datetime.now(timezone.utc).isoformat())  # treat as today's daily too
    elif daily_due:
        run_backup("daily")

    # Restore-test: weekly. Skip if no successful backup yet.
    last_test = get_setting("backup.last_test_at")
    test_due = False
    if not last_test:
        # Don't run test until we have *something* to verify.
        if latest_successful():
            test_due = True
    else:
        try:
            d = datetime.fromisoformat(last_test.replace("Z", "+00:00"))
            test_due = (now - d) >= timedelta(days=7)
        except Exception:  # noqa: BLE001
            test_due = True
    if test_due:
        restore_test()


# ── status surface for the page ─────────────────────────────────────────────

def status() -> dict[str, Any]:
    _ensure_runs_table()
    enabled = (get_setting("backup.enabled") or "0") == "1"
    kind = (get_setting("backup.backend") or "local").lower()
    passphrase_set = bool(_envstr("BACKUP_PASSPHRASE"))

    backend_ready = False
    backend_err = ""
    if enabled:
        try:
            get_backend()
            backend_ready = True
        except Exception as e:  # noqa: BLE001
            backend_err = str(e)

    last = latest_successful()
    last_test = get_setting("backup.last_test_at")
    last_test_ok = (get_setting("backup.last_test_ok") or "") == "1"

    return {
        "enabled": enabled,
        "backend": kind,
        "backend_ready": backend_ready,
        "backend_error": backend_err,
        "passphrase_set": passphrase_set,
        "local_path": get_setting("backup.local_path") or DEFAULT_LOCAL_PATH,
        "daily_keep": int(get_setting("backup.daily_keep") or "30"),
        "monthly_keep": int(get_setting("backup.monthly_keep") or "12"),
        "last_daily_at": get_setting("backup.last_daily_at"),
        "last_monthly_at": get_setting("backup.last_monthly_at"),
        "last_test_at": last_test,
        "last_test_ok": last_test_ok,
        "latest": last,
        "s3": {
            "bucket": _envstr("BACKUP_S3_BUCKET"),
            "endpoint": _envstr("BACKUP_S3_ENDPOINT") or "AWS default",
            "region": _envstr("BACKUP_S3_REGION") or "us-east-1",
            "key_set": bool(_envstr("BACKUP_S3_KEY")),
            "secret_set": bool(_envstr("BACKUP_S3_SECRET")),
        },
    }
