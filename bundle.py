"""
bundle.py — Phase 41. Encrypted config bundle for backup / VPS migration.

Bundle contents (JSON, then encrypted):
  - users (without password_hash + totp_secret? NO — we include them so
    importing into a fresh VPS preserves logins. The bundle is encrypted with
    a passphrase you choose, so the operator's threat model already trusts
    that passphrase.)
  - sources (federation)
  - whitelist
  - bouncer_targets
  - webhook_subs (incl. hmac_secret)
  - api_tokens (token_hash + metadata — plaintext tokens cannot be reconstructed
    from the hash; you must recreate working tokens after restore, but the
    bundle preserves their existence for audit reasons)
  - settings (all `notify.cred.*`, `notify.*`, `settings.*`, federation knobs)
  - alert_silences

Excluded:
  - decisions / alerts / mt_pushes / sync_events / login_audit
    (operational data; restoring would rewrite history. Re-acquired from
    LAPI on next poll.)
  - audit_log (append-only by design; restoring would re-introduce historical
    rows from another instance into our chain).
  - geo_cache / cti_cache / whois_cache / ip_sources (caches; re-populate
    naturally).

Crypto:
  - 16-byte salt + scrypt(passphrase, salt, n=2^15, r=8, p=1) → 32-byte key
  - AES-256-GCM with random 12-byte nonce, tag verified on import
  - File format (binary):
      MAGIC (8)  "PROTEK01"
      salt  (16)
      nonce (12)
      ciphertext + tag (rest)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from db import get_conn

MAGIC = b"PROTEK01"

# SQL identifier regex — used to gate column names from imported bundles
# before they're interpolated into the dynamic INSERT statement. Matches
# `[A-Za-z_][A-Za-z0-9_]*` — the standard ASCII identifier shape that
# every column in Protek's schema uses.
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # AES-256
SALT_LEN = 16
NONCE_LEN = 12

EXPORTED_TABLES = [
    "users", "sources", "whitelist", "bouncer_targets",
    "webhook_subs", "api_tokens", "settings", "alert_silences",
]


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    # `maxmem=128MB` raises the OpenSSL default (32MB) which is exactly the
    # memory n=2^15 needs — without this we hit "memory limit exceeded".
    return hashlib.scrypt(passphrase.encode(), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_LEN,
                          maxmem=128 * 1024 * 1024)


def _dump_table(conn, table: str) -> list[dict[str, Any]]:
    try:
        rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    except Exception:  # noqa: BLE001 — table may not exist on older DBs
        return []
    return [dict(r) for r in rows]


def build_payload() -> dict[str, Any]:
    """Snapshot the exportable tables into a single dict."""
    out: dict[str, Any] = {
        "format_version": 1,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tables": {},
    }
    conn = get_conn()
    try:
        for t in EXPORTED_TABLES:
            out["tables"][t] = _dump_table(conn, t)
    finally:
        conn.close()
    return out


def export_bundle(passphrase: str) -> bytes:
    """Return the encrypted bundle as raw bytes."""
    if not passphrase or len(passphrase) < 12:
        raise ValueError("passphrase must be ≥ 12 characters")
    payload = build_payload()
    plaintext = json.dumps(payload, default=str).encode()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, plaintext, MAGIC)  # AAD = MAGIC for header binding
    return MAGIC + salt + nonce + ct


def parse_bundle(blob: bytes, passphrase: str) -> dict[str, Any]:
    """Decrypt + return the payload dict. Raises ValueError on bad passphrase
    or corruption (AESGCM raises InvalidTag, which we wrap)."""
    if len(blob) < len(MAGIC) + SALT_LEN + NONCE_LEN + 16:
        raise ValueError("bundle truncated")
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("bad magic — not a Protek bundle")
    salt = blob[len(MAGIC):len(MAGIC) + SALT_LEN]
    nonce = blob[len(MAGIC) + SALT_LEN:len(MAGIC) + SALT_LEN + NONCE_LEN]
    ct = blob[len(MAGIC) + SALT_LEN + NONCE_LEN:]
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    try:
        plaintext = aes.decrypt(nonce, ct, MAGIC)
    except Exception as e:  # noqa: BLE001 — InvalidTag → wrong passphrase
        raise ValueError(f"decryption failed (wrong passphrase or corrupted): {e}") from e
    try:
        return json.loads(plaintext)
    except json.JSONDecodeError as e:
        raise ValueError(f"decrypted payload is not valid JSON: {e}") from e


def import_bundle(blob: bytes, passphrase: str,
                  overwrite: bool = False) -> dict[str, Any]:
    """Restore an exported bundle. Returns a summary of what was applied.

    Default behaviour is **additive**: new rows are inserted but existing rows
    (by primary key OR natural UNIQUE constraint) are not overwritten. Pass
    `overwrite=True` to clear each exported table before insert (USE WITH
    CARE — irreversibly drops local users/tokens/etc.).
    """
    payload = parse_bundle(blob, passphrase)
    if payload.get("format_version") != 1:
        raise ValueError(f"unsupported format_version: {payload.get('format_version')}")
    summary: dict[str, dict[str, int]] = {}
    conn = get_conn()
    try:
        for table, rows in payload.get("tables", {}).items():
            if table not in EXPORTED_TABLES:
                continue
            inserted = 0
            skipped = 0
            replaced = 0
            if overwrite:
                conn.execute(f"DELETE FROM {table}")
            for row in rows:
                # Drop the rowid `id` so we don't collide with the local sequence
                # unless the table uses id as a meaningful FK target. For users +
                # sources + bouncer_targets the IDs are referenced elsewhere, so
                # we keep them. The DB will raise UNIQUE violation if collision;
                # we INSERT OR IGNORE in additive mode, OR INSERT OR REPLACE in
                # overwrite mode.
                #
                # Defense-in-depth: validate every column name from the bundle
                # against the SQL identifier regex before interpolating into
                # the INSERT statement. Even though apply_bundle is admin-only
                # (callers gate on role_required("admin")), a malicious or
                # corrupted bundle could otherwise craft column names that
                # rewrite the INSERT's VALUES clause via comment-injection.
                # The fix rejects any non-identifier column name; the row is
                # logged as skipped rather than silently mangled.
                cols = list(row.keys())
                if not all(_IDENT_RE.match(c) for c in cols):
                    skipped += 1
                    continue
                placeholders = ",".join("?" * len(cols))
                col_list = ",".join(cols)
                values = [row[c] for c in cols]
                verb = "INSERT OR REPLACE" if overwrite else "INSERT OR IGNORE"
                try:
                    cur = conn.execute(
                        f"{verb} INTO {table} ({col_list}) VALUES ({placeholders})",
                        values,
                    )
                    if cur.rowcount:
                        if overwrite:
                            replaced += 1
                        else:
                            inserted += 1
                    else:
                        skipped += 1
                except Exception:  # noqa: BLE001
                    skipped += 1
            summary[table] = {"inserted": inserted, "replaced": replaced,
                              "skipped": skipped, "source_rows": len(rows)}
    finally:
        conn.close()
    return {"applied_at": datetime.now(timezone.utc).isoformat(),
            "overwrite": overwrite, "summary": summary}
