#!/usr/bin/env python3
"""
restore_backup.py — decrypt a Protek backup bundle and extract its members.

Usage:
    BACKUP_PASSPHRASE='your-passphrase' python3 restore_backup.py \
        --bundle /path/to/protek-YYYYMMDDTHHMMSSZ.bin \
        [--out /var/www/Protek/protek.db]   # just protek.db, in-place restore
        [--extract-dir /tmp/restored]       # whole bundle to a dir

If --out is given, only `protek.db` is written there. If --extract-dir is
given, the full bundle tree (protek.db, env, scenarios/, manifest.json)
is unpacked there. You can pass both.

Standalone — no Protek dependencies beyond `cryptography`. Safe to run on a
fresh box with only the venv (or system python3.12 + `pip install cryptography`).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"PROTEKBK"
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt,
                          n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                          dklen=32, maxmem=128 * 1024 * 1024)


def decrypt_bundle(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise SystemExit("not a Protek backup bundle (bad magic)")
    body = blob[len(MAGIC):]
    salt, nonce, ct = body[:16], body[16:28], body[28:]
    key = derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:
        raise SystemExit(f"decrypt failed (wrong passphrase?): {e}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--bundle", required=True, help="path to .bin bundle")
    p.add_argument("--out", help="write only protek.db to this path")
    p.add_argument("--extract-dir", help="unpack whole bundle to this dir")
    args = p.parse_args()

    passphrase = os.environ.get("BACKUP_PASSPHRASE") or ""
    if not passphrase:
        raise SystemExit("BACKUP_PASSPHRASE env var not set")

    blob = Path(args.bundle).read_bytes()
    tar_bytes = decrypt_bundle(blob, passphrase)

    tar = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz")
    members = tar.getmembers()
    print(f"bundle decrypted ok — {len(members)} members")

    if args.extract_dir:
        outdir = Path(args.extract_dir)
        outdir.mkdir(parents=True, exist_ok=True)
        for m in members:
            if m.name.startswith("/") or ".." in Path(m.name).parts:
                raise SystemExit(f"unsafe arcname: {m.name}")
        tar.extractall(outdir)
        print(f"extracted to {outdir}")

    if args.out:
        try:
            db = tar.extractfile("protek.db")
            if db is None:
                raise SystemExit("bundle contains no protek.db")
            Path(args.out).write_bytes(db.read())
            os.chmod(args.out, 0o600)
            print(f"wrote {args.out}")
        except KeyError:
            raise SystemExit("bundle missing protek.db")

    # Verify manifest sha256 sums if present
    try:
        manifest = tar.extractfile("manifest.json")
        if manifest:
            man = json.loads(manifest.read())
            tar.close()
            tar = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz")
            for entry in man.get("files", []):
                name, want = entry["name"], entry["sha256"]
                f = tar.extractfile(name)
                if f is None:
                    print(f"  ! missing {name}")
                    continue
                got = hashlib.sha256(f.read()).hexdigest()
                ok = (got == want)
                print(f"  {'ok' if ok else 'BAD'}  {name}  ({entry['bytes']} bytes)")
    except KeyError:
        print("(no manifest.json — skipping integrity check)")


if __name__ == "__main__":
    main()
