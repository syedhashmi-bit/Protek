#!/usr/bin/env python3
"""
setup_admin.py — bootstrap or rotate the Protek admin credentials.

Generates:
  - SECRET_KEY            (Flask session signer)
  - APP_USERNAME          (defaults to "admin", overridable via --username)
  - APP_PASSWORD_HASH     (bcrypt of a freshly generated strong password,
                           or one passed via --password)
  - TOTP_SECRET           (32-char base32 — works with Google Authenticator,
                           Authy, 1Password, Aegis, etc.)

Writes the secrets into /var/www/Protek/.env, creating the file from
.env.example if it doesn't exist. Existing non-credential values in .env
are preserved.

Prints the plaintext password and TOTP otpauth:// URL **once** on stdout
plus an ASCII QR code. Capture them now — they are not recoverable from
the hash later.

Usage:
    python scripts/setup_admin.py                       # interactive bootstrap
    python scripts/setup_admin.py --username syed       # custom username
    python scripts/setup_admin.py --password 'foo'      # provide password yourself
    python scripts/setup_admin.py --rotate-totp-only    # keep username/password, regenerate TOTP
"""

from __future__ import annotations

import argparse
import base64
import io
import os
import re
import secrets
import sys
from pathlib import Path

import bcrypt
import pyotp

ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = ROOT / ".env"
ENV_EXAMPLE = ROOT / ".env.example"

ISSUER = "Protek"


def load_env() -> dict[str, str]:
    """Read .env into an ordered dict. Preserves blank lines? No — but preserves keys."""
    if not ENV_PATH.exists():
        # Seed from .env.example so all comments/structure carry over
        if ENV_EXAMPLE.exists():
            ENV_PATH.write_text(ENV_EXAMPLE.read_text())
        else:
            ENV_PATH.touch()
    env: dict[str, str] = {}
    for line in ENV_PATH.read_text().splitlines():
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            env[m.group(1)] = m.group(2)
    return env


def write_env(updates: dict[str, str]) -> None:
    """Rewrite .env, replacing keys in `updates` and preserving everything else."""
    lines = ENV_PATH.read_text().splitlines() if ENV_PATH.exists() else []
    seen = set()
    out = []
    for line in lines:
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=", line)
        if m and m.group(1) in updates:
            out.append(f"{m.group(1)}={updates[m.group(1)]}")
            seen.add(m.group(1))
        else:
            out.append(line)
    for k, v in updates.items():
        if k not in seen:
            out.append(f"{k}={v}")
    ENV_PATH.write_text("\n".join(out) + "\n")
    os.chmod(ENV_PATH, 0o600)


def gen_password(length: int = 24) -> str:
    """URL-safe random password — readable, no shell-quote landmines."""
    return secrets.token_urlsafe(length)


def hash_password(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()


def gen_totp_secret() -> str:
    return pyotp.random_base32()


def ascii_qr(uri: str) -> str:
    """Tiny QR renderer with no external deps. Returns text with █▀▄ blocks."""
    # Lazy-import qrcode if available; otherwise emit a notice.
    try:
        import qrcode
    except ImportError:
        return "(install `qrcode` to render an in-terminal QR — for now, scan the URL with your authenticator's manual-entry option)"
    qr = qrcode.QRCode(border=1, box_size=1, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(uri)
    qr.make()
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=True)
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description="Bootstrap Protek admin credentials.")
    ap.add_argument("--username", default=None, help="Admin username (default: admin or existing)")
    ap.add_argument("--password", default=None, help="Plaintext password (default: auto-generate)")
    ap.add_argument("--rotate-totp-only", action="store_true", help="Only regenerate the TOTP secret")
    args = ap.parse_args()

    env = load_env()
    updates: dict[str, str] = {}

    if args.rotate_totp_only:
        totp_secret = gen_totp_secret()
        updates["TOTP_SECRET"] = totp_secret
        username = env.get("APP_USERNAME", "admin")
        plaintext_password = None
    else:
        username = args.username or env.get("APP_USERNAME") or "admin"
        plaintext_password = args.password or gen_password()
        updates["APP_USERNAME"] = username
        updates["APP_PASSWORD_HASH"] = hash_password(plaintext_password)
        updates["SECRET_KEY"] = env.get("SECRET_KEY") or secrets.token_hex(32)
        updates["TOTP_SECRET"] = gen_totp_secret()
        # Drop the legacy plaintext APP_PASSWORD if present
        if "APP_PASSWORD" in env:
            updates["APP_PASSWORD"] = ""

    write_env(updates)

    totp_secret = updates["TOTP_SECRET"]
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name=ISSUER)

    print()
    print("═════════════════════════════════════════════════════════════════════")
    print("  PROTEK — admin credentials")
    print("═════════════════════════════════════════════════════════════════════")
    print()
    print(f"  Username:      {username}")
    if plaintext_password is not None:
        print(f"  Password:      {plaintext_password}")
        print("                 ↑ stored as bcrypt hash; this plaintext is shown ONCE")
    print(f"  TOTP secret:   {totp_secret}")
    print(f"  TOTP issuer:   {ISSUER}")
    print()
    print("  otpauth URL (copy into authenticator's manual-entry field):")
    print(f"  {totp_uri}")
    print()
    print("  Or scan this QR with Google Authenticator / Authy / 1Password / Aegis:")
    print()
    print(ascii_qr(totp_uri))
    print("═════════════════════════════════════════════════════════════════════")
    print()
    print(f"  .env written to: {ENV_PATH} (chmod 0600)")
    print()
    print("  Capture the credentials above NOW. They are not recoverable.")
    print("  To rotate the TOTP later:   python scripts/setup_admin.py --rotate-totp-only")
    print("  To rotate the password:     python scripts/setup_admin.py --password 'newpw'")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
