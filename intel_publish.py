"""
intel_publish.py — Arc 13 phase 78. Publish Protek's own decisions as a
signed threat-intel feed.

Other Protek instances (or any consumer) can subscribe to this feed at
/feed/banned-ips.signed.json and get:

  - The IPs Protek has decided to ban (filtered to those Protek originated,
    not pass-throughs from community blocklists — we shouldn't republish
    `lists:firehol_*` as our own intel).
  - An ed25519 signature over the canonical JSON so consumers can verify
    the feed wasn't tampered in transit (independent of TLS).
  - A timestamp + sequence number for replay protection.

Auth model:
  - Public feed (no auth): only the decisions explicitly marked as
    publishable (origin = 'crowdsec' = our local detection) and matching
    `intel.publish.scenarios` filter. Defaults to empty filter = ALL local
    decisions are published.
  - Per-subscriber rate limiting via phase 68 token buckets keyed on
    `feed.<subscriber>` if `subscriber` query param provided.
  - Opt-in: feature is disabled by default. Operator enables via
    `intel.publish.enabled=1` in settings.

The signing key is an ed25519 keypair generated on first enable, stored in
`settings` (priv encrypted at rest with SECRET_KEY-derived AES-GCM, pub in
plaintext for distribution to subscribers).

Why a separate feed and not just `/api/v1/decisions`:
  - `/api/v1/*` requires a bearer token; the feed is meant to be subscribable
    by other Protek instances *without* preconfiguring per-subscriber tokens.
  - Signing lives at the feed level so a subscriber can verify the chain of
    custody — useful when relaying through a CDN or caching proxy.
  - Filter semantics: feeds filter to local-origin (don't echo other people's
    blocklists back).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from db import get_conn, get_setting, set_setting

log = logging.getLogger("protek.intel_publish")


def is_enabled() -> bool:
    return (get_setting("intel.publish.enabled") or "0") == "1"


def _secret_key() -> bytes:
    """Derive a stable 32-byte symmetric key from SECRET_KEY for at-rest
    encryption of the ed25519 private signing key."""
    sk = (os.environ.get("SECRET_KEY") or "").encode() or b"dev-secret-CHANGE-ME"
    return hashlib.sha256(sk + b"|intel-publish-priv-key").digest()


def _ensure_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Get or generate the feed signing keypair. Returns (priv, pub, pub_b64)."""
    pub_b64 = get_setting("intel.publish.pub_b64") or ""
    priv_enc_b64 = get_setting("intel.publish.priv_enc_b64") or ""

    if pub_b64 and priv_enc_b64:
        # Decrypt the private key
        try:
            enc = base64.b64decode(priv_enc_b64)
            nonce, ct = enc[:12], enc[12:]
            priv_bytes = AESGCM(_secret_key()).decrypt(nonce, ct, None)
            priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
            pub = priv.public_key()
            return priv, pub, pub_b64
        except Exception as e:  # noqa: BLE001
            log.warning("stored signing key unusable, regenerating: %s", e)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    nonce = os.urandom(12)
    ct = AESGCM(_secret_key()).encrypt(nonce, priv_bytes, None)
    priv_enc_b64 = base64.b64encode(nonce + ct).decode()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(pub_bytes).decode()
    set_setting("intel.publish.priv_enc_b64", priv_enc_b64)
    set_setting("intel.publish.pub_b64", pub_b64)
    return priv, pub, pub_b64


def rotate_keypair() -> str:
    """Invalidate existing key, generate a new one. Returns the new pub_b64."""
    conn = get_conn()
    try:
        conn.execute("DELETE FROM settings WHERE key IN (?, ?)",
                     ("intel.publish.pub_b64", "intel.publish.priv_enc_b64"))
    finally:
        conn.close()
    _, _, pub_b64 = _ensure_keypair()
    return pub_b64


def _filter_scenarios() -> list[str]:
    raw = get_setting("intel.publish.scenarios") or ""
    return [s.strip() for s in raw.split(",") if s.strip()]


def _filter_excluded_origins() -> list[str]:
    """Default-exclude `lists:*` since those aren't *our* intel."""
    raw = get_setting("intel.publish.exclude_origins") or "lists:"
    return [s.strip() for s in raw.split(",") if s.strip()]


def _excluded(origin: str, excludes: list[str]) -> bool:
    if not origin:
        return False
    for pat in excludes:
        if pat.endswith(":") or pat == "*":
            if origin.startswith(pat.rstrip("*")):
                return True
        elif pat == origin:
            return True
    return False


def build_feed() -> dict[str, Any]:
    """Build the unsigned payload — list of {ip, scope, scenario, origin,
    first_seen, until} entries."""
    scenarios = _filter_scenarios()
    excludes = _filter_excluded_origins()
    sql = ("SELECT value, scope, scenario, origin, first_seen_at, until "
           "FROM decisions WHERE deleted_at IS NULL")
    params: list[Any] = []
    if scenarios:
        placeholders = ",".join(["?"] * len(scenarios))
        sql += f" AND scenario IN ({placeholders})"
        params.extend(scenarios)
    sql += " ORDER BY id DESC LIMIT 10000"
    conn = get_conn()
    try:
        rows = conn.execute(sql, tuple(params)).fetchall()
    finally:
        conn.close()
    entries = []
    for r in rows:
        if _excluded(r["origin"] or "", excludes):
            continue
        entries.append({
            "ip":        r["value"],
            "scope":     r["scope"],
            "scenario":  r["scenario"] or "",
            "origin":    r["origin"] or "",
            "first_seen": r["first_seen_at"],
            "until":     r["until"],
        })

    seq = int(get_setting("intel.publish.seq") or "0") + 1
    set_setting("intel.publish.seq", str(seq))

    return {
        "version":     "1",
        "issuer":      get_setting("intel.publish.issuer") or "protek",
        "issued_at":   datetime.now(timezone.utc).isoformat(),
        "sequence":    seq,
        "count":       len(entries),
        "entries":     entries,
    }


def signed_feed() -> dict[str, Any]:
    """Build + sign the feed. Returns the JSON-ready dict including signature."""
    if not is_enabled():
        return {"error": "intel publishing disabled"}
    priv, _pub, pub_b64 = _ensure_keypair()
    body = build_feed()
    # Canonical JSON for signing — sort keys, no whitespace.
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    sig = priv.sign(canonical)
    return {
        "body":      body,
        "signature": base64.b64encode(sig).decode(),
        "algorithm": "ed25519",
        "public_key_b64": pub_b64,
    }


def status() -> dict[str, Any]:
    pub_b64 = get_setting("intel.publish.pub_b64") or ""
    return {
        "enabled":    is_enabled(),
        "pub_key_b64": pub_b64,
        "fingerprint": hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:16]
                       if pub_b64 else "",
        "sequence":   int(get_setting("intel.publish.seq") or "0"),
        "issuer":     get_setting("intel.publish.issuer") or "protek",
        "scenarios":  _filter_scenarios(),
        "exclude_origins": _filter_excluded_origins(),
    }
