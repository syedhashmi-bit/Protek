"""
federation.py — multi-source LAPI fan-in.

Phase 7 (foundation):
    seed_local_source()  — write the local LAPI as source #1 on every boot
    list_sources()       — read sources table (enabled only by default)
    clients()            — build LAPIClient instances per source

Phase 8+ extends this with add/remove/test-connection UI calls.

The reconcile / poll loop doesn't need to know whether one or ten sources
are configured — it just iterates whatever clients() returns and merges the
decisions. The reconcile pure function already handles dedup by `value`.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from crowdsec import LAPIClient
from db import get_conn

log = logging.getLogger("protek.federation")


def _envstr(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default) or ""
    return raw.split("#", 1)[0].strip()


@dataclass
class Source:
    id: int
    name: str
    url: str
    api_key: str
    enabled: bool
    last_pull_at: str | None = None
    last_pull_n: int = 0
    last_error: str = ""
    backoff_until: str | None = None     # phase-9 backoff control
    paused: bool = False                  # phase-9 pause-from-UI
    confidence: int = 1                   # phase-10 weight (1 = normal)
    last_pull_ms: int = 0                 # phase-88 per-source pull duration


# ── Seed local ──────────────────────────────────────────────────────────────

def seed_local_source() -> None:
    """Insert the local LAPI as `local` on first boot. Idempotent.

    `.env` is still the source of truth for the local creds — we just mirror
    them into the table so the rest of the codebase has a uniform shape.
    """
    url = _envstr("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080")
    key = _envstr("CROWDSEC_BOUNCER_KEY", "")
    if not key:
        return
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        existing = conn.execute("SELECT id FROM sources WHERE name = ?", ("local",)).fetchone()
        if existing:
            # Keep credentials fresh if .env changed.
            conn.execute(
                "UPDATE sources SET url = ?, api_key = ? WHERE name = ?",
                (url, key, "local"),
            )
        else:
            conn.execute(
                """
                INSERT INTO sources (name, url, api_key, enabled, created_at)
                VALUES (?, ?, ?, 1, ?)
                """,
                ("local", url, key, now),
            )
    finally:
        conn.close()


# ── List / fetch ───────────────────────────────────────────────────────────

def list_sources(include_disabled: bool = False) -> list[Source]:
    conn = get_conn()
    try:
        if include_disabled:
            rows = conn.execute("SELECT * FROM sources ORDER BY id").fetchall()
        else:
            rows = conn.execute("SELECT * FROM sources WHERE enabled = 1 ORDER BY id").fetchall()
    finally:
        conn.close()
    out: list[Source] = []
    for r in rows:
        keys = r.keys()
        out.append(Source(
            id=r["id"], name=r["name"], url=r["url"], api_key=r["api_key"],
            enabled=bool(r["enabled"]),
            last_pull_at=r["last_pull_at"], last_pull_n=r["last_pull_n"] or 0,
            last_error=r["last_error"] or "",
            backoff_until=r["backoff_until"] if "backoff_until" in keys else None,
            paused=bool(r["paused"]) if "paused" in keys else False,
            confidence=r["confidence"] if "confidence" in keys and r["confidence"] is not None else 1,
            last_pull_ms=int(r["last_pull_ms"] or 0) if "last_pull_ms" in keys else 0,
        ))
    return out


def clients() -> list[LAPIClient]:
    """Federation-ready: hand back one LAPIClient per enabled+un-paused source."""
    return [
        LAPIClient(url=s.url, api_key=s.api_key, name=s.name)
        for s in list_sources()
        if not s.paused
    ]


def record_pull(source_id: int, count: int, error: str = "",
                duration_ms: int = 0) -> None:
    """Phase 88 — duration_ms is the wall-clock time the pull took.
    Surfaced on /federation so a slow source is visible before it
    bogs the global cycle. Falls back gracefully if the column hasn't
    been migrated yet (sources.last_pull_ms is added in init_db, but a
    pre-migration DB can still record without it)."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        try:
            conn.execute(
                "UPDATE sources SET last_pull_at = ?, last_pull_n = ?, "
                "last_error = ?, last_pull_ms = ? WHERE id = ?",
                (now, count, error, int(duration_ms or 0), source_id),
            )
        except Exception:  # noqa: BLE001
            # Pre-migration: column doesn't exist yet
            conn.execute(
                "UPDATE sources SET last_pull_at = ?, last_pull_n = ?, "
                "last_error = ? WHERE id = ?",
                (now, count, error, source_id),
            )
    finally:
        conn.close()


def set_backoff(source_id: int, until_iso: str | None) -> None:
    conn = get_conn()
    try:
        conn.execute("UPDATE sources SET backoff_until = ? WHERE id = ?", (until_iso, source_id))
    finally:
        conn.close()


def set_paused(source_id: int, paused: bool) -> None:
    conn = get_conn()
    try:
        conn.execute("UPDATE sources SET paused = ? WHERE id = ?", (1 if paused else 0, source_id))
    finally:
        conn.close()


def set_enabled(source_id: int, enabled: bool) -> None:
    conn = get_conn()
    try:
        conn.execute("UPDATE sources SET enabled = ? WHERE id = ?", (1 if enabled else 0, source_id))
    finally:
        conn.close()


def set_confidence(source_id: int, confidence: int) -> None:
    conn = get_conn()
    try:
        conn.execute("UPDATE sources SET confidence = ? WHERE id = ?", (max(1, int(confidence)), source_id))
    finally:
        conn.close()


def add_source(name: str, url: str, api_key: str, confidence: int = 1) -> int:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        cur = conn.execute(
            """INSERT INTO sources (name, url, api_key, enabled, confidence, created_at)
               VALUES (?, ?, ?, 1, ?, ?)""",
            (name, url, api_key, max(1, int(confidence)), now),
        )
        return cur.lastrowid or 0
    finally:
        conn.close()


def delete_source(source_id: int) -> None:
    conn = get_conn()
    try:
        # Refuse to delete 'local' — that's the .env-sourced anchor.
        row = conn.execute("SELECT name FROM sources WHERE id = ?", (source_id,)).fetchone()
        if row and row["name"] == "local":
            raise ValueError("cannot delete the local source — manage it via .env")
        conn.execute("DELETE FROM sources WHERE id = ?", (source_id,))
    finally:
        conn.close()


def test_connection(url: str, api_key: str) -> dict:
    """Quick health probe used by the add-source UI before we save."""
    client = LAPIClient(url=url, api_key=api_key, name="probe")
    return client.health()
