"""
webhooks_out.py — Phase 45. Outbound webhook delivery.

On every decision event (created / deleted / approved / rejected) we POST to
every enabled subscriber whose `event_mask` matches. Payload is signed with
HMAC-SHA256 using the per-subscriber `hmac_secret`; receivers verify by
recomputing.

Reliability:
  - 3 attempts with exponential backoff (2s, 4s, 8s) per delivery, all from a
    background worker thread (the request that triggered the event never
    blocks on network I/O).
  - On exhausted retries, the payload + last error land in `webhook_dlq` so
    an operator can investigate at /webhooks. DLQ entries can be re-shipped
    one-at-a-time from the UI.
  - Per-subscriber `consec_failures` counter; surfaced on the page so a dead
    receiver is visible at a glance.

Headers sent to receivers:
    Content-Type: application/json
    X-Protek-Event: <event_type>
    X-Protek-Timestamp: <unix-seconds>
    X-Protek-Signature: sha256=<hex-hmac-of-(timestamp.payload)>

Verification on the receiver side (pseudo):
    expected = hmac_sha256(secret, f"{timestamp}.{raw_body}").hexdigest()
    if hmac.compare_digest(expected, sent_sig.split("=", 1)[1]): ok
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import secrets as pysecrets
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests

from db import get_conn

log = logging.getLogger("protek.webhooks_out")

DEFAULT_TIMEOUT = 8
BACKOFF = [2, 4, 8]  # seconds between attempts


# ── CRUD ───────────────────────────────────────────────────────────────────

def list_subs() -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, name, url, event_mask, enabled, created_at, "
            "last_ok_at, last_error, consec_failures "
            "FROM webhook_subs ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def add_sub(name: str, url: str, event_mask: str = "*",
            hmac_secret: str | None = None) -> dict[str, Any]:
    if not name.replace("-", "").replace("_", "").isalnum():
        raise ValueError("name must be alphanumeric (+ _ -)")
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must start with http:// or https://")
    secret = hmac_secret or pysecrets.token_urlsafe(32)
    conn = get_conn()
    try:
        cur = conn.execute(
            """INSERT INTO webhook_subs (name, url, hmac_secret, event_mask, enabled, created_at)
               VALUES (?, ?, ?, ?, 1, ?)""",
            (name, url, secret, event_mask, datetime.now(timezone.utc).isoformat()),
        )
        return {"id": cur.lastrowid, "name": name, "url": url,
                "event_mask": event_mask, "hmac_secret": secret}
    finally:
        conn.close()


def delete_sub(sub_id: int) -> None:
    conn = get_conn()
    try:
        conn.execute("DELETE FROM webhook_subs WHERE id = ?", (sub_id,))
        conn.execute("DELETE FROM webhook_dlq WHERE sub_id = ?", (sub_id,))
    finally:
        conn.close()


def toggle_sub(sub_id: int, enabled: bool) -> None:
    conn = get_conn()
    try:
        conn.execute("UPDATE webhook_subs SET enabled = ? WHERE id = ?",
                     (1 if enabled else 0, sub_id))
    finally:
        conn.close()


def list_dlq(limit: int = 200) -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT d.*, s.name AS sub_name, s.url AS sub_url "
            "FROM webhook_dlq d LEFT JOIN webhook_subs s ON s.id = d.sub_id "
            "ORDER BY d.id DESC LIMIT ?", (int(limit),)
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def replay_dlq(entry_id: int) -> dict[str, Any]:
    """Re-enqueue a single DLQ entry. Returns the delivery result inline
    (synchronous — operator triggered, so they want to see it land or fail)."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT d.*, s.url, s.hmac_secret, s.name AS sub_name "
            "FROM webhook_dlq d LEFT JOIN webhook_subs s ON s.id = d.sub_id "
            "WHERE d.id = ?", (entry_id,)
        ).fetchone()
        if not row:
            return {"ok": False, "error": "not found"}
        if not row["url"]:
            return {"ok": False, "error": "subscriber gone — DLQ orphaned, cannot replay"}
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError as e:
            return {"ok": False, "error": f"corrupted DLQ payload: {e}"}
        ok, err = _send_once(
            url=row["url"], secret=row["hmac_secret"],
            event_type=row["event_type"], payload=payload,
        )
        if ok:
            conn.execute("DELETE FROM webhook_dlq WHERE id = ?", (entry_id,))
            return {"ok": True, "delivered_to": row["url"]}
        else:
            conn.execute(
                "UPDATE webhook_dlq SET attempts = attempts + 1, "
                "last_attempt_at = ?, last_error = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), err[:300], entry_id),
            )
            return {"ok": False, "error": err}
    finally:
        conn.close()


# ── Signing ────────────────────────────────────────────────────────────────

def _sign(secret: str, timestamp: str, body: bytes) -> str:
    msg = f"{timestamp}.".encode() + body
    return "sha256=" + hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def _send_once(url: str, secret: str, event_type: str,
               payload: dict[str, Any]) -> tuple[bool, str]:
    # Phase-68 backpressure: per-host token bucket. If exhausted, treat as a
    # transient failure so the existing retry/DLQ machinery kicks in.
    try:
        import ratelimit
        if not ratelimit.webhook_bucket_for(url).acquire():
            return False, "backpressure — webhook bucket exhausted"
    except ImportError:
        pass
    body = json.dumps({"event": event_type, "data": payload}, default=str).encode()
    ts = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-Protek-Event": event_type,
        "X-Protek-Timestamp": ts,
        "X-Protek-Signature": _sign(secret, ts, body),
        "User-Agent": "protek-webhook/1.0",
    }
    try:
        r = requests.post(url, data=body, headers=headers, timeout=DEFAULT_TIMEOUT)
        if r.status_code == 429:
            try:
                import ratelimit
                ratelimit.webhook_bucket_for(url).record_429()
            except ImportError:
                pass
            return False, "HTTP 429: rate limited"
        if 200 <= r.status_code < 300:
            return True, ""
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except requests.RequestException as e:
        return False, f"network: {e}"


# ── Worker + queue ─────────────────────────────────────────────────────────

_q: queue.Queue[tuple[str, dict[str, Any]]] = queue.Queue(maxsize=10_000)
_worker_started = False
_worker_lock = threading.Lock()


def _worker_loop() -> None:
    while True:
        event_type, payload = _q.get()
        try:
            _deliver_all(event_type, payload)
        except Exception as e:  # noqa: BLE001
            log.warning("webhook delivery loop crashed on %s: %s", event_type, e)
        finally:
            _q.task_done()


def _ensure_worker() -> None:
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        t = threading.Thread(target=_worker_loop, name="protek-webhooks-out", daemon=True)
        t.start()
        _worker_started = True


def emit(event_type: str, payload: dict[str, Any]) -> None:
    """Non-blocking. Best-effort enqueue; drops with a log if queue is full."""
    _ensure_worker()
    try:
        _q.put_nowait((event_type, payload))
    except queue.Full:
        log.warning("webhook queue full — dropping %s event", event_type)


def _match(event_mask: str, event_type: str) -> bool:
    if not event_mask or event_mask == "*":
        return True
    # Comma-separated globs: "decision.*,auth.failure"
    import fnmatch as _fn
    for piece in (p.strip() for p in event_mask.split(",") if p.strip()):
        if _fn.fnmatchcase(event_type, piece):
            return True
    return False


def _deliver_all(event_type: str, payload: dict[str, Any]) -> None:
    subs = [s for s in list_subs() if s["enabled"] and _match(s["event_mask"], event_type)]
    if not subs:
        return
    for sub in subs:
        _deliver_one(sub, event_type, payload)


def _deliver_one(sub: dict[str, Any], event_type: str, payload: dict[str, Any]) -> None:
    # Pull the secret fresh — list_subs() returned a redacted view; we need
    # the hmac_secret column from the actual row.
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT hmac_secret FROM webhook_subs WHERE id = ?", (sub["id"],)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return
    secret = row["hmac_secret"]
    last_err = ""
    for i, wait in enumerate(BACKOFF):
        ok, err = _send_once(sub["url"], secret, event_type, payload)
        if ok:
            _mark_ok(sub["id"])
            return
        last_err = err
        if i < len(BACKOFF) - 1:
            time.sleep(wait)
    # Out of attempts → DLQ
    _push_dlq(sub["id"], event_type, payload, last_err)
    _mark_fail(sub["id"], last_err)


def _mark_ok(sub_id: int) -> None:
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE webhook_subs SET last_ok_at = ?, last_error = '', "
            "consec_failures = 0 WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), sub_id),
        )
    finally:
        conn.close()


def _mark_fail(sub_id: int, err: str) -> None:
    conn = get_conn()
    try:
        conn.execute(
            "UPDATE webhook_subs SET last_error = ?, "
            "consec_failures = consec_failures + 1 WHERE id = ?",
            (err[:300], sub_id),
        )
    finally:
        conn.close()


def _push_dlq(sub_id: int, event_type: str, payload: dict[str, Any], err: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO webhook_dlq
                 (sub_id, event_type, payload_json, last_error, attempts,
                  first_seen_at, last_attempt_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (sub_id, event_type, json.dumps(payload, default=str),
             err[:300], len(BACKOFF), now, now),
        )
        # Bound DLQ size — keep newest 1000.
        conn.execute(
            "DELETE FROM webhook_dlq WHERE id < (SELECT MAX(id) FROM webhook_dlq) - 1000"
        )
    finally:
        conn.close()
