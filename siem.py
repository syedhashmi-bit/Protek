"""
siem.py — Arc 6 phase 34. SIEM event forwarding.

Forwarders:
  - Syslog (RFC 5424) over UDP or TCP — configured via SYSLOG_HOST/PORT/PROTO
  - JSON webhook (Splunk HEC / generic) — configured via SIEM_WEBHOOK_URL +
    optional SIEM_WEBHOOK_TOKEN (sent as `Authorization: Bearer ...`)

Design:
  - Every event is **persisted first** to `siem_journal` (so we can replay
    it later regardless of forwarder state) and **then** enqueued for the
    background worker to ship.
  - Queue is a bounded `deque(maxlen=10_000)`; on overflow the oldest items
    are dropped silently (warned in the log). This keeps the reconcile loop
    free from backpressure if a SIEM is slow or down.
  - One daemon worker thread per Protek process; the same fcntl lock that
    elects the poller-owner also elects the siem-owner (in app.py) so we
    don't have N gunicorn workers each spawning their own.
  - On ship-success we stamp `siem_journal.shipped_at`; on failure we record
    `ship_error` so /audit-style views can show recent drops.
  - Replay: `replay(n)` reads the last N rows from `siem_journal` (regardless
    of shipped state) and re-enqueues them. Useful after re-pointing the
    syslog host.

Severity mapping (RFC 5424):
  0=emerg 1=alert 2=crit 3=err 4=warning 5=notice 6=info 7=debug

Event types and their defaults — keep these stable; downstream rules key
off the event_type field.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Protocol

import requests

from db import get_conn

log = logging.getLogger("protek.siem")


# ── Severity / event catalogue ─────────────────────────────────────────────

SEV_EMERG, SEV_ALERT, SEV_CRIT, SEV_ERR, SEV_WARN, SEV_NOTICE, SEV_INFO, SEV_DEBUG = range(8)

EVENT_SEVERITY: dict[str, int] = {
    "decision.created": SEV_NOTICE,
    "decision.deleted": SEV_INFO,
    "sync.error":       SEV_ERR,
    "sync.threshold":   SEV_WARN,
    "auth.failure":     SEV_WARN,
    "auth.success":     SEV_INFO,
    "auth.locked":      SEV_ALERT,
    "source.down":      SEV_ERR,
    "source.up":        SEV_INFO,
    "mt.unreachable":   SEV_ERR,
    "mt.recovered":     SEV_INFO,
    "bouncer.error":    SEV_ERR,
    "settings.changed": SEV_NOTICE,
}


def _envstr(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default) or ""
    return raw.split("#", 1)[0].strip()


def _envint(name: str, default: int) -> int:
    v = _envstr(name, "")
    try:
        return int(v) if v else default
    except ValueError:
        return default


# ── Forwarder interface + implementations ──────────────────────────────────

class Forwarder(Protocol):
    name: str
    def send(self, event_type: str, severity: int, payload: dict[str, Any]) -> None: ...


class SyslogForwarder:
    """RFC 5424 — TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG."""

    name = "syslog"

    def __init__(self, host: str, port: int, proto: str = "udp",
                 facility: int = 16, app_name: str = "protek") -> None:
        self.host = host
        self.port = port
        self.proto = (proto or "udp").lower()
        self.facility = facility
        self.app_name = app_name
        self._hostname = socket.gethostname() or "-"
        self._procid = str(os.getpid())
        self._sock: socket.socket | None = None
        self._sock_lock = threading.Lock()

    def _ensure_sock(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        if self.proto == "tcp":
            s = socket.create_connection((self.host, self.port), timeout=5)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock = s
        return s

    def _reset_sock(self) -> None:
        try:
            if self._sock:
                self._sock.close()
        except Exception:  # noqa: BLE001
            pass
        self._sock = None

    def send(self, event_type: str, severity: int, payload: dict[str, Any]) -> None:
        pri = self.facility * 8 + severity
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        msgid = event_type.replace(" ", "_")
        # Structured data block keeps key fields machine-parseable per RFC.
        sd_pairs = []
        for k in ("ip", "scenario", "origin", "source", "actor", "bouncer"):
            v = payload.get(k)
            if v is not None and v != "":
                sd_pairs.append(f'{k}="{str(v).replace(chr(34), chr(39))}"')
        sd = f"[protek@53595 {' '.join(sd_pairs)}]" if sd_pairs else "-"
        msg_body = json.dumps(payload, default=str, separators=(",", ":"))
        line = f"<{pri}>1 {ts} {self._hostname} {self.app_name} {self._procid} {msgid} {sd} {msg_body}"
        data = line.encode("utf-8", errors="replace")
        if self.proto == "tcp":
            # Octet-counted framing per RFC 6587 §3.4.1 — most syslog daemons
            # default to this when listening on TCP.
            data = f"{len(data)} ".encode() + data
        with self._sock_lock:
            try:
                s = self._ensure_sock()
                if self.proto == "tcp":
                    s.sendall(data)
                else:
                    s.sendto(data, (self.host, self.port))
            except OSError:
                self._reset_sock()
                # one retry for transient TCP closes / UDP refused-ports
                s = self._ensure_sock()
                if self.proto == "tcp":
                    s.sendall(data)
                else:
                    s.sendto(data, (self.host, self.port))


class WebhookForwarder:
    """JSON POST. Compatible with Splunk HEC if URL ends in /services/collector
    and token is a HEC token."""

    name = "webhook"

    def __init__(self, url: str, token: str = "", timeout: int = 8) -> None:
        self.url = url
        self.token = token
        self.timeout = timeout

    def send(self, event_type: str, severity: int, payload: dict[str, Any]) -> None:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = {
            "time": datetime.now(timezone.utc).timestamp(),
            "host": socket.gethostname(),
            "source": "protek",
            "sourcetype": event_type,
            "event": payload,
            "severity": severity,
        }
        r = requests.post(self.url, headers=headers, json=body, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"webhook HTTP {r.status_code}: {r.text[:200]}")


# ── Queue + worker ─────────────────────────────────────────────────────────

QUEUE_MAX = 10_000


class SIEMQueue:
    """Per-process singleton. Drains a bounded deque into one or more
    forwarders; tolerates configuration changes mid-flight by re-reading
    env vars on every cycle so a /settings change can take effect without
    a process restart."""

    def __init__(self) -> None:
        self._q: deque[tuple[int, str, int, dict[str, Any]]] = deque(maxlen=QUEUE_MAX)
        self._cv = threading.Condition()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._dropped = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="protek-siem", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        if self._thread:
            self._thread.join(timeout=3)

    # ── public API ──────────────────────────────────────────────────────────
    def ship(self, event_type: str, payload: dict[str, Any] | None = None,
             severity: int | None = None) -> int | None:
        """Persist to siem_journal, then enqueue for the worker.

        Returns the siem_journal row id (or None if journaling failed).
        Always non-blocking — if the worker is paused or the queue is full,
        the oldest event is dropped to make room.
        """
        payload = payload or {}
        sev = severity if severity is not None else EVENT_SEVERITY.get(event_type, SEV_INFO)
        now = datetime.now(timezone.utc).isoformat()
        row_id: int | None = None
        try:
            conn = get_conn()
            try:
                cur = conn.execute(
                    "INSERT INTO siem_journal (created_at, event_type, severity, payload_json) "
                    "VALUES (?, ?, ?, ?)",
                    (now, event_type, sev, json.dumps(payload, default=str)),
                )
                row_id = cur.lastrowid
                # Bound the journal to ~10k rows — drop oldest in bulk.
                conn.execute(
                    "DELETE FROM siem_journal "
                    "WHERE id < (SELECT MAX(id) FROM siem_journal) - 10000"
                )
            finally:
                conn.close()
        except Exception as e:  # noqa: BLE001
            log.warning("siem journal write failed: %s", e)
        # Enqueue regardless — worker can ship even if journal failed.
        with self._cv:
            if len(self._q) >= QUEUE_MAX:
                self._dropped += 1
                self._q.popleft()
            self._q.append((row_id or 0, event_type, sev, payload))
            self._cv.notify()
        return row_id

    def replay(self, n: int = 100) -> int:
        """Re-enqueue the last N events from the journal regardless of
        previous ship state. Returns how many were re-enqueued."""
        conn = get_conn()
        try:
            rows = conn.execute(
                "SELECT id, event_type, severity, payload_json FROM siem_journal "
                "ORDER BY id DESC LIMIT ?",
                (int(n),),
            ).fetchall()
        finally:
            conn.close()
        count = 0
        with self._cv:
            for r in reversed(rows):  # ship in chronological order
                try:
                    payload = json.loads(r["payload_json"] or "{}")
                except json.JSONDecodeError:
                    payload = {"raw": r["payload_json"]}
                if len(self._q) >= QUEUE_MAX:
                    self._dropped += 1
                    self._q.popleft()
                self._q.append((r["id"], r["event_type"], int(r["severity"] or SEV_INFO), payload))
                count += 1
            self._cv.notify()
        return count

    def stats(self) -> dict[str, Any]:
        return {
            "queued": len(self._q),
            "queue_max": QUEUE_MAX,
            "dropped_overflow": self._dropped,
            "configured": bool(_active_forwarders()),
        }

    # ── worker loop ─────────────────────────────────────────────────────────
    def _loop(self) -> None:
        while not self._stop.is_set():
            with self._cv:
                while not self._q and not self._stop.is_set():
                    self._cv.wait(timeout=2.0)
                if self._stop.is_set():
                    return
                row_id, event_type, severity, payload = self._q.popleft()
            self._dispatch(row_id, event_type, severity, payload)

    def _dispatch(self, row_id: int, event_type: str, severity: int,
                  payload: dict[str, Any]) -> None:
        forwarders = _active_forwarders()
        if not forwarders:
            return
        errors: list[str] = []
        for fw in forwarders:
            try:
                fw.send(event_type, severity, payload)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{fw.name}: {e}")
        # Stamp the journal row with ship result (best-effort).
        if row_id:
            now = datetime.now(timezone.utc).isoformat()
            try:
                conn = get_conn()
                try:
                    conn.execute(
                        "UPDATE siem_journal SET shipped_at = ?, ship_error = ? WHERE id = ?",
                        (now, "; ".join(errors)[:300], row_id),
                    )
                finally:
                    conn.close()
            except Exception as e:  # noqa: BLE001
                log.debug("siem journal stamp failed: %s", e)


# ── Forwarder construction ─────────────────────────────────────────────────

def _active_forwarders() -> list[Forwarder]:
    out: list[Forwarder] = []
    syslog_host = _envstr("SYSLOG_HOST", "")
    if syslog_host:
        out.append(SyslogForwarder(
            host=syslog_host,
            port=_envint("SYSLOG_PORT", 514),
            proto=_envstr("SYSLOG_PROTO", "udp"),
            facility=_envint("SYSLOG_FACILITY", 16),
        ))
    webhook_url = _envstr("SIEM_WEBHOOK_URL", "")
    if webhook_url:
        out.append(WebhookForwarder(
            url=webhook_url,
            token=_envstr("SIEM_WEBHOOK_TOKEN", ""),
        ))
    return out


# ── Singleton accessor ─────────────────────────────────────────────────────

_singleton: SIEMQueue | None = None
_singleton_lock = threading.Lock()


def get_siem() -> SIEMQueue:
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = SIEMQueue()
            _singleton.start()
        return _singleton


def ship(event_type: str, payload: dict[str, Any] | None = None,
         severity: int | None = None) -> None:
    """Convenience: enqueue an event without holding a reference.

    Also fans out to outbound webhook subscribers (phase 45). One call site,
    two pipelines — keeps emission points in the rest of the codebase from
    needing to know about webhooks vs SIEM.
    """
    payload = payload or {}
    try:
        get_siem().ship(event_type, payload, severity)
    except Exception as e:  # noqa: BLE001
        log.debug("siem ship swallowed: %s", e)
    try:
        import webhooks_out
        webhooks_out.emit(event_type, payload)
    except Exception as e:  # noqa: BLE001
        log.debug("webhook emit swallowed: %s", e)
