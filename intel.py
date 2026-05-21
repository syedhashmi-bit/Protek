"""
intel.py — Arc 3 intelligence layer.

Four enrichment sources, each cached aggressively in SQLite:
  • CrowdSec CTI       — paid/free reputation lookup (api.crowdsec.net)
  • Team Cymru WHOIS   — IP → ASN, AS-org via DNS TXT records (free, public)
  • Classic WHOIS      — IP → netname, abuse email (whois.cymru-style RDAP)
  • rDNS               — PTR lookup via dnspython with proper timeouts

All four are read in `enrichment_for_ip(ip)` and merged into a single dict
the dashboard can render. Cached failures are short-lived (NXDOMAIN is 1h
negative); cached hits are long-lived (CTI 24h, WHOIS/ASN 7d).

Network calls never run in the reconcile thread. Use `intel_worker.enqueue(ip)`
to schedule a lookup; the worker pulls and fills cache rows in the background.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from queue import Empty, Queue
from typing import Any

import requests

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
    _DNS_OK = True
except ImportError:
    _DNS_OK = False

from db import get_conn

log = logging.getLogger("protek.intel")

CTI_BASE = "https://cti.api.crowdsec.net"
CYMRU_ORIGIN = "origin.asn.cymru.com"
CYMRU_ORIGIN6 = "origin6.asn.cymru.com"
CYMRU_AS = "asn.cymru.com"

CTI_TTL = timedelta(hours=24)
ASN_TTL = timedelta(days=7)
WHOIS_TTL = timedelta(days=7)
RDNS_TTL_OK = timedelta(hours=24)
RDNS_TTL_NX = timedelta(hours=1)


def _envstr(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default) or ""
    return raw.split("#", 1)[0].strip()


# ── CTI ────────────────────────────────────────────────────────────────────

def cti_lookup(ip: str, force: bool = False) -> dict[str, Any]:
    """Read from cti_cache or hit the CrowdSec CTI smoke endpoint."""
    if not force:
        cached = _read_cti(ip)
        if cached and _fresh(cached.get("cached_at"), CTI_TTL):
            return cached
    key = _envstr("CROWDSEC_CTI_API_KEY", "")
    if not key:
        return {"ok": False, "error": "CROWDSEC_CTI_API_KEY not set", "ip": ip}
    try:
        r = requests.get(
            f"{CTI_BASE}/v2/smoke/{ip}",
            headers={"x-api-key": key, "Accept": "application/json"},
            timeout=8,
        )
        if r.status_code == 404:
            data = {"ip": ip, "reputation": "unknown", "found": False}
        elif r.status_code == 429:
            return {"ok": False, "error": "CTI rate-limited (40/day free tier)", "ip": ip}
        elif r.status_code >= 400:
            return {"ok": False, "error": f"CTI {r.status_code}: {r.text[:120]}", "ip": ip}
        else:
            data = r.json()
            data["found"] = True
        _write_cti(ip, data)
        return _read_cti(ip) or {"ok": True, **data}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"CTI error: {e}", "ip": ip}


def _write_cti(ip: str, data: dict) -> None:
    now = datetime.now(timezone.utc).isoformat()
    classifications = ",".join(c.get("name", "") for c in (data.get("classifications", {}) or {}).get("classifications", [])) if isinstance(data.get("classifications"), dict) else ""
    behaviors = ",".join(b.get("name", "") for b in (data.get("behaviors") or []) if isinstance(b, dict))
    score = 0
    try:
        score = int(((data.get("scores") or {}).get("overall") or {}).get("total") or 0)
    except (TypeError, ValueError):
        score = 0
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO cti_cache (ip, reputation, score, classifications, behaviors, feeds, raw_json, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
              reputation=excluded.reputation, score=excluded.score,
              classifications=excluded.classifications, behaviors=excluded.behaviors,
              feeds=excluded.feeds, raw_json=excluded.raw_json, cached_at=excluded.cached_at
            """,
            (ip, str(data.get("reputation") or ""), score,
             classifications, behaviors, "",
             json.dumps(data)[:30000], now),
        )
    finally:
        conn.close()


def _read_cti(ip: str) -> dict[str, Any] | None:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM cti_cache WHERE ip = ?", (ip,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    out = dict(row)
    try:
        out["raw"] = json.loads(row["raw_json"]) if row["raw_json"] else {}
    except json.JSONDecodeError:
        out["raw"] = {}
    return out


# ── Team Cymru ASN (free, DNS-based) ───────────────────────────────────────

def cymru_lookup(ip: str) -> dict[str, Any]:
    """Get ASN + AS-org from Team Cymru via DNS TXT.

    Two queries (cached separately by upstream resolver):
        1. <reversed-ip>.origin.asn.cymru.com → "ASN | prefix | CC | registry | allocated"
        2. AS<num>.asn.cymru.com            → "ASN | CC | registry | allocated | AS-name"
    """
    if not _DNS_OK:
        return {"ok": False, "error": "dnspython not installed"}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "not a valid IP"}

    if isinstance(addr, ipaddress.IPv4Address):
        rev = ".".join(reversed(str(addr).split(".")))
        zone = CYMRU_ORIGIN
    else:
        rev = ".".join(reversed(addr.exploded.replace(":", "")))
        zone = CYMRU_ORIGIN6

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 4.0
        answers = resolver.resolve(f"{rev}.{zone}", "TXT", raise_on_no_answer=False)
        if not answers.rrset:
            return {"ok": False, "error": "no ASN data"}
        # First record only
        raw = answers[0].to_text().strip('"').strip()
        parts = [p.strip() for p in raw.split("|")]
        asn = parts[0] if parts else ""
        prefix = parts[1] if len(parts) > 1 else ""
        cc = parts[2] if len(parts) > 2 else ""
        as_name = ""
        if asn:
            try:
                as_answers = resolver.resolve(f"AS{asn}.{CYMRU_AS}", "TXT", raise_on_no_answer=False)
                if as_answers.rrset:
                    as_raw = as_answers[0].to_text().strip('"').strip()
                    as_parts = [p.strip() for p in as_raw.split("|")]
                    if len(as_parts) >= 5:
                        as_name = as_parts[4]
            except Exception:  # noqa: BLE001
                pass
        return {"ok": True, "ip": ip, "asn": f"AS{asn}" if asn else "", "as_org": as_name,
                "prefix": prefix, "country": cc}
    except dns.resolver.NXDOMAIN:
        return {"ok": False, "ip": ip, "error": "NXDOMAIN"}
    except dns.exception.Timeout:
        return {"ok": False, "ip": ip, "error": "dns timeout"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ip": ip, "error": str(e)}


# ── rDNS ───────────────────────────────────────────────────────────────────

def rdns_lookup(ip: str) -> dict[str, Any]:
    """Return {ok, hostname, error} for a single PTR lookup, with cache."""
    cached = _read_rdns_cache(ip)
    if cached and _fresh(cached.get("cached_at"), RDNS_TTL_OK if cached.get("rdns") else RDNS_TTL_NX):
        return {"ok": bool(cached.get("rdns")), "ip": ip, "hostname": cached.get("rdns") or ""}

    if not _DNS_OK:
        return {"ok": False, "error": "dnspython not installed"}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 3.0
        rev = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev, "PTR", raise_on_no_answer=False)
        if answers.rrset and len(answers) > 0:
            host = str(answers[0]).rstrip(".")
            _write_rdns(ip, host)
            return {"ok": True, "ip": ip, "hostname": host}
        _write_rdns(ip, "")
        return {"ok": False, "ip": ip, "error": "no PTR"}
    except dns.resolver.NXDOMAIN:
        _write_rdns(ip, "")
        return {"ok": False, "ip": ip, "error": "NXDOMAIN"}
    except dns.exception.Timeout:
        return {"ok": False, "ip": ip, "error": "dns timeout"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ip": ip, "error": str(e)}


def _write_rdns(ip: str, hostname: str) -> None:
    """Stash rDNS in geo_cache (added 'rdns' column in migrations)."""
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO geo_cache (ip, rdns, cached_at) VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET rdns = excluded.rdns
            """,
            (ip, hostname, now),
        )
    finally:
        conn.close()


def _read_rdns_cache(ip: str) -> dict[str, Any] | None:
    conn = get_conn()
    try:
        row = conn.execute("SELECT rdns, cached_at FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


# ── WHOIS (cymru-style, port 43) ───────────────────────────────────────────

def whois_lookup(ip: str) -> dict[str, Any]:
    """Cheap WHOIS via whois.cymru.com (port 43 TCP). Cached 7d.

    For a richer experience operators can configure a real RDAP endpoint —
    cymru's output is intentionally narrow (ASN + country) but free + reliable.
    """
    cached = _read_whois(ip)
    if cached and _fresh(cached.get("cached_at"), WHOIS_TTL):
        return {"ok": True, **cached}
    try:
        s = socket.create_connection(("whois.cymru.com", 43), timeout=4)
        s.sendall(f" -v {ip}\n".encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 16384:
                break
        s.close()
        raw = data.decode(errors="ignore").strip()
        # parse: data has a header + data line, " | " separated.
        org = country = netname = ""
        for line in raw.splitlines():
            if line.startswith("AS"):  # data
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 7:
                    netname = parts[2]   # prefix
                    country = parts[3]
                    org = parts[6]
        _write_whois(ip, org=org, country=country, netname=netname, raw=raw)
        return _read_whois(ip) or {"ok": True, "org": org, "country": country}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "ip": ip, "error": str(e)}


def _write_whois(ip: str, org: str = "", country: str = "", netname: str = "",
                  abuse_email: str = "", raw: str = "") -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO whois_cache (ip, netname, org, country, abuse_email, raw, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
              netname=excluded.netname, org=excluded.org, country=excluded.country,
              abuse_email=excluded.abuse_email, raw=excluded.raw, cached_at=excluded.cached_at
            """,
            (ip, netname, org, country, abuse_email, raw[:8000], now),
        )
    finally:
        conn.close()


def _read_whois(ip: str) -> dict[str, Any] | None:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM whois_cache WHERE ip = ?", (ip,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


# ── Aggregate ──────────────────────────────────────────────────────────────

def enrichment_for_ip(ip: str) -> dict[str, Any]:
    """Read every cached enrichment without making any network calls."""
    conn = get_conn()
    try:
        geo = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
        cti = conn.execute("SELECT * FROM cti_cache WHERE ip = ?", (ip,)).fetchone()
        whois = conn.execute("SELECT * FROM whois_cache WHERE ip = ?", (ip,)).fetchone()
        scenarios = conn.execute(
            """
            SELECT scenario, origin, origin_source, duration, first_seen_at, last_seen_at, deleted_at
            FROM decisions WHERE value = ? ORDER BY id DESC LIMIT 50
            """,
            (ip,),
        ).fetchall()
        sources_seen = conn.execute(
            "SELECT source_name, last_seen_at FROM ip_sources WHERE ip = ? ORDER BY last_seen_at DESC",
            (ip,),
        ).fetchall()
    finally:
        conn.close()
    return {
        "ip": ip,
        "geo": dict(geo) if geo else None,
        "cti": dict(cti) if cti else None,
        "whois": dict(whois) if whois else None,
        "scenarios": [dict(r) for r in scenarios],
        "sources_seen": [dict(r) for r in sources_seen],
    }


# ── Worker ─────────────────────────────────────────────────────────────────

class IntelWorker:
    """Background thread that enriches recently-banned IPs.

    Pulls active IPs whose geo OR rdns OR asn rows are missing/stale, and
    calls the relevant providers with a 1s sleep between requests to keep
    well under Cymru/CTI rate limits. CTI is only called when the key is set.
    """

    def __init__(self, interval_sec: int = 60, per_cycle: int = 30):
        self.interval = max(10, int(interval_sec))
        self.per_cycle = max(1, int(per_cycle))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.cycles = 0
        self.last_filled = 0
        self.last_error = ""

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="protek-intel", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        self._stop.wait(30)  # let other workers populate decisions first
        while not self._stop.is_set():
            try:
                self.cycle()
            except Exception as e:  # noqa: BLE001
                log.exception("intel worker crashed: %s", e)
                self.last_error = str(e)
            self._stop.wait(self.interval)

    def cycle(self) -> int:
        ips = self._pick_targets(self.per_cycle)
        filled = 0
        cti_key_present = bool(_envstr("CROWDSEC_CTI_API_KEY"))
        for ip in ips:
            if self._stop.is_set():
                break
            cymru_lookup(ip)         # writes via geo_cache.asn through caller? No — Cymru just returns
            res = cymru_lookup(ip)
            if res.get("ok"):
                _persist_asn(ip, res.get("asn", ""), res.get("as_org", ""))
            rdns_lookup(ip)
            if cti_key_present:
                cti_lookup(ip)
            time.sleep(0.5)
            filled += 1
        self.cycles += 1
        self.last_filled = filled
        self.last_error = ""
        return filled

    def _pick_targets(self, limit: int) -> list[str]:
        cutoff = (datetime.now(timezone.utc) - ASN_TTL).isoformat()
        conn = get_conn()
        try:
            rows = conn.execute(
                """
                SELECT DISTINCT d.value
                FROM decisions d
                LEFT JOIN geo_cache g ON g.ip = d.value
                WHERE d.deleted_at IS NULL
                  AND d.scope = 'Ip'
                  AND d.value NOT LIKE '%:%'
                  AND (g.asn IS NULL OR g.asn = '' OR g.cached_at < ?)
                ORDER BY d.id DESC LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        finally:
            conn.close()
        return [r["value"] for r in rows if r["value"]]


def _persist_asn(ip: str, asn: str, as_org: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO geo_cache (ip, asn, as_org, cached_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET asn=excluded.asn, as_org=excluded.as_org, cached_at=excluded.cached_at
            """,
            (ip, asn, as_org, now),
        )
        # Also stamp the decisions rows for fast filtering on the table view.
        conn.execute("UPDATE decisions SET asn = ?, as_org = ? WHERE value = ?", (asn, as_org, ip))
    finally:
        conn.close()


# ── helpers ────────────────────────────────────────────────────────────────

def _fresh(iso_str: str | None, ttl: timedelta) -> bool:
    if not iso_str:
        return False
    try:
        ts = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False
    return (datetime.now(timezone.utc) - ts) < ttl
