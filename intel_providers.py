"""
intel_providers.py — Phases 59 + 60.

Additional enrichment providers alongside the existing CTI / Cymru / WHOIS /
rDNS in intel.py. Each provider is gated on its own env var; missing keys =
silently skipped.

Providers shipped:
    AbuseIPDB        — abuseipdb.com Check Endpoint v2 (1000/day free tier)
    AlienVault OTX   — otx.alienvault.com pulses by IP indicator (free)
    Spamhaus DROP    — downloadable plain-text DROP / EDROP lists (free)
    Tor exit list    — check.torproject.org/exit-addresses (free, daily refresh)
    Proxy/VPN        — proxycheck.io (1000/day free tier) — optional

All results are cached to keep network out of the reconcile hot path. The
Tor exit + Spamhaus lists pull bulk every 24h; per-IP providers cache 7d
per lookup (matches the existing intel cache TTL).
"""

from __future__ import annotations

import json
import logging
import os
import socket
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from db import get_conn, get_setting, set_setting

log = logging.getLogger("protek.intel_providers")


def _envstr(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default) or ""
    return raw.split("#", 1)[0].strip()


def _ip_add_tag(ip: str, tag: str, source: str = "",
                expires_at: str | None = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO ip_tags (ip, tag, source, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(ip, tag) DO UPDATE SET
                 source = excluded.source,
                 expires_at = excluded.expires_at,
                 created_at = excluded.created_at""",
            (ip, tag, source, now, expires_at),
        )
    finally:
        conn.close()


def ip_tags(ip: str) -> list[dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT tag, source, created_at, expires_at FROM ip_tags "
            "WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now'))",
            (ip,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# ── AbuseIPDB ──────────────────────────────────────────────────────────────

def abuseipdb_lookup(ip: str, max_age_days: int = 90) -> dict[str, Any]:
    """Check endpoint v2 — returns abuseConfidenceScore (0..100) + categories."""
    key = _envstr("ABUSEIPDB_API_KEY")
    if not key:
        return {"ok": False, "ip": ip, "error": "ABUSEIPDB_API_KEY not set"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=8,
        )
    except requests.RequestException as e:
        return {"ok": False, "ip": ip, "error": str(e)}
    if r.status_code == 429:
        return {"ok": False, "ip": ip, "error": "abuseipdb rate-limited (free tier 1000/day)"}
    if r.status_code >= 400:
        return {"ok": False, "ip": ip, "error": f"HTTP {r.status_code}"}
    data = r.json().get("data") or {}
    score = int(data.get("abuseConfidenceScore") or 0)
    if score >= 75:
        _ip_add_tag(ip, "abuseipdb-confident", source="abuseipdb",
                    expires_at=(datetime.now(timezone.utc) + timedelta(days=14)).isoformat())
    return {"ok": True, "ip": ip, "abuse_confidence": score,
            "reports": int(data.get("totalReports") or 0),
            "country": data.get("countryCode") or "",
            "isp": data.get("isp") or "",
            "raw": data}


# ── AlienVault OTX ─────────────────────────────────────────────────────────

def otx_lookup(ip: str) -> dict[str, Any]:
    """OTX IPv4 indicator section. No key required for general pulse lookups."""
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            timeout=8,
        )
    except requests.RequestException as e:
        return {"ok": False, "ip": ip, "error": str(e)}
    if r.status_code >= 400:
        return {"ok": False, "ip": ip, "error": f"HTTP {r.status_code}"}
    data = r.json() or {}
    pulse_count = int((data.get("pulse_info") or {}).get("count") or 0)
    if pulse_count >= 1:
        _ip_add_tag(ip, "otx-pulse", source="alienvault-otx",
                    expires_at=(datetime.now(timezone.utc) + timedelta(days=14)).isoformat())
    return {"ok": True, "ip": ip, "pulse_count": pulse_count,
            "reputation": int(data.get("reputation") or 0),
            "raw": {"pulses": [(p.get("name") or "")[:60]
                                for p in ((data.get("pulse_info") or {}).get("pulses") or [])[:5]]}}


# ── Spamhaus DROP / EDROP (bulk download) ──────────────────────────────────

def spamhaus_refresh() -> dict[str, Any]:
    """Pulls Spamhaus DROP + EDROP lists and tags matching IPs as 'spamhaus-drop'.
    Bulk download is the official method; runs ~daily."""
    out = {"drop": 0, "edrop": 0, "tagged": 0, "errors": []}
    for label, url in (("drop", "https://www.spamhaus.org/drop/drop.txt"),
                       ("edrop", "https://www.spamhaus.org/drop/edrop.txt")):
        try:
            r = requests.get(url, timeout=12, headers={"User-Agent": "protek/1.1"})
            if r.status_code >= 400:
                out["errors"].append(f"{label} HTTP {r.status_code}")
                continue
            cidrs = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                cidr = line.split(";", 1)[0].strip()
                if cidr:
                    cidrs.append(cidr)
            out[label] = len(cidrs)
            # Tag any active decision IPs whose addresses fall in a DROP CIDR.
            import ipaddress
            networks = []
            for c in cidrs:
                try:
                    networks.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass
            conn = get_conn()
            try:
                active = [r["value"] for r in conn.execute(
                    "SELECT DISTINCT value FROM decisions WHERE deleted_at IS NULL"
                ).fetchall()]
            finally:
                conn.close()
            for ip in active:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                for net in networks:
                    if addr in net:
                        _ip_add_tag(ip, f"spamhaus-{label}", source=f"spamhaus-{label}",
                                    expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat())
                        out["tagged"] += 1
                        break
        except requests.RequestException as e:
            out["errors"].append(f"{label}: {e}")
    set_setting("spamhaus.last_refresh_at", datetime.now(timezone.utc).isoformat())
    return out


# ── Tor exit list (bulk, daily) ─────────────────────────────────────────────

def tor_refresh() -> dict[str, Any]:
    out = {"exits": 0, "tagged": 0, "errors": []}
    try:
        r = requests.get("https://check.torproject.org/exit-addresses",
                         timeout=10, headers={"User-Agent": "protek/1.1"})
        if r.status_code >= 400:
            out["errors"].append(f"HTTP {r.status_code}")
            return out
        ips: set[str] = set()
        for line in r.text.splitlines():
            if line.startswith("ExitAddress "):
                ips.add(line.split()[1])
        out["exits"] = len(ips)
        # Tag any matching active decisions
        conn = get_conn()
        try:
            active = {r["value"] for r in conn.execute(
                "SELECT DISTINCT value FROM decisions WHERE deleted_at IS NULL"
            ).fetchall()}
        finally:
            conn.close()
        for ip in ips & active:
            _ip_add_tag(ip, "tor-exit", source="torproject.org",
                        expires_at=(datetime.now(timezone.utc) + timedelta(days=2)).isoformat())
            out["tagged"] += 1
    except requests.RequestException as e:
        out["errors"].append(str(e))
    set_setting("tor.last_refresh_at", datetime.now(timezone.utc).isoformat())
    return out


# ── Proxy/VPN (proxycheck.io) ──────────────────────────────────────────────

def proxycheck_lookup(ip: str) -> dict[str, Any]:
    key = _envstr("PROXYCHECK_API_KEY")
    if not key:
        return {"ok": False, "ip": ip, "error": "PROXYCHECK_API_KEY not set"}
    try:
        r = requests.get(
            f"https://proxycheck.io/v2/{ip}",
            params={"key": key, "vpn": "1", "risk": "1"},
            timeout=8,
        )
    except requests.RequestException as e:
        return {"ok": False, "ip": ip, "error": str(e)}
    if r.status_code >= 400:
        return {"ok": False, "ip": ip, "error": f"HTTP {r.status_code}"}
    payload = r.json() or {}
    info = payload.get(ip) or {}
    proxy_yes = (info.get("proxy") or "").lower() == "yes"
    typ = info.get("type") or ""
    risk = int(info.get("risk") or 0)
    if proxy_yes:
        _ip_add_tag(ip, f"proxy-{typ.lower() or 'unknown'}", source="proxycheck.io",
                    expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat())
    return {"ok": True, "ip": ip, "proxy": proxy_yes, "type": typ, "risk": risk,
            "raw": info}


# ── Bulk refresh dispatcher (called daily by poller) ───────────────────────

def maybe_refresh_bulk() -> dict[str, Any]:
    """Refreshes Tor + Spamhaus once per day. No-op until ≥20h since last."""
    now = datetime.now(timezone.utc)
    out: dict[str, Any] = {}
    last_tor = get_setting("tor.last_refresh_at") or ""
    if not last_tor or _hours_since(last_tor, now) >= 20:
        out["tor"] = tor_refresh()
    last_sp = get_setting("spamhaus.last_refresh_at") or ""
    if not last_sp or _hours_since(last_sp, now) >= 20:
        out["spamhaus"] = spamhaus_refresh()
    return out


def _hours_since(iso: str, now: datetime) -> float:
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (now - t).total_seconds() / 3600
    except (ValueError, AttributeError):
        return 1e9
