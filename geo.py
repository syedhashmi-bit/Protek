"""
geo.py — out-of-band IP geolocation worker.

Why a worker, not inline:
  Geocoding is a network call that can take 200–800ms on cold lookups,
  and the free providers rate-limit. Doing it inside the reconcile loop
  would slow down bans. Geo lives here, drains a queue lazily, fills
  `geo_cache`, and the dashboard reads the cache — no map marker blocks
  on a network call.

Cache TTL: 7 days minimum (attacker IPs don't move that often).

Provider: ip-api.com /batch endpoint (no API key, 45 requests/min, 100
IPs per request — perfect for this workload). Fallback: ipapi.co (single
lookup, ~1k/day free). Both ToS allow self-hosted dashboards.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from db import get_conn

log = logging.getLogger("protek.geo")


class GeoWorker:
    """Background thread that fills geo_cache for any decision IP missing one.

    Drains in batches of 100 every 30s (ip-api.com batch endpoint).
    Re-queues IPs whose cache row is older than the TTL.
    """

    def __init__(self, ttl_days: int = 7, interval_sec: int = 30):
        self.ttl = timedelta(days=max(1, int(ttl_days)))
        self.interval = max(5, int(interval_sec))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.cycles: int = 0
        self.last_filled: int = 0
        self.last_error: str = ""

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="protek-geo", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        # Small delay so the first reconcile cycle populates the DB before
        # we try to read it.
        self._stop.wait(15)
        while not self._stop.is_set():
            try:
                self.cycle()
            except Exception as e:  # noqa: BLE001
                log.exception("geo worker crashed: %s", e)
                self.last_error = str(e)
            self._stop.wait(self.interval)

    def cycle(self) -> int:
        """Fetch up to 100 missing IPs and write their geo into the cache."""
        ips = self._pick_missing(limit=100)
        if not ips:
            self.cycles += 1
            self.last_filled = 0
            return 0
        rows = self._batch_lookup(ips)
        if not rows:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        conn = get_conn()
        try:
            for r in rows:
                if not r.get("ip"):
                    continue
                conn.execute(
                    """
                    INSERT INTO geo_cache (ip, country, country_code, city, lat, lon, asn, as_org, cached_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        country = excluded.country,
                        country_code = excluded.country_code,
                        city = excluded.city,
                        lat = excluded.lat,
                        lon = excluded.lon,
                        asn = excluded.asn,
                        as_org = excluded.as_org,
                        cached_at = excluded.cached_at
                    """,
                    (
                        r.get("ip"),
                        r.get("country") or "",
                        r.get("country_code") or "",
                        r.get("city") or "",
                        r.get("lat"),
                        r.get("lon"),
                        r.get("asn") or "",
                        r.get("as_org") or "",
                        now,
                    ),
                )
        finally:
            conn.close()
        self.cycles += 1
        self.last_filled = len(rows)
        self.last_error = ""
        return len(rows)

    # ── picking work ────────────────────────────────────────────────────────

    def _pick_missing(self, limit: int) -> list[str]:
        cutoff = (datetime.now(timezone.utc) - self.ttl).isoformat()
        conn = get_conn()
        try:
            # Active IP-scope decisions whose geo is missing or stale.
            rows = conn.execute(
                """
                SELECT DISTINCT d.value
                FROM decisions d
                LEFT JOIN geo_cache g ON g.ip = d.value
                WHERE d.deleted_at IS NULL
                  AND d.scope = 'Ip'
                  AND d.value NOT LIKE '%:%'
                  AND (g.ip IS NULL OR g.cached_at < ?)
                ORDER BY d.id DESC
                LIMIT ?
                """,
                (cutoff, limit),
            ).fetchall()
        finally:
            conn.close()
        return [r["value"] for r in rows if r["value"]]

    # ── provider ───────────────────────────────────────────────────────────

    def _batch_lookup(self, ips: list[str]) -> list[dict[str, Any]]:
        """ip-api.com /batch — 100 IPs per request, no API key, 45 req/min."""
        try:
            payload = [
                {"query": ip, "fields": "status,country,countryCode,city,lat,lon,as,query"}
                for ip in ips
            ]
            r = requests.post("http://ip-api.com/batch", json=payload, timeout=12)
            r.raise_for_status()
            data = r.json()
        except Exception as e:  # noqa: BLE001
            self.last_error = f"ip-api.com batch: {e}"
            log.warning("geo batch lookup failed: %s", e)
            return []
        out: list[dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            if item.get("status") != "success":
                continue
            # "as" field shape: "AS15169 Google LLC" — split into number/org.
            as_full = (item.get("as") or "").strip()
            asn = ""
            as_org = ""
            if as_full:
                parts = as_full.split(" ", 1)
                asn = parts[0]
                as_org = parts[1] if len(parts) > 1 else ""
            out.append({
                "ip": item.get("query"),
                "country": item.get("country") or "",
                "country_code": item.get("countryCode") or "",
                "city": item.get("city") or "",
                "lat": item.get("lat"),
                "lon": item.get("lon"),
                "asn": asn,
                "as_org": as_org,
            })
        return out


def points_for_map(limit: int = 500) -> list[dict[str, Any]]:
    """Return cached IP points usable by Leaflet — IP × geo × top scenario."""
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT d.value AS ip, d.scenario, d.origin,
                   g.country, g.country_code, g.city, g.lat, g.lon, g.asn, g.as_org
            FROM decisions d
            JOIN geo_cache g ON g.ip = d.value
            WHERE d.deleted_at IS NULL
              AND d.scope = 'Ip'
              AND g.lat IS NOT NULL AND g.lon IS NOT NULL
            ORDER BY d.id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def geo_for_ip(ip: str) -> dict[str, Any] | None:
    """Single-row lookup for /api/geo/<ip>."""
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None
