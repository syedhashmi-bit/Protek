"""
reputation.py — Phase 58. Composite per-IP reputation scoring.

Score = 0–100, derived from:
    cti_score              0..20  (CrowdSec CTI smoke endpoint score)
    scenario_severity      0..30  (max severity of scenarios that hit this IP)
    cross_source_agreement 0..20  (# of distinct origin_sources reporting)
    age_decay              0..15  (recency — newer hits score higher)
    cti_behaviors          0..15  (e.g. ssh:bruteforce, http:exploit weights)

Three tiers:
    auto    ≥ settings.reputation.auto_threshold     (default 80)
    queue   ≥ settings.reputation.queue_threshold    (default 50)
    monitor < queue_threshold

Tiers are advisory — they're surfaced on /attackers/<ip> and exposed to the
reconciler as `min_reputation` per-bouncer filter. Operators tune thresholds
per-bouncer in the config_json: `"min_reputation": 50` on a Cloudflare
target means "only push IPs scoring ≥ 50 to CF" (great for the 10k cap).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from db import get_conn, get_setting

log = logging.getLogger("protek.reputation")

SCENARIO_SEVERITY: dict[str, int] = {
    # High-severity (CVE-style) → 30
    "crowdsecurity/http-cve-2021-41773": 30,
    "crowdsecurity/http-cve-2021-42013": 30,
    "crowdsecurity/CVE-2017-9841": 28,
    "crowdsecurity/thinkphp-cve-2018-20062": 28,
    "crowdsecurity/apache_log4j2_cve-2021-44228": 30,
    "crowdsecurity/http-backdoors-attempts": 28,
    # Active exploitation attempts → 25
    "crowdsecurity/http-sensitive-files": 22,
    "crowdsecurity/http-admin-interface-probing": 20,
    "crowdsecurity/http-open-proxy": 18,
    # Brute force → 22
    "crowdsecurity/ssh-bf": 22,
    "crowdsecurity/ssh-slow-bf": 18,
    "crowdsecurity/ssh-bf_user-enum": 22,
    # Reconnaissance → 12
    "crowdsecurity/http-probing": 14,
    "crowdsecurity/http-bad-user-agent": 12,
    "crowdsecurity/http-technology-probing": 10,
    "crowdsecurity/http-crawl-non_statics": 8,
    # CAPI / community labels (generic buckets, lower weight)
    "http:exploit": 18,
    "http:scan": 10,
    "ssh:bruteforce": 18,
}
DEFAULT_SEVERITY = 12

BEHAVIOR_WEIGHTS: dict[str, int] = {
    "ssh:bruteforce": 5,
    "http:exploit": 5,
    "http:scan": 3,
    "http:bruteforce": 4,
    "spam:": 2,
    "tcp:scan": 2,
    "generic:vuln-scan": 4,
}


def _setting_int(key: str, default: int) -> int:
    v = get_setting(key)
    try:
        return int(v) if v else default
    except (TypeError, ValueError):
        return default


def compute(ip: str) -> dict[str, Any]:
    """Compute reputation score + breakdown for a single IP. Cached in
    `reputation_cache` for ~6 hours; called explicitly on attacker-page load
    or lazily from the reconciler when `min_reputation` filter is in use."""
    conn = get_conn()
    try:
        # Aggregate scenarios + origin_sources for this IP
        rows = conn.execute(
            "SELECT scenario, origin_source, first_seen_at "
            "FROM decisions WHERE value = ? AND deleted_at IS NULL",
            (ip,),
        ).fetchall()
        if not rows:
            return {"ip": ip, "score": 0, "tier": "monitor",
                    "breakdown": {"reason": "no active decisions"}}

        scenarios = {r["scenario"] for r in rows if r["scenario"]}
        sources = {r["origin_source"] for r in rows if r["origin_source"]}
        first_seen = min((r["first_seen_at"] for r in rows if r["first_seen_at"]),
                         default=None)

        # CTI lookup (cached, never blocks on network)
        cti_row = conn.execute(
            "SELECT raw_json FROM cti_cache WHERE ip = ?", (ip,)
        ).fetchone()
        cti_score = 0
        cti_behaviors: list[str] = []
        if cti_row and cti_row["raw_json"]:
            try:
                cti = json.loads(cti_row["raw_json"])
                # CrowdSec CTI returns `score` 0..5 normally
                cti_score = int(cti.get("score") or 0)
                cti_behaviors = [b.get("name", "") for b in (cti.get("behaviors") or [])]
            except (json.JSONDecodeError, ValueError, TypeError):
                pass
    finally:
        conn.close()

    # Component scores
    s_cti = min(20, cti_score * 4)  # CTI 5 → 20

    s_scen = 0
    for scen in scenarios:
        s_scen = max(s_scen, SCENARIO_SEVERITY.get(scen, DEFAULT_SEVERITY))

    s_sources = min(20, len(sources) * 4)  # 5+ sources → 20

    s_age = 15
    if first_seen:
        try:
            t = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            days = (datetime.now(timezone.utc) - t).days
            # 0d=15, 7d=10, 30d=5, 90d+=0
            s_age = max(0, 15 - int(days * 0.5))
        except (ValueError, AttributeError):
            pass

    s_behaviors = 0
    for b in cti_behaviors:
        for prefix, weight in BEHAVIOR_WEIGHTS.items():
            if b.startswith(prefix):
                s_behaviors += weight
    s_behaviors = min(15, s_behaviors)

    total = s_cti + s_scen + s_sources + s_age + s_behaviors
    total = max(0, min(100, total))

    auto_t = _setting_int("reputation.auto_threshold", 80)
    queue_t = _setting_int("reputation.queue_threshold", 50)
    tier = "auto" if total >= auto_t else ("queue" if total >= queue_t else "monitor")

    breakdown = {
        "cti_score": s_cti, "scenario_severity": s_scen,
        "cross_source_agreement": s_sources, "age_decay": s_age,
        "cti_behaviors": s_behaviors,
        "raw": {
            "scenarios": sorted(scenarios), "sources": sorted(sources),
            "cti_raw_score": cti_score, "cti_behaviors": cti_behaviors,
        },
    }
    return {"ip": ip, "score": total, "tier": tier, "breakdown": breakdown}


def cache_put(ip: str, score: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """INSERT INTO reputation_cache (ip, score, tier, breakdown_json, computed_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 score = excluded.score,
                 tier  = excluded.tier,
                 breakdown_json = excluded.breakdown_json,
                 computed_at = excluded.computed_at""",
            (ip, score["score"], score["tier"], json.dumps(score["breakdown"]), now),
        )
    finally:
        conn.close()


def cache_get(ip: str, max_age_hours: int = 6) -> dict[str, Any] | None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max_age_hours)).isoformat()
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM reputation_cache WHERE ip = ? AND computed_at >= ?",
            (ip, cutoff),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    try:
        breakdown = json.loads(row["breakdown_json"] or "{}")
    except json.JSONDecodeError:
        breakdown = {}
    return {"ip": ip, "score": row["score"], "tier": row["tier"],
            "breakdown": breakdown, "computed_at": row["computed_at"]}


def get_or_compute(ip: str) -> dict[str, Any]:
    cached = cache_get(ip)
    if cached:
        return cached
    score = compute(ip)
    cache_put(ip, score)
    return score


def bulk_compute_for_min(min_score: int) -> set[str]:
    """Return the set of IPs whose CURRENT score is >= min_score. Used by the
    reconciler's `min_reputation` per-bouncer filter. We compute for IPs that
    don't have a cached score (or have a stale one)."""
    conn = get_conn()
    try:
        active = [r["value"] for r in conn.execute(
            "SELECT DISTINCT value FROM decisions WHERE deleted_at IS NULL"
        ).fetchall()]
        # Cached fast path
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
        cached_rows = conn.execute(
            "SELECT ip, score FROM reputation_cache WHERE computed_at >= ?",
            (cutoff,),
        ).fetchall()
        cached = {r["ip"]: r["score"] for r in cached_rows}
    finally:
        conn.close()
    qualifying: set[str] = set()
    uncached: list[str] = []
    for ip in active:
        if ip in cached:
            if cached[ip] >= min_score:
                qualifying.add(ip)
        else:
            uncached.append(ip)
    # Compute up to 200 uncached per call so a freshly-set filter doesn't
    # stall the reconcile cycle. Remaining IPs fill in on subsequent cycles.
    for ip in uncached[:200]:
        s = compute(ip)
        cache_put(ip, s)
        if s["score"] >= min_score:
            qualifying.add(ip)
    return qualifying
