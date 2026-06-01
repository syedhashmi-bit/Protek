"""
ml_anomaly.py — Phase 62. Isolation-Forest anomaly detection over per-IP
features.

Goal: surface IPs that are weird relative to your own LAPI's recent history,
even when no CrowdSec scenario fired on them. Operator can investigate and
decide; we never auto-ban from ML.

Per-IP feature vector (current implementation):
    1. scenario_count       distinct scenarios this IP triggered
    2. source_count         distinct origin_sources reporting
    3. lifetime_hours       (now - first_seen) in hours
    4. recent_hits          decisions touching this IP in the last 24h
    5. cti_score            0..5 from cached cti_cache
    6. asn_size             count of other distinct IPs from this ASN
    7. is_capi              binary: 1 if origin starts with "lists:"
    8. is_local             binary: 1 if origin = "crowdsec"

Training: nightly on the last 30d of decisions. Recommend-only.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from db import get_conn

log = logging.getLogger("protek.ml")

# Lazy import — sklearn is heavy and we don't want to take down the poller
# if the install drifts. The score() function returns gracefully empty if
# sklearn isn't importable.


def _load_sklearn():
    try:
        from sklearn.ensemble import IsolationForest  # noqa: F401
        import numpy as np  # noqa: F401
        return True
    except ImportError:
        return False


def _features() -> tuple[list[list[float]], list[str]]:
    """Build the (X, ips) matrix for training/scoring."""
    conn = get_conn()
    try:
        rows = conn.execute(
            """
            SELECT d.value AS ip,
                   COUNT(DISTINCT d.scenario)      AS scen_count,
                   COUNT(DISTINCT d.origin_source) AS src_count,
                   MIN(d.first_seen_at)            AS first_seen,
                   COUNT(*)                        AS hits_24h_estimate,
                   MAX(d.asn)                      AS asn,
                   MAX(d.origin)                   AS origin
            FROM decisions d
            WHERE d.deleted_at IS NULL
              AND d.first_seen_at >= ?
            GROUP BY d.value
            HAVING COUNT(*) > 0
            LIMIT 5000
            """,
            ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),),
        ).fetchall()
        # CTI scores in one shot
        cti_map = {r["ip"]: 0 for r in rows}
        if rows:
            placeholders = ",".join("?" * len(rows))
            for c in conn.execute(
                f"SELECT ip, raw_json FROM cti_cache WHERE ip IN ({placeholders})",
                [r["ip"] for r in rows],
            ).fetchall():
                try:
                    s = json.loads(c["raw_json"] or "{}").get("score") or 0
                    cti_map[c["ip"]] = int(s)
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass
        # ASN size — distinct IPs per ASN in active set
        asn_counts: dict[str, int] = {}
        for c in conn.execute(
            "SELECT asn, COUNT(DISTINCT value) AS n FROM decisions "
            "WHERE deleted_at IS NULL AND asn != '' AND asn IS NOT NULL "
            "GROUP BY asn"
        ).fetchall():
            asn_counts[c["asn"]] = int(c["n"])
    finally:
        conn.close()

    X: list[list[float]] = []
    ips: list[str] = []
    now = datetime.now(timezone.utc)
    for r in rows:
        ip = r["ip"]
        first_seen = r["first_seen"]
        try:
            t = datetime.fromisoformat((first_seen or "").replace("Z", "+00:00"))
            lifetime_h = max(0.0, (now - t).total_seconds() / 3600)
        except (ValueError, AttributeError):
            lifetime_h = 0.0
        origin = r["origin"] or ""
        X.append([
            float(r["scen_count"] or 0),
            float(r["src_count"] or 0),
            lifetime_h,
            float(r["hits_24h_estimate"] or 0),
            float(cti_map.get(ip, 0)),
            float(asn_counts.get(r["asn"] or "", 0)),
            1.0 if origin.startswith("lists:") else 0.0,
            1.0 if origin == "crowdsec" else 0.0,
        ])
        ips.append(ip)
    return X, ips


def score(top_n: int = 50) -> dict:
    """Run isolation-forest on the recent feature set and return the top-N
    most anomalous IPs. Returns {trained_on, top: [...]}. Empty when sklearn
    isn't installed or there are fewer than 20 samples."""
    if not _load_sklearn():
        return {"trained_on": 0, "top": [], "error": "sklearn not installed"}
    from sklearn.ensemble import IsolationForest
    import numpy as np

    X, ips = _features()
    if len(X) < 20:
        return {"trained_on": len(X), "top": [],
                "error": "not enough samples (need 20+)"}
    arr = np.array(X, dtype=float)
    model = IsolationForest(n_estimators=100, contamination="auto",
                             random_state=42, n_jobs=1)
    model.fit(arr)
    scores = model.score_samples(arr)
    # Lower score = more anomalous in sklearn's IsolationForest
    order = np.argsort(scores)  # ascending → most anomalous first
    top: list[dict] = []
    for idx in order[:top_n]:
        idx = int(idx)
        top.append({
            "ip": ips[idx],
            "anomaly_score": float(scores[idx]),
            "features": {
                "scenario_count": X[idx][0], "source_count": X[idx][1],
                "lifetime_hours": round(X[idx][2], 1),
                "recent_hits": X[idx][3], "cti_score": X[idx][4],
                "asn_size": X[idx][5], "is_capi": X[idx][6],
                "is_local": X[idx][7],
            },
        })
    return {"trained_on": len(X), "top": top,
            "computed_at": datetime.now(timezone.utc).isoformat()}
