"""
asn_detector.py — Phase 57. ASN-level threshold detection.

Surfaces "this ASN has N+ IPs banned in the last K hours" suggestions to the
operator on /intel. Doesn't auto-block the ASN — that would be too aggressive
without human review (ASN ranges can be huge; an aggressive auto-rule could
block a residential ISP). Instead, suggestions queue in `asn_escalations`
with status='pending'; operator approves → CrowdSec gets a manual decision
for the ASN range via cscli.

Thresholds are operator-tuned via settings:
    asn_detector.min_ips        default 10
    asn_detector.window_hours   default 24
    asn_detector.cooldown_hours default 48   (don't re-suggest same ASN within this)

Runs every Nth poller cycle (default every 6 = ~1 min) — cheap query against
decisions joined with the asn column.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from db import get_conn, get_setting

log = logging.getLogger("protek.asn_detector")


def _setting_int(key: str, default: int) -> int:
    v = get_setting(key)
    try:
        return int(v) if v else default
    except (TypeError, ValueError):
        return default


def evaluate() -> list[dict]:
    """Find ASNs that crossed the threshold but don't yet have a pending /
    approved escalation. Returns the new suggestions written."""
    min_ips = _setting_int("asn_detector.min_ips", 10)
    window_h = _setting_int("asn_detector.window_hours", 24)
    cooldown_h = _setting_int("asn_detector.cooldown_hours", 48)
    since = (datetime.now(timezone.utc) - timedelta(hours=window_h)).isoformat()
    cooldown_cutoff = (datetime.now(timezone.utc) - timedelta(hours=cooldown_h)).isoformat()

    conn = get_conn()
    new_suggestions: list[dict] = []
    try:
        # Find ASNs with N+ distinct IPs in the window.
        rows = conn.execute(
            """
            SELECT d.asn, MAX(d.as_org) AS as_org,
                   COUNT(DISTINCT d.value) AS ip_count,
                   GROUP_CONCAT(DISTINCT d.value) AS sample
            FROM decisions d
            WHERE d.deleted_at IS NULL
              AND d.first_seen_at >= ?
              AND d.asn != '' AND d.asn IS NOT NULL
            GROUP BY d.asn
            HAVING COUNT(DISTINCT d.value) >= ?
            ORDER BY ip_count DESC
            """,
            (since, min_ips),
        ).fetchall()
        for r in rows:
            asn = r["asn"]
            # Suppress if there's a recent pending or recently-decided row
            # for this ASN (operator's decision should stick).
            recent = conn.execute(
                "SELECT status, decided_at FROM asn_escalations "
                "WHERE asn = ? AND (status = 'pending' "
                "OR (decided_at IS NOT NULL AND decided_at >= ?)) "
                "ORDER BY id DESC LIMIT 1",
                (asn, cooldown_cutoff),
            ).fetchone()
            if recent:
                continue
            sample_ips = (r["sample"] or "").split(",")[:10]
            now = datetime.now(timezone.utc).isoformat()
            cur = conn.execute(
                """INSERT INTO asn_escalations
                     (asn, as_org, ip_count, window_hours, sample_ips,
                      first_seen_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (asn, r["as_org"] or "", r["ip_count"], window_h,
                 json.dumps(sample_ips), now, now),
            )
            sid = cur.lastrowid
            new_suggestions.append({
                "id": sid, "asn": asn, "as_org": r["as_org"],
                "ip_count": r["ip_count"], "window_hours": window_h,
                "sample_ips": sample_ips,
            })
    finally:
        conn.close()

    if new_suggestions:
        log.info("asn_detector: %d new ASN escalation(s) suggested", len(new_suggestions))
        try:
            import siem
            for s in new_suggestions:
                siem.ship("asn.escalation", s)
        except Exception:  # noqa: BLE001
            pass
    return new_suggestions


def list_escalations(status: str | None = None, limit: int = 100) -> list[dict]:
    conn = get_conn()
    try:
        if status:
            rows = conn.execute(
                "SELECT * FROM asn_escalations WHERE status = ? "
                "ORDER BY id DESC LIMIT ?", (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM asn_escalations ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["sample_ips"] = json.loads(d["sample_ips"] or "[]")
        except json.JSONDecodeError:
            d["sample_ips"] = []
        out.append(d)
    return out


def decide(escalation_id: int, decision: str, decided_by: str = "",
           note: str = "") -> dict:
    """Operator approves or rejects a suggestion.

    On 'approve': adds a CrowdSec decision for the ASN scope (via the
    decisions table directly — Protek will mirror to bouncers next cycle).
    On 'reject': records the decision; cooldown applies before re-suggest.
    """
    if decision not in ("approved", "rejected"):
        raise ValueError("decision must be 'approved' or 'rejected'")
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM asn_escalations WHERE id = ?", (escalation_id,)
        ).fetchone()
        if not row:
            raise ValueError("escalation not found")
        conn.execute(
            "UPDATE asn_escalations SET status = ?, decided_by = ?, "
            "decided_at = ?, note = ? WHERE id = ?",
            (decision, decided_by, now, note, escalation_id),
        )
        result: dict = {"id": escalation_id, "decision": decision,
                        "asn": row["asn"]}
        if decision == "approved":
            # Insert a synthetic decision with scope=AS so it flows through
            # reconcile alongside regular IP/Range bans. Protek's bouncers
            # need to handle scope='AS' or the diff will skip these — for
            # now, we mark them and the operator can convert to actual cscli
            # rules manually.
            try:
                import time as _t
                synth_id = int(_t.time() * 1000)
                conn.execute(
                    """INSERT INTO decisions
                         (origin_source, lapi_id, value, scope, type, scenario,
                          origin, duration, until, first_seen_at, last_seen_at)
                       VALUES ('asn_detector', ?, ?, 'AS', 'ban',
                               'asn_detector/escalation', 'asn_detector',
                               '720h', ?, ?, ?)""",
                    (synth_id, row["asn"],
                     (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
                     now, now),
                )
                result["decision_id"] = synth_id
            except Exception as e:  # noqa: BLE001
                log.warning("asn approve insert decision failed: %s", e)
                result["warning"] = str(e)
    finally:
        conn.close()
    try:
        import audit
        audit.record(f"asn.escalation.{decision}", actor=decided_by,
                     target=row["asn"],
                     after={"ip_count": row["ip_count"], "as_org": row["as_org"]},
                     note=note)
    except Exception:  # noqa: BLE001
        pass
    return result
