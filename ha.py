"""
ha.py — Arc 11 phase 65. Active-passive HA scaffolding.

Pairs with phase 64 (Litestream WAL replication). DB state already
flows from the primary VPS to a hot standby; this module adds the
operator-side promote/demote workflow + the run-time gate that keeps
the standby's poller quiet.

Roles:
  primary  — runs the poller, owns MT writes, writes the heartbeat
             that the standby watches.
  standby  — `/admin/ha`, `/health`, and the read-only dashboard are
             reachable, but the poller is NOT started. SQLite is
             being filled by Litestream restore-from-replica; if the
             standby were to also start its poller, it'd race the
             replica and the diff would scribble at the MT.

Role resolution:
  1. `ha.role` setting in the DB (operator-promoted via /admin/ha).
  2. `HA_ROLE` env var (boot default).
  3. Implicit "primary" if neither is set — preserves backwards
     compat for installs that never opted into HA.

The current schema reuses `poller.last_at` (already written every
cycle) as the heartbeat — no new table needed. The standby reads
this via the Litestream-replicated DB; lag = (now - last_at).

Failover today is **manual**: operator sees the heartbeat is stale
on /admin/ha (or pages from /health on the primary going 503),
SSHes to the standby, hits the Promote button. Auto-failover is
deferred because it needs split-brain protection (network
partitions where the primary is alive but unreachable from the
standby) — solving that without a real consensus layer is
genuinely hard. Scaffolding now, automation in a future phase.

Break-glass: an admin can always flip `ha.role` via direct
`set_setting('ha.role', 'primary')` on the host, even if /admin/ha
is unreachable (e.g. the standby's UI is also down). Same shape
as the .env-anchored admin override.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from db import get_setting, set_setting

log = logging.getLogger("protek.ha")


VALID_ROLES = ("primary", "standby")
DEFAULT_HEARTBEAT_STALE_SEC = 60


def _envstr(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").split("#", 1)[0].strip()


def role() -> str:
    """Resolve the current role. Returns "primary" or "standby"."""
    db_override = (get_setting("ha.role") or "").strip().lower()
    if db_override in VALID_ROLES:
        return db_override
    env_role = _envstr("HA_ROLE").lower()
    if env_role in VALID_ROLES:
        return env_role
    return "primary"


def is_standby() -> bool:
    return role() == "standby"


def is_primary() -> bool:
    return role() == "primary"


# ── promote / demote (operator-driven) ────────────────────────────────────


def _promote_impl(actor: str = "system", reason: str = "") -> dict[str, Any]:
    """Internal — flips the DB setting and writes the audit row. The
    HTTP layer wraps this with confirmation + RBAC."""
    old = role()
    set_setting("ha.role", "primary")
    set_setting("ha.last_role_change_at", datetime.now(timezone.utc).isoformat())
    set_setting("ha.last_role_change_actor", actor)
    set_setting("ha.last_role_change_reason", reason[:300])
    _audit("ha.promote", {"actor": actor, "reason": reason, "old": old,
                            "new": "primary"})
    log.info("HA promoted: %s → primary (actor=%s, reason=%s)",
             old, actor, reason)
    return {"old_role": old, "new_role": "primary", "actor": actor,
            "reason": reason}


def _demote_impl(actor: str = "system", reason: str = "") -> dict[str, Any]:
    old = role()
    set_setting("ha.role", "standby")
    set_setting("ha.last_role_change_at", datetime.now(timezone.utc).isoformat())
    set_setting("ha.last_role_change_actor", actor)
    set_setting("ha.last_role_change_reason", reason[:300])
    _audit("ha.demote", {"actor": actor, "reason": reason, "old": old,
                           "new": "standby"})
    log.info("HA demoted: %s → standby (actor=%s, reason=%s)",
             old, actor, reason)
    return {"old_role": old, "new_role": "standby", "actor": actor,
            "reason": reason}


# ── heartbeat (read-only — primary writes it via poller cycle) ────────────


def last_heartbeat_iso() -> str:
    """ISO timestamp of the last poller cycle. The poller writes
    `poller.last_at` at the bottom of every tick — we reuse that as
    the HA heartbeat to avoid duplicating state."""
    return get_setting("poller.last_at") or ""


def heartbeat_lag_seconds() -> int | None:
    iso = last_heartbeat_iso()
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return int((datetime.now(timezone.utc) - t).total_seconds())


def heartbeat_stale_threshold_sec() -> int:
    """Operator-tunable via `ha.heartbeat_stale_sec` setting. Defaults
    to 60s — long enough to ride out one slow cycle, short enough to
    flag a wedged primary within a minute."""
    try:
        return max(15, int(get_setting("ha.heartbeat_stale_sec") or DEFAULT_HEARTBEAT_STALE_SEC))
    except (TypeError, ValueError):
        return DEFAULT_HEARTBEAT_STALE_SEC


def is_heartbeat_stale() -> bool:
    lag = heartbeat_lag_seconds()
    return lag is not None and lag > heartbeat_stale_threshold_sec()


# ── summary for /admin/ha ────────────────────────────────────────────────


def summary() -> dict[str, Any]:
    """All the data /admin/ha needs in one call."""
    lag = heartbeat_lag_seconds()
    threshold = heartbeat_stale_threshold_sec()
    stale = is_heartbeat_stale()
    r = role()
    return {
        "role": r,
        "is_primary": r == "primary",
        "is_standby": r == "standby",
        "env_role":   _envstr("HA_ROLE") or "(unset)",
        "db_override": (get_setting("ha.role") or "").strip() or "(unset)",
        "last_heartbeat_at": last_heartbeat_iso() or "(never)",
        "heartbeat_lag_seconds": lag,
        "heartbeat_stale_threshold": threshold,
        "heartbeat_stale": stale,
        "last_role_change_at": get_setting("ha.last_role_change_at") or "(never)",
        "last_role_change_actor": get_setting("ha.last_role_change_actor") or "",
        "last_role_change_reason": get_setting("ha.last_role_change_reason") or "",
        "auto_failover_enabled":
            (get_setting("ha.auto_failover_enabled") or "0") == "1",
    }


# ── audit helper ─────────────────────────────────────────────────────────


def _audit(action: str, payload: dict[str, Any]) -> None:
    import json
    from db import get_conn
    try:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO audit_log (created_at, actor, action, after_json) "
                "VALUES (?, ?, ?, ?)",
                (datetime.now(timezone.utc).isoformat(),
                 payload.get("actor", "system"),
                 action, json.dumps(payload)),
            )
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass


# ── promote helper called by the HTTP route (RBAC enforced there) ─────────


def promote(actor: str, reason: str = "") -> dict[str, Any]:
    return _promote_impl(actor=actor, reason=reason)


def demote(actor: str, reason: str = "") -> dict[str, Any]:
    return _demote_impl(actor=actor, reason=reason)
