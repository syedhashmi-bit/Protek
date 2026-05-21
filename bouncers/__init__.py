"""
bouncers/ — Arc 5 multi-target adapters.

Every adapter implements the Bouncer protocol:
    name        — friendly label shown in UI
    kind        — adapter type (matches `kind` in bouncer_targets table)
    health()    — reachability probe
    snapshot()  — current entries (filtered to Protek-owned)
    apply(to_add, to_remove_ids) — push diff

`load_all_targets()` returns the env-driven MikroTik (legacy phase-2 target)
plus every enabled row in `bouncer_targets`. The reconciler iterates this
list — every bouncer gets the same desired-decisions, each computes its
own diff against its own snapshot.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

log = logging.getLogger("protek.bouncers")


class Bouncer(Protocol):
    name: str
    kind: str

    def is_configured(self) -> bool: ...
    def health(self) -> dict[str, Any]: ...
    def snapshot(self) -> list[dict[str, Any]]: ...
    def apply(self, to_add: list[tuple[str, str]], to_remove_ids: list[str]) -> dict[str, Any]: ...


KINDS: dict[str, type] = {}


def register(kind: str):
    def deco(cls):
        KINDS[kind] = cls
        cls.kind = kind
        return cls
    return deco


def make_bouncer(name: str, kind: str, config: dict[str, Any]) -> Bouncer | None:
    cls = KINDS.get(kind)
    if not cls:
        log.warning("unknown bouncer kind: %s", kind)
        return None
    try:
        return cls(name=name, **config)
    except Exception as e:  # noqa: BLE001
        log.warning("bouncer %s/%s init failed: %s", kind, name, e)
        return None


def load_all_targets() -> list[Bouncer]:
    from db import get_conn
    out: list[Bouncer] = []
    # Env-driven legacy MikroTik adapter
    legacy_mt = MikroTikLegacyAdapter()
    if legacy_mt.is_configured():
        out.append(legacy_mt)
    # DB-driven targets
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM bouncer_targets WHERE enabled = 1 ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    for r in rows:
        try:
            cfg = json.loads(r["config_json"] or "{}")
        except json.JSONDecodeError:
            cfg = {}
        b = make_bouncer(r["name"], r["kind"], cfg)
        if b:
            out.append(b)
    return out


# Import adapters so they self-register via @register().
from .mikrotik_adapter import MikroTikLegacyAdapter  # noqa: E402,F401
from . import iptables_adapter   # noqa: E402,F401
from . import cloudflare_adapter # noqa: E402,F401
from . import pfsense_adapter    # noqa: E402,F401
from . import opnsense_adapter   # noqa: E402,F401
