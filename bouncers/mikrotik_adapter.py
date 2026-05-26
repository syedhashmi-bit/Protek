"""
Legacy MikroTik adapter — wraps the env-driven /var/www/Protek/mikrotik.py
in the new Bouncer protocol. Keeps phase-1/2 behavior identical.

IPv6 routing: RouterOS uses separate resources for IPv4 and IPv6
address-lists (/ip/... vs /ipv6/...). Adds are dispatched by IP family;
removes consult the `v4:` / `v6:` prefix added to the snapshot's `.id`.
Without this split, RouterOS rejects IPv6 entries with "<addr> is not a
valid dns name" because the v4 list parses `address` as IP-or-DNS and
v6 colons confuse the DNS parser.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from mikrotik import MikroTik, address_list_name
from reconcile import is_owned

from . import register


def _is_ipv6(addr: str) -> bool:
    """Return True for IPv6 (with or without /prefix), False otherwise."""
    try:
        return ipaddress.ip_network(addr.strip(), strict=False).version == 6
    except (ValueError, AttributeError):
        return False


def _split_id(prefixed_id: str) -> tuple[str, str]:
    """('v4:*123', ) → ('/ip/firewall/address-list', '*123').
    Bare ids (no prefix) are treated as v4 for backward compat."""
    if prefixed_id.startswith("v6:"):
        return "/ipv6/firewall/address-list", prefixed_id[3:]
    if prefixed_id.startswith("v4:"):
        return "/ip/firewall/address-list", prefixed_id[3:]
    return "/ip/firewall/address-list", prefixed_id


@register("mikrotik_env")
class MikroTikLegacyAdapter:
    """The .env-configured MikroTik target. Reads MT_HOST/MT_USERNAME/etc."""

    def __init__(self, name: str = "mikrotik", **_: Any):
        self.name = name
        self.kind = "mikrotik_env"
        self._mt = MikroTik()
        self.list_name = address_list_name()

    def is_configured(self) -> bool:
        return self._mt.is_configured()

    def health(self) -> dict[str, Any]:
        h = self._mt.health()
        return {**h, "bouncer": self.name, "kind": self.kind, "list": self.list_name}

    def snapshot(self) -> list[dict[str, Any]]:
        if not self.is_configured():
            return []
        try:
            entries = self._mt.get_address_list(self.list_name)
        except Exception:  # noqa: BLE001
            return []
        # Normalize to the diff-friendly shape — only Protek-owned rows count
        # against the diff; reconcile.is_owned filters this.
        return entries

    def apply(self, to_add: list[tuple[str, str]], to_remove_ids: list[str]) -> dict[str, Any]:
        applied_add = 0
        applied_remove = 0
        errors = 0
        push_log: list[dict[str, Any]] = []

        if not self.is_configured():
            return {"applied_add": 0, "applied_remove": 0, "errors": 0, "push_log": []}

        self._mt.connect()
        try:
            # Resource handles cached per family to avoid re-resolving on every
            # op. _ipv6_res may stay None if the router has no IPv6 config —
            # we lazily try once and surface the result per-op.
            res_v4 = self._mt._api.get_resource("/ip/firewall/address-list")  # noqa: SLF001
            try:
                res_v6 = self._mt._api.get_resource("/ipv6/firewall/address-list")  # noqa: SLF001
            except Exception:  # noqa: BLE001
                res_v6 = None

            for addr, comment in to_add:
                want_v6 = _is_ipv6(addr)
                res = res_v6 if want_v6 else res_v4
                if res is None:
                    errors += 1
                    push_log.append({"ip": addr, "action": "add", "success": False,
                                     "error": "ipv6 address-list resource unavailable"})
                    continue
                try:
                    res.add(list=self.list_name, address=addr, comment=comment)
                    applied_add += 1
                    push_log.append({"ip": addr, "action": "add", "success": True})
                except Exception as e:  # noqa: BLE001
                    msg = str(e).lower()
                    if "already have such entry" in msg or "duplicate" in msg or "already exists" in msg:
                        applied_add += 1
                        push_log.append({"ip": addr, "action": "add", "success": True,
                                         "error": "idempotent"})
                    else:
                        errors += 1
                        push_log.append({"ip": addr, "action": "add", "success": False,
                                         "error": str(e)[:300]})
            for mt_id in to_remove_ids:
                path, real_id = _split_id(mt_id)
                res = res_v6 if path == "/ipv6/firewall/address-list" else res_v4
                if res is None:
                    errors += 1
                    push_log.append({"ip": mt_id, "action": "remove", "success": False,
                                     "error": "ipv6 address-list resource unavailable"})
                    continue
                try:
                    res.remove(id=real_id)
                    applied_remove += 1
                    push_log.append({"ip": mt_id, "action": "remove", "success": True})
                except Exception as e:  # noqa: BLE001
                    msg = str(e).lower()
                    if "no such item" in msg or "not found" in msg:
                        applied_remove += 1
                        push_log.append({"ip": mt_id, "action": "remove", "success": True,
                                         "error": "idempotent"})
                    else:
                        errors += 1
                        push_log.append({"ip": mt_id, "action": "remove", "success": False,
                                         "error": str(e)[:300]})
        finally:
            self._mt.disconnect()

        return {"applied_add": applied_add, "applied_remove": applied_remove,
                "errors": errors, "push_log": push_log}
