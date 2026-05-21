"""
Legacy MikroTik adapter — wraps the env-driven /var/www/Protek/mikrotik.py
in the new Bouncer protocol. Keeps phase-1/2 behavior identical.
"""

from __future__ import annotations

from typing import Any

from mikrotik import MikroTik, address_list_name
from reconcile import is_owned

from . import register


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
            res = self._mt._api.get_resource("/ip/firewall/address-list")  # noqa: SLF001
            for addr, comment in to_add:
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
                try:
                    res.remove(id=mt_id)
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
