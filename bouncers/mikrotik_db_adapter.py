"""
Multi-instance MikroTik adapter — kind="mikrotik".

Sibling of mikrotik_adapter.py's MikroTikLegacyAdapter (kind="mikrotik_env",
which is hardcoded to the .env-anchored primary router). Use this one when
you want to push the same decisions to additional routers — e.g. an office
router, a backup site, or a friend's MikroTik you're protecting.

Config_json shape (set via /bouncers add form):
    {
      "host": "10.0.0.1",
      "username": "protek-api",
      "password": "...",
      "port": 8728,
      "use_ssl": false,
      "address_list": "crowdsec",          # router-side list name
      "max_entries": 30000,                # optional; per-bouncer filter
      "exclude_origins": ["lists:firehol_cruzit_web_attacks"]
    }

The operator still owns the firewall rules on each router. Protek only
writes the address-list with `protek:` comment ownership — same safety
contract as the env-anchored adapter.
"""

from __future__ import annotations

from typing import Any

from mikrotik import MikroTik

from . import register


@register("mikrotik")
class MikroTikDBAdapter:
    """DB-configured MikroTik. Each row in bouncer_targets is one router."""

    def __init__(self, name: str = "mikrotik",
                 host: str = "", username: str = "", password: str = "",
                 port: int = 8728, use_ssl: bool = False,
                 address_list: str = "crowdsec",
                 origins: list[str] | None = None,
                 exclude_origins: list[str] | None = None,
                 max_entries: int | None = None,
                 **_: Any):
        self.name = name
        self.kind = "mikrotik"
        self._mt = MikroTik(host=host, username=username, password=password,
                            port=int(port), use_ssl=bool(use_ssl))
        self.list_name = address_list or "crowdsec"
        # Per-bouncer filter knobs — same shape as cloudflare_adapter.
        self.origins = list(origins or [])
        self.exclude_origins = list(exclude_origins or [])
        self.max_entries = int(max_entries) if max_entries else None

    def is_configured(self) -> bool:
        return self._mt.is_configured()

    def health(self) -> dict[str, Any]:
        h = self._mt.health()
        return {**h, "bouncer": self.name, "kind": self.kind, "list": self.list_name}

    def snapshot(self) -> list[dict[str, Any]]:
        if not self.is_configured():
            return []
        try:
            return self._mt.get_address_list(self.list_name)
        except Exception:  # noqa: BLE001
            return []

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
