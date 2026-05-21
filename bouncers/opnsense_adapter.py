"""
OPNsense bouncer — uses the built-in REST API (no plugin required).

Auth: HTTP Basic with key:secret. Generate at System → Access → Users → API keys.
The alias must already exist; this adapter manages its contents only.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
from requests.auth import HTTPBasicAuth

from . import register

log = logging.getLogger("protek.bouncer.opnsense")


@register("opnsense")
class OPNsenseBouncer:
    def __init__(self, name: str = "opnsense", base_url: str = "",
                 api_key: str = "", api_secret: str = "",
                 alias_name: str = "protek_bans",
                 verify_tls: bool = False, **_: Any):
        self.name = name
        self.kind = "opnsense"
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.alias_name = alias_name
        self.verify_tls = verify_tls

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.api_secret)

    def _auth(self) -> HTTPBasicAuth:
        return HTTPBasicAuth(self.api_key, self.api_secret)

    def health(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "bouncer": self.name, "kind": self.kind,
                    "error": "base_url + api_key + api_secret required"}
        try:
            r = requests.get(
                f"{self.base_url}/api/firewall/alias_util/list/{self.alias_name}",
                auth=self._auth(), timeout=10, verify=self.verify_tls,
            )
            if r.status_code >= 400:
                return {"ok": False, "bouncer": self.name, "kind": self.kind,
                        "error": f"OPNsense {r.status_code}: {r.text[:200]}"}
            rows = (r.json() or {}).get("rows") or []
            return {"ok": True, "bouncer": self.name, "kind": self.kind,
                    "alias": self.alias_name, "size": len(rows)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "bouncer": self.name, "kind": self.kind, "error": str(e)}

    def snapshot(self) -> list[dict[str, Any]]:
        if not self.is_configured():
            return []
        try:
            r = requests.get(
                f"{self.base_url}/api/firewall/alias_util/list/{self.alias_name}",
                auth=self._auth(), timeout=15, verify=self.verify_tls,
            )
            if r.status_code >= 400:
                return []
            rows = (r.json() or {}).get("rows") or []
        except Exception:  # noqa: BLE001
            return []
        return [{"address": row.get("ip", ""),
                 "comment": "protek:opnsense::0",
                 ".id": row.get("ip", ""),
                 "list": self.alias_name} for row in rows if row.get("ip")]

    def apply(self, to_add: list[tuple[str, str]], to_remove_ids: list[str]) -> dict[str, Any]:
        if not self.is_configured():
            return {"applied_add": 0, "applied_remove": 0, "errors": 1, "push_log": [],
                    "error": "not configured"}
        applied_add = 0
        applied_remove = 0
        errors = 0
        push_log: list[dict[str, Any]] = []
        for addr, _cmt in to_add:
            try:
                r = requests.post(
                    f"{self.base_url}/api/firewall/alias_util/add/{self.alias_name}",
                    json={"address": addr}, auth=self._auth(),
                    timeout=10, verify=self.verify_tls,
                )
                if r.status_code in (200, 201):
                    applied_add += 1
                    push_log.append({"ip": addr, "action": "add", "success": True})
                else:
                    errors += 1
                    push_log.append({"ip": addr, "action": "add", "success": False,
                                     "error": f"OPNsense {r.status_code}: {r.text[:200]}"})
            except Exception as e:  # noqa: BLE001
                errors += 1
                push_log.append({"ip": addr, "action": "add", "success": False, "error": str(e)[:300]})
        for rid in to_remove_ids:
            try:
                r = requests.post(
                    f"{self.base_url}/api/firewall/alias_util/delete/{self.alias_name}",
                    json={"address": rid}, auth=self._auth(),
                    timeout=10, verify=self.verify_tls,
                )
                if r.status_code in (200, 201):
                    applied_remove += 1
                    push_log.append({"ip": rid, "action": "remove", "success": True})
                else:
                    errors += 1
                    push_log.append({"ip": rid, "action": "remove", "success": False,
                                     "error": f"OPNsense {r.status_code}: {r.text[:200]}"})
            except Exception as e:  # noqa: BLE001
                errors += 1
                push_log.append({"ip": rid, "action": "remove", "success": False, "error": str(e)[:300]})
        return {"applied_add": applied_add, "applied_remove": applied_remove,
                "errors": errors, "push_log": push_log}
