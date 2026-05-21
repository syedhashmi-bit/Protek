"""
pfSense bouncer — uses the community pfsense-pkg-RESTAPI v2.

The operator must have installed `pfSense-pkg-RESTAPI` and created an
alias of type `network` named in the adapter config (default: protek_bans).
A floating WAN block rule with src = that alias is the operator's job.

v2 dropped per-entry add/delete, so we PATCH the whole `addresses` array
on every cycle — matches phase-3 "compute full diff, push minimal delta"
semantics but the API only accepts whole-array replacement.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from . import register

log = logging.getLogger("protek.bouncer.pfsense")


@register("pfsense")
class PfSenseBouncer:
    def __init__(self, name: str = "pfsense", base_url: str = "",
                 api_key: str = "", alias_name: str = "protek_bans",
                 verify_tls: bool = False, **_: Any):
        self.name = name
        self.kind = "pfsense"
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.alias_name = alias_name
        self.verify_tls = verify_tls

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _hdrs(self) -> dict[str, str]:
        return {"X-API-Key": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}

    def health(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "bouncer": self.name, "kind": self.kind,
                    "error": "base_url + api_key required"}
        try:
            r = requests.get(
                f"{self.base_url}/api/v2/firewall/alias",
                params={"name": self.alias_name},
                headers=self._hdrs(), timeout=10, verify=self.verify_tls,
            )
            if r.status_code >= 400:
                return {"ok": False, "bouncer": self.name, "kind": self.kind,
                        "error": f"pfSense {r.status_code}: {r.text[:200]}"}
            data = r.json() or {}
            addresses = (data.get("data") or {}).get("addresses") or []
            return {"ok": True, "bouncer": self.name, "kind": self.kind,
                    "alias": self.alias_name, "size": len(addresses)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "bouncer": self.name, "kind": self.kind, "error": str(e)}

    def snapshot(self) -> list[dict[str, Any]]:
        if not self.is_configured():
            return []
        try:
            r = requests.get(
                f"{self.base_url}/api/v2/firewall/alias",
                params={"name": self.alias_name},
                headers=self._hdrs(), timeout=10, verify=self.verify_tls,
            )
            if r.status_code >= 400:
                return []
            data = (r.json() or {}).get("data") or {}
            addrs = data.get("addresses") or []
        except Exception:  # noqa: BLE001
            return []
        # pfSense aliases have no comment field on entries, so ownership is
        # implicit — the whole alias is Protek-managed by convention.
        return [{"address": a, "comment": "protek:pfsense::0", ".id": a,
                 "list": self.alias_name} for a in addrs]

    def apply(self, to_add: list[tuple[str, str]], to_remove_ids: list[str]) -> dict[str, Any]:
        if not self.is_configured():
            return {"applied_add": 0, "applied_remove": 0, "errors": 1, "push_log": [],
                    "error": "not configured"}
        # PATCH replaces the whole alias address-list.
        current = {e["address"] for e in self.snapshot()}
        added = {a for a, _c in to_add}
        removed = set(to_remove_ids)
        new_set = (current | added) - removed
        try:
            r = requests.patch(
                f"{self.base_url}/api/v2/firewall/alias",
                json={"name": self.alias_name, "type": "network",
                      "addresses": sorted(new_set)},
                headers=self._hdrs(), timeout=20, verify=self.verify_tls,
            )
            if r.status_code >= 400:
                return {"applied_add": 0, "applied_remove": 0, "errors": 1, "push_log": [
                    {"ip": "(bulk)", "action": "patch", "success": False,
                     "error": f"pfSense {r.status_code}: {r.text[:200]}"}
                ]}
            # Apply pending changes.
            requests.post(f"{self.base_url}/api/v2/firewall/apply",
                          headers=self._hdrs(), timeout=20, verify=self.verify_tls)
            return {"applied_add": len(added), "applied_remove": len(removed),
                    "errors": 0, "push_log": [{"ip": "(bulk)", "action": "patch", "success": True}]}
        except Exception as e:  # noqa: BLE001
            return {"applied_add": 0, "applied_remove": 0, "errors": 1, "push_log": [
                {"ip": "(bulk)", "action": "patch", "success": False, "error": str(e)[:300]}
            ]}
