"""
Cloudflare WAF Rules List bouncer.

Uses the v4 API. The operator needs:
  - A scoped API token with "Account Filter Lists: Edit" permission.
  - An account ID + an existing IP list (or this adapter creates one on first
    health() if `auto_create_list = true`).
  - A WAF Custom Rule manually attached: expression `(ip.src in $protek_bans)`
    action "block".  The adapter does NOT create that rule — same separation
    as the iptables adapter (we own the list, operator owns the rule).
"""

from __future__ import annotations

import logging
from typing import Any

import requests

from . import register

log = logging.getLogger("protek.bouncer.cloudflare")

API = "https://api.cloudflare.com/client/v4"


@register("cloudflare")
class CloudflareBouncer:
    """Cloudflare Rules List bouncer (account-level)."""

    def __init__(self, name: str = "cloudflare", account_id: str = "",
                 list_id: str = "", api_token: str = "",
                 list_name: str = "protek_bans", auto_create_list: bool = True,
                 **_: Any):
        self.name = name
        self.kind = "cloudflare"
        self.account_id = account_id
        self.list_id = list_id
        self.api_token = api_token
        self.list_name = list_name
        self.auto_create_list = auto_create_list

    def is_configured(self) -> bool:
        return bool(self.account_id and self.api_token)

    def _hdrs(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_token}", "Accept": "application/json",
                "Content-Type": "application/json"}

    def _ensure_list(self) -> tuple[str | None, str]:
        """Returns (list_id, diagnostic). On success, diagnostic is empty.
        On failure, list_id is None and diagnostic explains why (so health()
        can surface the real CF error instead of a generic fallback)."""
        if self.list_id:
            return self.list_id, ""
        if not self.auto_create_list:
            return None, "auto_create_list=false and no list_id provided"
        # Before trying to create, see if a list with the same name exists —
        # operators often create it once in the CF dashboard, then leave
        # auto_create on. Reuse instead of erroring with "already exists".
        try:
            r = requests.get(
                f"{API}/accounts/{self.account_id}/rules/lists",
                headers=self._hdrs(), timeout=10,
            )
            if r.status_code == 200:
                for item in r.json().get("result") or []:
                    if item.get("name") == self.list_name and item.get("kind") == "ip":
                        self.list_id = item.get("id") or ""
                        return self.list_id, ""
            elif r.status_code in (401, 403):
                return None, (f"CF token rejected listing lists (HTTP {r.status_code}). "
                              "Token needs Account → Account Filter Lists: Edit.")
        except Exception as e:  # noqa: BLE001
            return None, f"network error listing CF lists: {e}"
        # No existing list — try to create.
        try:
            r = requests.post(
                f"{API}/accounts/{self.account_id}/rules/lists",
                json={"name": self.list_name, "kind": "ip",
                      "description": "CrowdSec bans (managed by Protek)"},
                headers=self._hdrs(), timeout=10,
            )
            if r.status_code in (200, 201):
                data = r.json().get("result") or {}
                self.list_id = data.get("id") or ""
                return self.list_id, ""
            # Surface the actual error verbatim so the operator can fix it
            # instead of guessing.
            return None, f"CF create-list HTTP {r.status_code}: {r.text[:300]}"
        except Exception as e:  # noqa: BLE001
            return None, f"network error creating CF list: {e}"

    def health(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "bouncer": self.name, "kind": self.kind,
                    "error": "account_id + api_token required"}
        try:
            lid, diag = self._ensure_list()
            if not lid:
                return {"ok": False, "bouncer": self.name, "kind": self.kind,
                        "error": diag or "list_id required"}
            r = requests.get(
                f"{API}/accounts/{self.account_id}/rules/lists/{lid}",
                headers=self._hdrs(), timeout=10,
            )
            if r.status_code >= 400:
                return {"ok": False, "bouncer": self.name, "kind": self.kind,
                        "error": f"CF {r.status_code}: {r.text[:200]}"}
            data = r.json().get("result") or {}
            return {"ok": True, "bouncer": self.name, "kind": self.kind,
                    "list_name": data.get("name"), "list_id": lid,
                    "size": data.get("num_items", 0)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "bouncer": self.name, "kind": self.kind, "error": str(e)}

    # CF's Lists items endpoint caps GET at per_page=500 (the docs only mention
    # the POST bulk-add 1000 cap — easy to mix them up). per_page>500 returns
    # an "invalid cursor" 400 even with no cursor sent, which silently broke
    # snapshot() and made the reconciler think the list was empty every cycle.
    SNAPSHOT_PAGE_SIZE = 500

    def snapshot(self) -> list[dict[str, Any]]:
        lid = self.list_id
        if not lid:
            lid, _diag = self._ensure_list()
        if not lid:
            return []
        out: list[dict[str, Any]] = []
        cursor = ""
        try:
            while True:
                url = (f"{API}/accounts/{self.account_id}/rules/lists/{lid}/items"
                       f"?per_page={self.SNAPSHOT_PAGE_SIZE}")
                if cursor:
                    url += f"&cursor={cursor}"
                r = requests.get(url, headers=self._hdrs(), timeout=15)
                if r.status_code >= 400:
                    log.warning("cf snapshot failed: %s", r.text[:200])
                    break
                payload = r.json() or {}
                items = payload.get("result") or []
                for item in items:
                    out.append({
                        "address": item.get("ip", ""),
                        "comment": (item.get("comment") or "protek:cloudflare::0"),
                        ".id": item.get("id", ""),
                        "list": lid,
                    })
                # CF returns `cursors: null` (not just missing `after`) on the
                # last page — handle both shapes defensively.
                ri = payload.get("result_info") or {}
                cursors = ri.get("cursors") or {}
                cursor = cursors.get("after") or ""
                if not cursor or len(items) < self.SNAPSHOT_PAGE_SIZE:
                    break
        except Exception as e:  # noqa: BLE001
            log.warning("cf snapshot crashed: %s", e)
        return out

    def apply(self, to_add: list[tuple[str, str]], to_remove_ids: list[str]) -> dict[str, Any]:
        lid = self.list_id
        if not lid:
            lid, diag = self._ensure_list()
        else:
            diag = ""
        if not lid:
            return {"applied_add": 0, "applied_remove": 0, "errors": 1, "push_log": [],
                    "error": diag or "no list_id"}
        applied_add = 0
        applied_remove = 0
        errors = 0
        push_log: list[dict[str, Any]] = []
        try:
            # Append items (bulk, async)
            if to_add:
                payload = [{"ip": addr, "comment": cmt[:500]} for addr, cmt in to_add]
                # Cloudflare allows up to 1000 items per request.
                for i in range(0, len(payload), 1000):
                    chunk = payload[i:i + 1000]
                    r = requests.post(
                        f"{API}/accounts/{self.account_id}/rules/lists/{lid}/items",
                        json=chunk, headers=self._hdrs(), timeout=30,
                    )
                    if r.status_code in (200, 201, 202):
                        applied_add += len(chunk)
                        for addr, _c in [(p["ip"], p["comment"]) for p in chunk]:
                            push_log.append({"ip": addr, "action": "add", "success": True})
                    else:
                        errors += 1
                        push_log.append({"ip": "(bulk)", "action": "add", "success": False,
                                         "error": f"CF {r.status_code}: {r.text[:200]}"})
            if to_remove_ids:
                items = [{"id": rid} for rid in to_remove_ids]
                for i in range(0, len(items), 1000):
                    chunk = items[i:i + 1000]
                    r = requests.delete(
                        f"{API}/accounts/{self.account_id}/rules/lists/{lid}/items",
                        json={"items": chunk}, headers=self._hdrs(), timeout=30,
                    )
                    if r.status_code in (200, 202):
                        applied_remove += len(chunk)
                        for rid in [c["id"] for c in chunk]:
                            push_log.append({"ip": rid, "action": "remove", "success": True})
                    else:
                        errors += 1
                        push_log.append({"ip": "(bulk)", "action": "remove", "success": False,
                                         "error": f"CF {r.status_code}: {r.text[:200]}"})
        except Exception as e:  # noqa: BLE001
            errors += 1
            push_log.append({"ip": "", "action": "?", "success": False, "error": str(e)[:300]})
        return {"applied_add": applied_add, "applied_remove": applied_remove,
                "errors": errors, "push_log": push_log}
