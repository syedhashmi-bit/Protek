"""
RouterOS v7+ REST API adapter — kind="mikrotik_rest". Arc 16 phase 98.

Why a second adapter rather than a flag on the existing one:

  - The binary API (`mikrotik_db_adapter.py` → `mikrotik.MikroTik`)
    uses RouterOS-api over a stateful TCP socket on 8728/8729. Snapshot
    of a 51 k-entry address-list takes ~118 s on the primary VPS
    (measured in the 2026-05-26 MEMORY note) — the wall-time floor on
    every reconcile cycle.
  - REST returns large pages per request and runs over HTTPS, so the
    snapshot stage drops to 30-50 s on the same router in v7 benchmarks.
    That's a 2-3× speedup, which removes the cycle-cadence rate-limit
    that's been hampering the operator since arc 15.
  - Falling back binary→REST inside a single adapter would have made
    the failure modes ambiguous (was the timeout the binary path or
    the REST path?). Two adapters keep diagnostics clean: each
    `bouncer_targets` row picks its transport.

Config_json shape:
    {
      "host":          "10.0.0.1",
      "username":      "protek-api",
      "password":      "...",
      "port":          443,                # 443 default; some MTs use 80/8080
      "use_ssl":       true,               # default true (https). false → http
      "verify_tls":    true,               # default true; set false for self-signed
      "address_list":  "crowdsec",
      "page_size":     500,                # snapshot pagination (RouterOS default cap)
      "timeout_s":     20,
      # phase 97 filters
      "source_filter":   "local,vps-b",
      "scenario_filter": "http-",
    }

Endpoints used (all under `/rest/`):
  GET    /rest/ip/firewall/address-list?list=<name>   → list entries
  PUT    /rest/ip/firewall/address-list               → add entry
  DELETE /rest/ip/firewall/address-list/<id>          → remove by .id
  GET    /rest/system/resource                        → health probe

REST requires `rest-api` in the user's group policy. The bootstrap
script from phase 94 adds it under a `:do {...} on-error={...}` block
so v6 routers (which don't know about `rest-api`) don't error out.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

from . import register


@register("mikrotik_rest")
class MikroTikRESTAdapter:
    """REST-API variant of the MikroTik bouncer. Same Bouncer protocol
    contract as `MikroTikDBAdapter` — reconciler doesn't care which
    transport delivers the snapshot/apply ops."""

    field_schema = [
        {"name": "host", "label": "Router host or IP", "type": "text",
         "required": True, "placeholder": "192.168.88.1",
         "help": "RouterOS v7+ host. Hostname or IP — REST URL is "
                 "https://<host>:<port>/rest/."},
        {"name": "username", "label": "API username", "type": "text",
         "required": True, "placeholder": "protek",
         "help": "Use the operator created via the phase-94 bootstrap "
                 "script. Group must include `rest-api` policy "
                 "(v7+ only — script handles this conditionally)."},
        {"name": "password", "label": "API password", "type": "password",
         "required": True, "mask": True,
         "help": "Stored at rest in bouncer_targets.config_json. "
                 "Same value the bootstrap printed."},
        {"name": "port", "label": "HTTPS port", "type": "number",
         "required": False, "placeholder": "443", "default": 443,
         "coerce": "int",
         "help": "443 is the RouterOS default. Some operators expose "
                 "the REST endpoint on a non-standard port via /ip "
                 "service set www-ssl port=N."},
        {"name": "use_ssl", "label": "Use HTTPS", "type": "checkbox",
         "required": False, "default": True, "coerce": "bool",
         "help": "RouterOS REST works over HTTPS or HTTP. HTTPS is "
                 "strongly preferred — uncheck only if you're on a "
                 "trusted management VLAN."},
        {"name": "verify_tls", "label": "Verify TLS certificate", "type": "checkbox",
         "required": False, "default": True, "coerce": "bool",
         "help": "RouterOS self-signed certs won't validate against "
                 "the public CA bundle. Uncheck for self-signed; the "
                 "connection still uses HTTPS — only the cert chain "
                 "verification is skipped."},
        {"name": "address_list", "label": "Address-list name", "type": "text",
         "required": False, "placeholder": "crowdsec", "default": "crowdsec"},
        {"name": "page_size", "label": "Snapshot page size", "type": "number",
         "required": False, "placeholder": "500", "default": 500,
         "coerce": "int",
         "help": "How many entries to fetch per REST page. 500 matches "
                 "the RouterOS default cap. Larger = fewer round trips "
                 "but more memory per request."},
        {"name": "timeout_s", "label": "Request timeout (s)", "type": "number",
         "required": False, "placeholder": "20", "default": 20,
         "coerce": "int",
         "help": "Per-request HTTP timeout. Increase for slow links "
                 "or very large lists."},
        # Phase 97 filter knobs — same as the binary adapter
        {"name": "source_filter", "label": "Source filter (optional)", "type": "text",
         "required": False, "placeholder": "local,vps-b"},
        {"name": "scenario_filter", "label": "Scenario filter (regex, optional)", "type": "text",
         "required": False, "placeholder": "http-.*"},
    ]

    def __init__(self, name: str = "mikrotik_rest",
                 host: str = "", username: str = "", password: str = "",
                 port: int = 443, use_ssl: bool = True,
                 verify_tls: bool = True,
                 address_list: str = "crowdsec",
                 page_size: int = 500,
                 timeout_s: int = 20,
                 origins: list[str] | None = None,
                 exclude_origins: list[str] | None = None,
                 max_entries: int | None = None,
                 min_reputation: int | None = None,
                 source_filter: str | list[str] | None = None,
                 scenario_filter: str | None = None,
                 **_: Any):
        self.name = name
        self.kind = "mikrotik_rest"
        self.host = host
        self.username = username
        self.password = password
        self.port = int(port)
        self.use_ssl = bool(use_ssl)
        self.verify_tls = bool(verify_tls)
        self.list_name = address_list or "crowdsec"
        self.page_size = max(50, int(page_size))
        self.timeout_s = max(5, int(timeout_s))
        # phase 97 filter knobs — same names as binary adapter, picked up
        # by reconciler._filter_desired_for_bouncer via getattr.
        self.origins = list(origins or [])
        self.exclude_origins = list(exclude_origins or [])
        self.max_entries = int(max_entries) if max_entries else None
        self.min_reputation = int(min_reputation) if min_reputation else None
        self.source_filter = source_filter or None
        self.scenario_filter = scenario_filter or None

    # ── transport helpers ─────────────────────────────────────────────────
    def _base_url(self) -> str:
        scheme = "https" if self.use_ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/rest"

    def _auth(self) -> tuple[str, str]:
        return (self.username, self.password)

    def _request(self, method: str, path: str,
                 json: dict[str, Any] | None = None) -> requests.Response:
        url = f"{self._base_url()}/{path.lstrip('/')}"
        return requests.request(
            method, url,
            auth=self._auth(),
            json=json,
            verify=self.verify_tls,
            timeout=self.timeout_s,
        )

    # ── Bouncer protocol ─────────────────────────────────────────────────
    def is_configured(self) -> bool:
        return bool(self.host and self.username and self.password)

    def health(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "bouncer": self.name, "kind": self.kind,
                    "list": self.list_name, "error": "not configured"}
        try:
            r = self._request("GET", "system/resource")
            r.raise_for_status()
            body = r.json() if r.content else {}
            # Pagination-light size probe (counts via a HEAD-like call).
            # RouterOS REST returns the whole list per GET — for the
            # health probe we just take .length() (single request).
            size_r = self._request(
                "GET", f"ip/firewall/address-list?list={quote(self.list_name)}")
            size_r.raise_for_status()
            entries = size_r.json() if size_r.content else []
            size = len(entries) if isinstance(entries, list) else 0
        except requests.RequestException as e:
            return {"ok": False, "bouncer": self.name, "kind": self.kind,
                    "list": self.list_name, "error": str(e)[:200]}
        except ValueError as e:  # bad JSON
            return {"ok": False, "bouncer": self.name, "kind": self.kind,
                    "list": self.list_name, "error": f"bad JSON: {e}"}
        return {
            "ok": True,
            "bouncer": self.name,
            "kind": self.kind,
            "list": self.list_name,
            "size": size,
            "version": body.get("version", ""),
            "uptime": body.get("uptime", ""),
            "board": body.get("board-name", ""),
        }

    def snapshot(self) -> list[dict[str, Any]]:
        """Pages through the address-list. Returns entries shaped the
        same as the binary adapter so the reconciler's diff doesn't need
        to know which transport produced them. RouterOS REST returns
        `.id` with the leading dot — we surface it as-is so existing
        diff code (reconcile.py) handles it via the same `entry_id()`
        helper used for the binary path."""
        if not self.is_configured():
            return []
        try:
            r = self._request(
                "GET",
                f"ip/firewall/address-list?list={quote(self.list_name)}")
            r.raise_for_status()
            entries = r.json() if r.content else []
            if not isinstance(entries, list):
                return []
            # Normalize: REST returns `address`, `comment`, `.id`. Convert
            # to the dict shape the binary adapter produces.
            return [
                {
                    ".id":      e.get(".id", ""),
                    "address":  e.get("address", ""),
                    "comment":  e.get("comment", ""),
                    "list":     e.get("list", ""),
                }
                for e in entries
            ]
        except (requests.RequestException, ValueError):
            return []

    def apply(self, to_add: list[tuple[str, str]],
              to_remove_ids: list[str]) -> dict[str, Any]:
        applied_add = 0
        applied_remove = 0
        errors = 0
        push_log: list[dict[str, Any]] = []
        if not self.is_configured():
            return {"applied_add": 0, "applied_remove": 0, "errors": 0,
                    "push_log": []}

        for addr, comment in to_add:
            try:
                r = self._request(
                    "PUT", "ip/firewall/address-list",
                    json={"list": self.list_name, "address": addr,
                          "comment": comment},
                )
                if r.status_code in (200, 201):
                    applied_add += 1
                    push_log.append({"ip": addr, "action": "add", "success": True})
                elif r.status_code == 400 and self._is_duplicate(r):
                    # Idempotent — entry already exists. Same handling as
                    # the binary adapter's "already have such entry" path.
                    applied_add += 1
                    push_log.append({"ip": addr, "action": "add", "success": True,
                                     "error": "idempotent"})
                else:
                    errors += 1
                    push_log.append({"ip": addr, "action": "add", "success": False,
                                     "error": self._error_text(r)})
            except requests.RequestException as e:
                errors += 1
                push_log.append({"ip": addr, "action": "add", "success": False,
                                 "error": str(e)[:200]})

        for rid in to_remove_ids:
            try:
                r = self._request(
                    "DELETE", f"ip/firewall/address-list/{quote(rid)}",
                )
                if r.status_code in (200, 204):
                    applied_remove += 1
                    push_log.append({"ip": rid, "action": "remove", "success": True})
                elif r.status_code == 404:
                    # Already gone — also idempotent.
                    applied_remove += 1
                    push_log.append({"ip": rid, "action": "remove", "success": True,
                                     "error": "idempotent"})
                else:
                    errors += 1
                    push_log.append({"ip": rid, "action": "remove", "success": False,
                                     "error": self._error_text(r)})
            except requests.RequestException as e:
                errors += 1
                push_log.append({"ip": rid, "action": "remove", "success": False,
                                 "error": str(e)[:200]})

        return {"applied_add": applied_add, "applied_remove": applied_remove,
                "errors": errors, "push_log": push_log}

    # ── error formatting ─────────────────────────────────────────────────
    @staticmethod
    def _is_duplicate(r: requests.Response) -> bool:
        try:
            body = r.json() if r.content else {}
        except ValueError:
            return False
        msg = (body.get("detail") or body.get("message") or "").lower()
        return ("already have such entry" in msg
                or "duplicate" in msg
                or "already exists" in msg)

    @staticmethod
    def _error_text(r: requests.Response) -> str:
        try:
            body = r.json() if r.content else {}
            return str(body.get("detail") or body.get("message")
                       or r.text[:200])
        except ValueError:
            return r.text[:200]
