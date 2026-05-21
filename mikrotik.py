"""
mikrotik.py — RouterOS API adapter, phase-2 read-only shape.

Phase 2 only exposes:
    connect / disconnect
    get_address_list(list_name) → list of entries (filtered server-side by list)
    health() → {"ok": bool, "version": str | None, "error": str | None}

Phase 4 adds add_entry / remove_entry / bulk_apply for live writes. The split
keeps phase 2 deliberately incapable of touching the router state.

Field names from RouterOS use hyphens ("creation-time"). The `.id` handle
sometimes arrives as `id` depending on library version — always read it
through entry_id(). Lifted from /var/www/pipsqueeze/mikrotik_api.py.
"""

from __future__ import annotations

import os
from typing import Any

import routeros_api


def _envstr(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default) or ""
    return raw.split("#", 1)[0].strip()


def _envint(name: str, default: int) -> int:
    v = _envstr(name, "")
    try:
        return int(v) if v else default
    except ValueError:
        return default


def entry_id(entry: dict[str, Any]) -> str | None:
    """Return the RouterOS internal handle regardless of dot-prefix variant."""
    return entry.get("id") or entry.get(".id") or entry.get("numbers")


class MikroTikError(Exception):
    """Anything that goes wrong talking to the router."""


class MikroTik:
    """Lazy-connected wrapper. Each operation may raise MikroTikError."""

    def __init__(
        self,
        host: str | None = None,
        username: str | None = None,
        password: str | None = None,
        port: int | None = None,
        use_ssl: bool | None = None,
    ):
        self.host = host or _envstr("MT_HOST", "")
        self.username = username or _envstr("MT_USERNAME", "")
        # MT_PASSWORD never gets a stripped comment because passwords may legitimately contain "#"
        self.password = password if password is not None else os.environ.get("MT_PASSWORD", "")
        self.port = int(port if port is not None else _envint("MT_PORT", 8728))
        if use_ssl is None:
            use_ssl = _envstr("MT_USE_SSL", "false").lower() in ("1", "true", "yes")
        self.use_ssl = use_ssl
        self._pool: routeros_api.RouterOsApiPool | None = None
        self._api = None

    # ── connection ──────────────────────────────────────────────────────────
    def is_configured(self) -> bool:
        return bool(self.host and self.username and self.password)

    def connect(self) -> None:
        if not self.is_configured():
            raise MikroTikError("MikroTik not configured — set MT_HOST/MT_USERNAME/MT_PASSWORD in .env")
        try:
            self._pool = routeros_api.RouterOsApiPool(
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                plaintext_login=True,
                use_ssl=self.use_ssl,
                ssl_verify=False,
                ssl_verify_hostname=False,
            )
            self._api = self._pool.get_api()
        except Exception as e:  # noqa: BLE001
            raise MikroTikError(f"connect failed: {e}") from e

    def disconnect(self) -> None:
        try:
            if self._pool:
                self._pool.disconnect()
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._pool = None
            self._api = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.disconnect()

    # ── reads ───────────────────────────────────────────────────────────────
    def health(self) -> dict[str, Any]:
        if not self.is_configured():
            return {"ok": False, "configured": False, "error": "MT_HOST / MT_USERNAME / MT_PASSWORD not set"}
        try:
            self.connect()
            try:
                identity = self._api.get_resource("/system/identity").get()
                resource = self._api.get_resource("/system/resource").get()
                version = resource[0].get("version") if resource else None
                name = identity[0].get("name") if identity else None
                return {
                    "ok": True,
                    "configured": True,
                    "host": self.host,
                    "port": self.port,
                    "use_ssl": self.use_ssl,
                    "version": version,
                    "name": name,
                }
            finally:
                self.disconnect()
        except MikroTikError as e:
            return {"ok": False, "configured": True, "host": self.host, "port": self.port, "error": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "configured": True, "host": self.host, "port": self.port, "error": str(e)}

    def get_address_list(self, list_name: str) -> list[dict[str, Any]]:
        """Return all entries with `list == list_name`. Connect/disconnect inline."""
        if not self.is_configured():
            raise MikroTikError("MikroTik not configured")
        self.connect()
        try:
            res = self._api.get_resource("/ip/firewall/address-list")
            try:
                entries = res.get(list=list_name)
            except TypeError:
                # Older client variants don't accept kwargs to get()
                entries = [e for e in res.get() if e.get("list") == list_name]
            return list(entries or [])
        except Exception as e:  # noqa: BLE001
            raise MikroTikError(f"get_address_list({list_name}) failed: {e}") from e
        finally:
            self.disconnect()


def address_list_name() -> str:
    return _envstr("MT_ADDRESS_LIST", "crowdsec") or "crowdsec"
