"""
crowdsec.py — CrowdSec LAPI client.

Federation-ready: every LAPIClient instance carries its own (url, api_key, name).
No reads from os.environ inside methods. To talk to a remote LAPI in phase 2,
just construct another LAPIClient — the rest of the codebase doesn't care.

Endpoints used:
    GET /v1/decisions?type=ban&scope=Ip      — full snapshot (bootstrap)
    GET /v1/decisions/stream?startup=true    — delta stream (steady-state)
    GET /v1/alerts                           — richer context per scenario fire

See SKILL.md § "The three endpoints we care about" before changing this file.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests

log = logging.getLogger("protek.crowdsec")


class LAPIError(Exception):
    """Anything that goes wrong talking to a CrowdSec LAPI."""


@dataclass
class LAPIClient:
    url: str
    api_key: str
    name: str = "local"
    timeout: float = 10.0

    def _headers(self) -> dict[str, str]:
        return {
            "X-Api-Key": self.api_key,
            "User-Agent": f"protek-bouncer/0.1 ({self.name})",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = f"{self.url.rstrip('/')}{path}"
        # Phase-68 backpressure: skip the call if our LAPI bucket is empty.
        # Caller treats LAPIError as "try next cycle", which matches the
        # poller's existing skip-cycle behavior on transient failures.
        try:
            import ratelimit
            if not ratelimit.acquire("lapi"):
                raise LAPIError(f"{self.name}: backpressure — lapi bucket exhausted")
        except ImportError:
            pass
        try:
            r = requests.get(url, headers=self._headers(), params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise LAPIError(f"{self.name}: GET {path} network error: {e}") from e
        if r.status_code == 429:
            try:
                import ratelimit
                ratelimit.record_429("lapi")
            except ImportError:
                pass
            raise LAPIError(f"{self.name}: 429 rate limited")
        if r.status_code == 401:
            raise LAPIError(f"{self.name}: 401 Unauthorized — bad bouncer key")
        if r.status_code == 403:
            raise LAPIError(f"{self.name}: 403 Forbidden")
        if r.status_code >= 400:
            raise LAPIError(f"{self.name}: GET {path} → HTTP {r.status_code}: {r.text[:200]}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError as e:
            raise LAPIError(f"{self.name}: invalid JSON from {path}: {e}") from e

    # ── Health ──────────────────────────────────────────────────────────────
    def health(self) -> dict[str, Any]:
        """Cheap liveness probe. Calls /v1/decisions with limit=1.

        LAPI has no public unauthed /health for bouncers — the cheapest
        authenticated check is a 1-row decision fetch.
        """
        try:
            data = self._get("/v1/decisions", params={"limit": 1})
            return {"ok": True, "name": self.name, "url": self.url, "sample_size": len(data or [])}
        except LAPIError as e:
            return {"ok": False, "name": self.name, "url": self.url, "error": str(e)}

    # ── Decisions ───────────────────────────────────────────────────────────
    def decisions(self, scope: str = "Ip", decision_type: str = "ban") -> list[dict[str, Any]]:
        """Full active snapshot. Use once at startup; prefer stream() afterwards."""
        data = self._get("/v1/decisions", params={"scope": scope, "type": decision_type})
        return list(data or [])

    def decisions_stream(self, startup: bool = False) -> dict[str, list[dict[str, Any]]]:
        """Delta stream: returns {"new": [...], "deleted": [...]}.

        Pass startup=True on the first call after Protek (re)starts so the
        LAPI re-emits the full active set instead of only deltas since the
        cursor it remembered for this bouncer key.
        """
        params: dict[str, Any] = {"scopes": "Ip,Range"}
        if startup:
            params["startup"] = "true"
        data = self._get("/v1/decisions/stream", params=params) or {}
        return {
            "new": list(data.get("new") or []),
            "deleted": list(data.get("deleted") or []),
        }

    # ── Alerts (bouncer-key path — always returns [] by LAPI design) ────────
    def alerts(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Bouncer keys are read-only on decisions only; alerts require a
        machine credential. Use MachineClient for the real fetch."""
        return []


class MachineClient:
    """Authenticated as a CrowdSec **machine** (not a bouncer). Uses
    `/v1/watchers/login` to obtain a short-lived JWT, then `Authorization:
    Bearer <jwt>` for subsequent calls. The JWT is cached + auto-refreshed
    on 401.

    Only needed for `/v1/alerts` (richer event context). Decisions remain
    on the bouncer path.
    """

    def __init__(self, url: str, machine_id: str, password: str,
                 timeout: float = 10.0) -> None:
        self.url = url.rstrip("/")
        self.machine_id = machine_id
        self.password = password
        self.timeout = timeout
        self._token: str | None = None

    def _login(self) -> None:
        try:
            r = requests.post(
                f"{self.url}/v1/watchers/login",
                json={"machine_id": self.machine_id, "password": self.password},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise LAPIError(f"machine login network error: {e}") from e
        if r.status_code != 200:
            raise LAPIError(f"machine login HTTP {r.status_code}: {r.text[:200]}")
        try:
            body = r.json()
        except ValueError as e:
            raise LAPIError(f"machine login invalid JSON: {e}") from e
        tok = body.get("token")
        if not tok:
            raise LAPIError("machine login: no token in response")
        self._token = tok

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "protek-machine/0.1",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: dict[str, Any] | None = None,
             _retry: bool = True) -> Any:
        if not self._token:
            self._login()
        try:
            r = requests.get(
                f"{self.url}{path}",
                headers=self._headers(), params=params, timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise LAPIError(f"machine GET {path} network error: {e}") from e
        if r.status_code == 401 and _retry:
            # Token expired — refresh and retry once.
            self._token = None
            return self._get(path, params=params, _retry=False)
        if r.status_code >= 400:
            raise LAPIError(f"machine GET {path} → HTTP {r.status_code}: {r.text[:200]}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError as e:
            raise LAPIError(f"machine GET {path} invalid JSON: {e}") from e

    def alerts(self, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Fetch recent alerts. `since` is a Go duration string ("1h", "24h")."""
        params: dict[str, Any] = {"limit": limit}
        if since:
            params["since"] = since
        data = self._get("/v1/alerts", params=params)
        return list(data or [])

    def health(self) -> dict[str, Any]:
        try:
            self.alerts(limit=1)
            return {"ok": True, "url": self.url, "machine_id": self.machine_id}
        except LAPIError as e:
            return {"ok": False, "url": self.url, "error": str(e)}
