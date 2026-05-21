"""
ratelimit.py — Arc 11 phase 68. Token-bucket backpressure for upstream calls.

Buckets per upstream:
  - `lapi`                 — LAPI HTTP calls (decisions, alerts, stream)
  - `bouncer.<kind>`       — one per bouncer kind (cloudflare, pfsense, ...)
  - `webhook.<host>`       — one per outbound webhook host
  - `intel.<provider>`     — one per intel provider (abuseipdb, otx, ...)

Caller pattern:

    if not ratelimit.acquire("bouncer.cloudflare"):
        # bucket empty — defer this push to next cycle
        return {"skipped": True, "reason": "backpressure"}
    do_the_upstream_call()

`acquire()` returns True if a token was consumed, False otherwise. It NEVER
sleeps — the caller is responsible for the right "what to do when denied"
action (retry-next-cycle for reconcile, drop-with-log for webhook fan-out).

When an upstream returns 429, call `ratelimit.record_429(name)`. That halves
the bucket's refill rate for 5 minutes (adaptive backoff). The bucket
auto-restores once the penalty window passes.

Defaults are conservative; tune per-bucket via the `settings` table:
    ratelimit.<bucket>.tokens_per_min  — refill rate
    ratelimit.<bucket>.capacity        — max bucket size (burst)

All counters are in-memory only — restart resets them. The settings tunings
persist; the runtime state does not.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from typing import Any

from db import get_setting

log = logging.getLogger("protek.ratelimit")

# (tokens_per_min, capacity) for buckets we know about. Unknown bucket names
# get the DEFAULT entry, so adding a new upstream is automatic — only override
# in DEFAULTS if the conservative default is wrong for that upstream.
DEFAULTS: dict[str, tuple[int, int]] = {
    "DEFAULT":              (600,  120),  # 10 req/s, 120 burst
    "lapi":                 (600,  60),
    "bouncer.mikrotik_env": (1200, 200),
    "bouncer.mikrotik":     (1200, 200),
    "bouncer.iptables_ipset": (6000, 500),  # local fd ops, very cheap
    "bouncer.cloudflare":   (200,  50),    # CF Rules List has per-zone limits
    "bouncer.pfsense":      (300,  60),
    "bouncer.opnsense":     (300,  60),
    "webhook":              (60,   20),    # per-host default
    "intel.abuseipdb":      (40,   10),    # free tier: 1000/day ≈ 41/h
    "intel.proxycheck":     (40,   10),
    "intel.otx":            (300,  60),
    "intel.cti":            (2,    2),     # free tier ~40/day
}

PENALTY_WINDOW_S = 300  # 429-induced halving lasts 5 min
PENALTY_DIVISOR = 2


class TokenBucket:
    __slots__ = ("name", "_capacity", "_tokens", "_refill_per_s",
                 "_last", "_lock", "_penalty_until", "_consumed_log",
                 "_denied_log")

    def __init__(self, name: str, tokens_per_min: int, capacity: int):
        self.name = name
        self._capacity = max(1, capacity)
        self._tokens = float(self._capacity)
        self._refill_per_s = max(0.001, tokens_per_min / 60.0)
        self._last = time.monotonic()
        self._lock = threading.Lock()
        self._penalty_until: float = 0.0
        # Last 60s of (timestamp, outcome) — bounded for /perf surface
        self._consumed_log: deque[float] = deque(maxlen=2000)
        self._denied_log: deque[float] = deque(maxlen=200)

    def _refill_rate_now(self) -> float:
        if time.monotonic() < self._penalty_until:
            return self._refill_per_s / PENALTY_DIVISOR
        return self._refill_per_s

    def acquire(self, tokens: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self._last)
            self._tokens = min(
                float(self._capacity),
                self._tokens + elapsed * self._refill_rate_now(),
            )
            self._last = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                self._consumed_log.append(now)
                return True
            self._denied_log.append(now)
            return False

    def record_429(self) -> None:
        with self._lock:
            self._penalty_until = time.monotonic() + PENALTY_WINDOW_S
            self._tokens = 0.0  # drain immediately

    def status(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            elapsed = max(0.0, now - self._last)
            current = min(float(self._capacity),
                          self._tokens + elapsed * self._refill_rate_now())
            consumed_last_min = sum(1 for t in self._consumed_log
                                    if now - t <= 60.0)
            denied_last_min = sum(1 for t in self._denied_log
                                  if now - t <= 60.0)
            penalty_s = max(0.0, self._penalty_until - now)
        return {
            "name": self.name,
            "capacity": self._capacity,
            "tokens": round(current, 1),
            "tokens_pct": round(100 * current / self._capacity, 1),
            "tokens_per_min": int(self._refill_per_s * 60),
            "consumed_last_min": consumed_last_min,
            "denied_last_min": denied_last_min,
            "penalty_remaining_s": int(penalty_s),
            "penalty_active": penalty_s > 0,
        }


_REGISTRY: dict[str, TokenBucket] = {}
_REGISTRY_LOCK = threading.Lock()


def _settings_for(name: str) -> tuple[int, int]:
    """Per-bucket settings, falling back to family default then DEFAULT."""
    rate = get_setting(f"ratelimit.{name}.tokens_per_min")
    cap = get_setting(f"ratelimit.{name}.capacity")
    # Family fallback: `bouncer.cloudflare` → `bouncer` (no good default
    # we want there, so we use DEFAULT only). Skip the family layer for
    # simplicity; DEFAULTS map carries explicit entries for each known kind.
    base = DEFAULTS.get(name) or DEFAULTS["DEFAULT"]
    try:
        r = int(rate) if rate else base[0]
        c = int(cap) if cap else base[1]
    except ValueError:
        r, c = base
    return r, c


def get_bucket(name: str) -> TokenBucket:
    with _REGISTRY_LOCK:
        b = _REGISTRY.get(name)
        if b is None:
            r, c = _settings_for(name)
            b = TokenBucket(name, r, c)
            _REGISTRY[name] = b
        return b


def acquire(name: str, tokens: int = 1) -> bool:
    return get_bucket(name).acquire(tokens)


def record_429(name: str) -> None:
    get_bucket(name).record_429()


def all_status() -> list[dict[str, Any]]:
    with _REGISTRY_LOCK:
        names = list(_REGISTRY.keys())
    return sorted(
        (get_bucket(n).status() for n in names),
        key=lambda s: s["name"],
    )


def webhook_bucket_for(url: str) -> TokenBucket:
    """Per-host bucket — `webhook.example.com`. Uses the family `webhook`
    default rates when the specific host has no override."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or "unknown"
    except Exception:  # noqa: BLE001
        host = "unknown"
    name = f"webhook.{host}"
    # Materialize using the webhook default rate if not pre-registered
    with _REGISTRY_LOCK:
        if name not in _REGISTRY:
            r, c = DEFAULTS["webhook"]
            override_r = get_setting(f"ratelimit.{name}.tokens_per_min")
            override_c = get_setting(f"ratelimit.{name}.capacity")
            try:
                if override_r:
                    r = int(override_r)
                if override_c:
                    c = int(override_c)
            except ValueError:
                pass
            _REGISTRY[name] = TokenBucket(name, r, c)
    return get_bucket(name)


def reset_for_test() -> None:
    """Drop all registered buckets — used by unit tests, never in prod."""
    with _REGISTRY_LOCK:
        _REGISTRY.clear()
