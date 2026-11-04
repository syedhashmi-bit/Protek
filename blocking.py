"""
blocking.py — is the router actually dropping what Protek pushes?

Protek owns the *contents* of the address-list; the operator owns the
firewall rules that consume it (SKILL.md §1). Without a rule that drops
traffic from that list, every push lands in a list nothing reads — the
dashboard looks healthy and nothing is blocked. This module answers the
question with a read-only look at the router's firewall:

    analyze(list_name, tables)  — pure: rule dicts in, verdict out
    check_target(bouncer)       — fetch + analyze one MikroTik target
    refresh()                   — check every MikroTik target, cache result
    cached()                    — last cached result, no network I/O

Verdicts, worst first:
    none        no enabled-or-disabled rule drops the list
    disabled    rules exist, all disabled
    shadowed    enabled rules exist, but an earlier unconditional `accept`
                in the same chain means they never see a packet
    unknown     the firewall couldn't be read (connection / permission)
    unverified  enabled rules exist only in a custom chain — Protek can't
                tell whether anything jumps to it
    blocking    an enabled drop/reject rule in filter input/forward or raw
                prerouting, not shadowed

Read-only by construction: the fetchers only ever call `.get()` on the
binary API and GET on the REST API. tests/test_blocking.py holds that line.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("protek.blocking")

# Actions that stop a packet. `tarpit` is TCP-only but still blocks.
_BLOCK_ACTIONS = {"drop", "reject", "tarpit"}

# Chains a packet from the internet always traverses, per table, and which
# traffic each one covers. A rule in raw prerouting sees both.
_BUILTIN = {
    "raw": {"prerouting": {"input", "forward"}},
    "filter": {"input": {"input"}, "forward": {"forward"}},
}
# Built-in chains that never see inbound traffic from a banned source.
_IRRELEVANT = {"output", "postrouting"}

# Keys that describe a rule rather than restrict what it matches. A rule
# with no other keys matches every packet. Unknown keys count as matchers,
# which errs toward "not unconditional" — never a false "shadowed".
_NON_MATCHERS = {
    ".id", "id", ".nextid", ".about", "chain", "action", "disabled", "dynamic",
    "invalid", "comment", "log", "log-prefix", "bytes", "packets",
    "jump-target", "reject-with", "address-list", "address-list-timeout",
    "passthrough", "new-connection-mark", "new-packet-mark", "new-routing-mark",
    "new-dscp", "new-ttl", "new-mss", "new-priority", "to-addresses",
    "to-ports", "route-dst", "hw-offload", "place-before",
}

_SEVERITY = ["none", "disabled", "shadowed", "unknown", "unverified", "blocking"]

SETTING_KEY = "blocking.status"


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("true", "yes", "1")


def _int(v: Any) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return 0


def _is_unconditional_accept(rule: dict[str, Any]) -> bool:
    if (rule.get("action") or "accept") != "accept":
        return False
    if _truthy(rule.get("disabled")) or _truthy(rule.get("invalid")):
        return False
    return not any(k not in _NON_MATCHERS for k in rule)


def _analyze_family(list_name: str, tables: dict[str, list[dict[str, Any]] | None]) -> dict[str, Any]:
    """One address family. `tables` maps "filter"/"raw" to that table's rules
    in router order (None = table couldn't be read)."""
    matches: list[dict[str, Any]] = []
    for table in ("raw", "filter"):
        rules = tables.get(table) or []
        seen_accept_all: set[str] = set()     # chains with an earlier accept-all
        for pos, rule in enumerate(rules):
            chain = rule.get("chain") or ""
            if (rule.get("src-address-list") or "") == list_name \
                    and (rule.get("action") or "") in _BLOCK_ACTIONS:
                if chain in _IRRELEVANT:
                    continue
                enabled = not _truthy(rule.get("disabled")) and not _truthy(rule.get("invalid"))
                matches.append({
                    "table": table,
                    "chain": chain,
                    "position": pos,
                    "action": rule.get("action"),
                    "enabled": enabled,
                    "shadowed": enabled and chain in seen_accept_all,
                    "builtin": chain in _BUILTIN[table],
                    "packets": _int(rule.get("packets")),
                    "comment": rule.get("comment") or "",
                })
            if _is_unconditional_accept(rule):
                seen_accept_all.add(chain)

    live = [m for m in matches if m["enabled"] and not m["shadowed"]]
    live_builtin = [m for m in live if m["builtin"]]
    coverage: set[str] = set()
    for m in live_builtin:
        coverage |= _BUILTIN[m["table"]][m["chain"]]

    if live_builtin:
        status = "blocking"
    elif live:
        status = "unverified"
    elif any(m["enabled"] for m in matches):
        status = "shadowed"
    elif matches:
        status = "disabled"
    else:
        status = "none"

    return {
        "status": status,
        "rules": matches,
        "coverage": sorted(coverage),
        "packets": sum(m["packets"] for m in live),
        "custom_chains": sorted({m["chain"] for m in live if not m["builtin"]}),
    }


def analyze(list_name: str, tables: dict[str, list[dict[str, Any]] | None]) -> dict[str, Any]:
    """Pure verdict for one router.

    `tables` keys: "filter", "raw" (IPv4) and "filter6", "raw6" (IPv6), each
    a list of rule dicts as RouterOS returns them, in rule order. An IPv6
    table of None means the router has no IPv6 firewall (package off); the
    IPv6 verdict is then None.
    """
    v4 = _analyze_family(list_name, {"filter": tables.get("filter"), "raw": tables.get("raw")})
    has_v6 = tables.get("filter6") is not None or tables.get("raw6") is not None
    v6 = _analyze_family(list_name, {"filter": tables.get("filter6"), "raw": tables.get("raw6")}) \
        if has_v6 else None

    warnings: list[str] = []
    if v4["status"] == "blocking":
        cov = set(v4["coverage"])
        if "forward" not in cov:
            warnings.append("Only traffic to the router itself is dropped. Banned IPs can "
                            "still reach port-forwarded services on your network — add the "
                            "rule to the forward chain too, or use raw prerouting.")
        elif "input" not in cov:
            warnings.append("Only forwarded traffic is dropped. Banned IPs can still reach "
                            "the router itself (its services, VPN) — add the rule to the "
                            "input chain too, or use raw prerouting.")
    if v6 is not None and v6["status"] != "blocking" and v4["status"] == "blocking":
        warnings.append("No IPv6 drop rule — IPv6 bans Protek pushes to the IPv6 "
                        "address-list aren't blocked.")

    return {
        "list": list_name,
        "status": v4["status"],
        "rules": v4["rules"],
        "coverage": v4["coverage"],
        "packets": v4["packets"],
        "custom_chains": v4["custom_chains"],
        "v6_status": v6["status"] if v6 else None,
        "v6_rules": v6["rules"] if v6 else [],
        "warnings": warnings,
    }


# ── fetchers (read-only) ────────────────────────────────────────────────────

_API_PATHS = {
    "filter": "/ip/firewall/filter",
    "raw": "/ip/firewall/raw",
    "filter6": "/ipv6/firewall/filter",
    "raw6": "/ipv6/firewall/raw",
}


def fetch_rules_api(mt) -> dict[str, list[dict[str, Any]] | None]:
    """Firewall rules over the binary API (`mikrotik.MikroTik`). IPv4 read
    failures raise; IPv6 tables come back None when the router has none."""
    mt.connect()
    try:
        out: dict[str, list[dict[str, Any]] | None] = {}
        for key, path in _API_PATHS.items():
            try:
                out[key] = list(mt._api.get_resource(path).get())  # noqa: SLF001
            except Exception:
                if key in ("filter", "raw"):
                    raise
                out[key] = None
        return out
    finally:
        mt.disconnect()


def fetch_rules_rest(get) -> dict[str, list[dict[str, Any]] | None]:
    """Firewall rules over the REST API. `get(path)` returns a parsed JSON
    list or raises; only GETs are issued."""
    out: dict[str, list[dict[str, Any]] | None] = {}
    for key, path in _API_PATHS.items():
        try:
            out[key] = list(get(path))
        except Exception:
            if key in ("filter", "raw"):
                raise
            out[key] = None
    return out


# ── per-target + cache ─────────────────────────────────────────────────────

def check_target(bouncer) -> dict[str, Any]:
    """Verdict for one target. Targets without `firewall_rules()` (pfSense,
    Cloudflare, …) aren't MikroTiks and return None."""
    fetch = getattr(bouncer, "firewall_rules", None)
    if fetch is None:
        return None
    base = {"target": bouncer.name, "kind": bouncer.kind,
            "list": getattr(bouncer, "list_name", "")}
    try:
        tables = fetch()
    except Exception as e:  # noqa: BLE001
        return {**base, "status": "unknown", "error": str(e)[:300], "rules": [],
                "coverage": [], "packets": 0, "custom_chains": [], "v6_status": None,
                "v6_rules": [], "warnings": []}
    return {**base, **analyze(base["list"], tables), "error": ""}


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Worst status across targets; `status` is None when there are no
    MikroTik targets at all."""
    if not results:
        return {"status": None, "targets": []}
    worst = min(results, key=lambda r: _SEVERITY.index(r["status"]))
    return {"status": worst["status"], "worst": worst["target"], "targets": results}


def refresh() -> dict[str, Any]:
    """Check every enabled MikroTik target and cache the result."""
    import bouncers
    from db import set_setting
    results = []
    for b in bouncers.load_all_targets():
        r = check_target(b)
        if r is not None:
            results.append(r)
    out = {**summarize(results), "checked_at": datetime.now(timezone.utc).isoformat()}
    try:
        set_setting(SETTING_KEY, json.dumps(out))
    except Exception as e:  # noqa: BLE001
        log.warning("couldn't cache blocking status: %s", e)
    return out


def cached() -> dict[str, Any]:
    from db import get_setting
    raw = get_setting(SETTING_KEY)
    if not raw:
        return {"status": None, "targets": [], "checked_at": None}
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {"status": None, "targets": [], "checked_at": None}


def age_seconds(result: dict[str, Any]) -> float | None:
    at = result.get("checked_at")
    if not at:
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(at)).total_seconds()
    except ValueError:
        return None


LABELS = {
    "blocking": "Blocking active",
    "none": "Not blocking — no drop rule",
    "disabled": "Not blocking — drop rule disabled",
    "shadowed": "Not blocking — drop rule never fires",
    "unverified": "Probably blocking — rule in a custom chain",
    "unknown": "Couldn't check the firewall",
}


def pill_state(status: str | None) -> str | None:
    """ok / warn / down for the topbar pill; None hides it."""
    if status is None:
        return None
    if status == "blocking":
        return "ok"
    if status in ("unverified", "unknown"):
        return "warn"
    return "down"
