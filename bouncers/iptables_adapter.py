"""
iptables/ipset bouncer — for boxes without a managed firewall product.

Two sets are managed:
    protek-bans     hash:net family inet
    protek-bans6    hash:net family inet6

The operator owns the iptables/ip6tables DROP rules that consume the sets:
    iptables  -I INPUT 1 -m set --match-set protek-bans  src -j DROP
    iptables  -I FORWARD 1 -m set --match-set protek-bans src -j DROP
    ip6tables -I INPUT 1 -m set --match-set protek-bans6 src -j DROP
    ip6tables -I FORWARD 1 -m set --match-set protek-bans6 src -j DROP

We never write to iptables — only to ipset. That separation matches
phase-2's MikroTik comment-ownership rule (we own the list contents,
operator owns the firewall rules that consume it).

Ownership is implicit: anything in `protek-bans` is ours, since the set
is named for Protek. Foreign tools should use a different set name.
"""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
from typing import Any

from . import register


@register("iptables_ipset")
class IpsetBouncer:
    """Local-host iptables/ipset bouncer. Runs as root (Protek already does)."""

    field_schema = [
        {"name": "set_v4", "label": "IPv4 ipset name", "type": "text",
         "required": False, "placeholder": "protek-bans", "default": "protek-bans",
         "help": "ipset set name for IPv4 addresses. Operator owns the matching "
                 "iptables `-m set --match-set <name> src -j DROP` rule."},
        {"name": "set_v6", "label": "IPv6 ipset name", "type": "text",
         "required": False, "placeholder": "protek-bans6", "default": "protek-bans6",
         "help": "ipset set name for IPv6 addresses. Adapter auto-creates both sets "
                 "on first health check (-exist, idempotent)."},
        {"name": "max_v4", "label": "Max IPv4 entries", "type": "number",
         "required": False, "placeholder": "200000", "default": 200000, "coerce": "int",
         "help": "Set's hash table size. Default 200 000 fits the largest community feeds."},
        {"name": "max_v6", "label": "Max IPv6 entries", "type": "number",
         "required": False, "placeholder": "50000", "default": 50000, "coerce": "int"},
    ]

    def __init__(self, name: str = "iptables", set_v4: str = "protek-bans",
                 set_v6: str = "protek-bans6", max_v4: int = 200000, max_v6: int = 50000,
                 **_: Any):
        self.name = name
        self.kind = "iptables_ipset"
        self.set_v4 = set_v4
        self.set_v6 = set_v6
        self.max_v4 = int(max_v4)
        self.max_v6 = int(max_v6)
        self._ipset = shutil.which("ipset")
        self._ensured = False

    def is_configured(self) -> bool:
        return bool(self._ipset)

    def health(self) -> dict[str, Any]:
        if not self._ipset:
            return {"ok": False, "bouncer": self.name, "kind": self.kind,
                    "error": "ipset binary not found"}
        try:
            self._ensure_sets()
            return {"ok": True, "bouncer": self.name, "kind": self.kind,
                    "set_v4": self.set_v4, "set_v6": self.set_v6,
                    "v4_size": self._count(self.set_v4),
                    "v6_size": self._count(self.set_v6)}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "bouncer": self.name, "kind": self.kind, "error": str(e)}

    def _ensure_sets(self) -> None:
        if self._ensured:
            return
        for setname, family, maxelem in (
            (self.set_v4, "inet", self.max_v4),
            (self.set_v6, "inet6", self.max_v6),
        ):
            subprocess.run(
                [self._ipset, "create", setname, "hash:net", "family", family,
                 "hashsize", "4096", "maxelem", str(maxelem), "-exist"],
                capture_output=True, text=True, timeout=5, check=False,
            )
        self._ensured = True

    def _count(self, setname: str) -> int:
        try:
            r = subprocess.run(
                [self._ipset, "list", setname], capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode != 0:
                return 0
            # Members section follows "Members:" line.
            members_seen = False
            n = 0
            for line in r.stdout.splitlines():
                if members_seen:
                    if line.strip():
                        n += 1
                elif line.startswith("Members:"):
                    members_seen = True
            return n
        except Exception:  # noqa: BLE001
            return 0

    def snapshot(self) -> list[dict[str, Any]]:
        """Return all set members in the Protek-flavored entry shape.

        The set itself is our ownership marker — every entry is owned. We
        synthesize a comment that mirrors what reconcile.py would have
        written, so the reconcile diff still works through the standard
        is_owned() path.
        """
        if not self._ipset:
            return []
        self._ensure_sets()
        out: list[dict[str, Any]] = []
        for setname in (self.set_v4, self.set_v6):
            try:
                r = subprocess.run(
                    [self._ipset, "list", setname], capture_output=True, text=True, timeout=15, check=False,
                )
                if r.returncode != 0:
                    continue
                members_seen = False
                for line in r.stdout.splitlines():
                    if members_seen:
                        addr = line.strip()
                        if not addr:
                            continue
                        out.append({
                            "address": addr,
                            "comment": "protek:ipset::0",  # implicit ownership
                            ".id": f"{setname}|{addr}",   # synthetic handle
                            "list": setname,
                        })
                    elif line.startswith("Members:"):
                        members_seen = True
            except Exception:  # noqa: BLE001
                continue
        return out

    def apply(self, to_add: list[tuple[str, str]], to_remove_ids: list[str]) -> dict[str, Any]:
        if not self._ipset:
            return {"applied_add": 0, "applied_remove": 0, "errors": 0, "push_log": []}
        self._ensure_sets()
        applied_add = 0
        applied_remove = 0
        errors = 0
        push_log: list[dict[str, Any]] = []
        for addr, _comment in to_add:
            target = self._set_for(addr)
            try:
                r = subprocess.run(
                    [self._ipset, "add", target, addr, "-exist"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                if r.returncode == 0:
                    applied_add += 1
                    push_log.append({"ip": addr, "action": "add", "success": True})
                else:
                    errors += 1
                    push_log.append({"ip": addr, "action": "add", "success": False,
                                     "error": (r.stderr or r.stdout)[:300]})
            except Exception as e:  # noqa: BLE001
                errors += 1
                push_log.append({"ip": addr, "action": "add", "success": False, "error": str(e)[:300]})
        for rid in to_remove_ids:
            # synthetic id is "setname|address"
            if "|" not in rid:
                continue
            target, addr = rid.split("|", 1)
            try:
                r = subprocess.run(
                    [self._ipset, "del", target, addr, "-exist"],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                if r.returncode == 0:
                    applied_remove += 1
                    push_log.append({"ip": addr, "action": "remove", "success": True})
                else:
                    errors += 1
                    push_log.append({"ip": addr, "action": "remove", "success": False,
                                     "error": (r.stderr or r.stdout)[:300]})
            except Exception as e:  # noqa: BLE001
                errors += 1
                push_log.append({"ip": addr, "action": "remove", "success": False, "error": str(e)[:300]})
        return {"applied_add": applied_add, "applied_remove": applied_remove,
                "errors": errors, "push_log": push_log}

    def _set_for(self, addr: str) -> str:
        try:
            if ":" in addr or isinstance(ipaddress.ip_network(addr, strict=False).network_address, ipaddress.IPv6Address):
                return self.set_v6
        except ValueError:
            pass
        return self.set_v4
