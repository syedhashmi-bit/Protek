"""
reconcile.py — the diff engine.

Pure function. No I/O. No imports of crowdsec / mikrotik / db.

Given:
    desired_decisions  — what SHOULD be in the address-list, deduped union of
                         all federated LAPI sources
    current_mt_entries — what IS in the address-list right now (all entries,
                         not just Protek's — the ownership filter lives here
                         so the diff itself never proposes removing a foreign
                         entry)

Returns:
    ReconcileDiff(to_add, to_remove, unchanged)

This is the only piece of logic that has to be exactly correct. Everything
else (the LAPI client, the MT adapter, the poller) is plumbing. Pure-function
design lets us unit-test the whole behavior tree without a CrowdSec or a
MikroTik instance. See SKILL.md § 4.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


OWNER_PREFIX = "protek:"


def encode_comment(decision: dict[str, Any]) -> str:
    """Build the ownership-marker comment Protek writes to MikroTik.

    Format: protek:<origin_source>:<scenario>:<lapi_id>

    The leading "protek:" prefix is the ownership marker. Anything in the
    address-list without that prefix is considered foreign and Protek MUST
    NOT touch it.

    We use ":" as delimiter and sanitize each field so a malicious-looking
    scenario name can't break round-tripping.
    """
    src = _sanitize(decision.get("origin_source") or "local")
    scen = _sanitize(decision.get("scenario") or "")
    lid = _sanitize(str(decision.get("lapi_id") or decision.get("id") or "0"))
    return f"{OWNER_PREFIX}{src}:{scen}:{lid}"


def decode_comment(comment: str) -> dict[str, str] | None:
    """Return the four-part metadata stuffed into a `protek:` comment.

    Returns None if the comment isn't ours. We intentionally accept any
    comment shape starting with "protek:" — older Protek versions may have
    written variants and we don't want to orphan their entries.
    """
    if not comment or not comment.startswith(OWNER_PREFIX):
        return None
    body = comment[len(OWNER_PREFIX):]
    parts = body.split(":", 2)
    while len(parts) < 3:
        parts.append("")
    return {"origin_source": parts[0], "scenario": parts[1], "lapi_id": parts[2]}


def _sanitize(s: str) -> str:
    # Strip colons (our delimiter) and surrounding whitespace.
    return (s or "").replace(":", "_").strip()


def is_owned(comment: str | None) -> bool:
    return bool(comment) and comment.startswith(OWNER_PREFIX)


@dataclass
class ReconcileDiff:
    to_add: list[tuple[str, str]] = field(default_factory=list)      # (address, comment)
    to_remove: list[str] = field(default_factory=list)                # MT .id values
    unchanged: int = 0
    foreign_kept: int = 0    # entries left alone because they're not ours

    @property
    def changes(self) -> int:
        return len(self.to_add) + len(self.to_remove)


def reconcile(
    desired_decisions: list[dict[str, Any]],
    current_mt_entries: list[dict[str, Any]],
) -> ReconcileDiff:
    """Pure diff. Both inputs are lists of dicts.

    desired_decisions: each dict must have at minimum 'value' (the IP/CIDR).
                       Optional 'origin_source', 'scenario', 'id'/'lapi_id'
                       for the comment.
    current_mt_entries: raw entries from /ip/firewall/address-list. Each
                        should have 'address', 'comment', and an id field
                        (either '.id' or 'id').

    Deduplication: if two decisions target the same value, the first wins
    (the caller decides which "first" — we don't enforce a confidence rule
    here, that's phase 10).

    Ownership: foreign entries (comment without "protek:" prefix) are
    counted but never proposed for removal.
    """
    # Build a desired-by-address map, first-wins on collisions.
    desired_by_addr: dict[str, dict[str, Any]] = {}
    for d in desired_decisions:
        val = (d.get("value") or "").strip()
        if not val:
            continue
        desired_by_addr.setdefault(val, d)

    # Split current entries into ours vs foreign. Only ours can be diff'd.
    diff = ReconcileDiff()
    owned_by_addr: dict[str, dict[str, Any]] = {}
    for e in current_mt_entries:
        if is_owned(e.get("comment")):
            addr = _normalize_addr(e.get("address", ""))
            owned_by_addr[addr] = e
        else:
            diff.foreign_kept += 1

    # to_add: desired addresses not present among our owned entries
    for addr, d in desired_by_addr.items():
        n_addr = _normalize_addr(addr)
        if n_addr in owned_by_addr:
            diff.unchanged += 1
        else:
            diff.to_add.append((addr, encode_comment(d)))

    # to_remove: our owned entries whose address is no longer desired
    desired_norm = {_normalize_addr(a) for a in desired_by_addr.keys()}
    for addr, e in owned_by_addr.items():
        if addr not in desired_norm:
            eid = e.get("id") or e.get(".id")
            if eid:
                diff.to_remove.append(str(eid))

    return diff


def _normalize_addr(addr: str) -> str:
    """Canonical form for address comparison.

    MikroTik may store '1.2.3.4' and '1.2.3.4/32' as separate entries even
    though they mean the same thing. We treat both as equivalent for the
    purposes of diffing — desired '1.2.3.4' matches a MT entry stored as
    '1.2.3.4' OR '1.2.3.4/32'.
    """
    a = (addr or "").strip().lower()
    if a.endswith("/32"):
        a = a[:-3]
    if a.endswith("/128"):
        a = a[:-4]
    return a
