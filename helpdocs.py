"""
helpdocs.py — the in-app help text (roadmap #4).

One catalog, help/catalog.json, feeds both the guided tour and help mode, so
they can't drift apart. It's keyed by page — the `active=` key each route
passes, the same keys NAV uses:

    {"pages": {"<key>": {
        "intro":    "what this page is for",
        "sections": {"<h2 leading text>": "..."},     # each panel heading
        "kpis":     {"<.kpi .k label>": "..."},       # each figure tile
        "fields":   {"<input name>": "..."}}},        # each setting; * = wildcard
     "fields": {"<input name>": "..."}}               # shared fallbacks

The browser matches a heading by prefix (the catalog holds the static part of
headings like "Address-List · {{ list }}"), so keys are the leading text as
written in the template. tests/test_help.py fails when a NAV page, a section,
a KPI or a field on a covered template has no entry.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

CATALOG = Path(__file__).resolve().parent / "help" / "catalog.json"

# "Tour Protek" — the everyday pages, in the order a new admin meets them.
TOUR = ["dashboard", "decisions", "alerts", "bouncers", "whitelist", "settings"]


@lru_cache(maxsize=1)
def catalog() -> dict[str, Any]:
    try:
        return json.loads(CATALOG.read_text())
    except (OSError, ValueError):
        return {"pages": {}, "fields": {}}


def for_page(key: str) -> dict[str, Any]:
    """Help for one page; shared field help is merged under the page's own."""
    cat = catalog()
    page = (cat.get("pages") or {}).get(key) or {}
    fields = dict(cat.get("fields") or {})
    fields.update(page.get("fields") or {})
    return {
        "intro": page.get("intro", ""),
        "sections": page.get("sections") or {},
        "kpis": page.get("kpis") or {},
        "fields": fields,
    }


def has_page(key: str) -> bool:
    return key in (catalog().get("pages") or {})
