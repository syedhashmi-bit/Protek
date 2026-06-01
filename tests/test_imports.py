"""Import-smoke: every top-level module must import cleanly.

Most of Protek's modules have no dedicated unit test, so a typo, undefined
name, or bad import in (say) siem.py / honeypot.py / oidc.py would otherwise
ship green — pytest never touches them. Importing each module here is the
cheap safety net that catches NameError / SyntaxError / ImportError across
the whole tree.

Modules are discovered dynamically, so a newly added top-level module is
covered automatically without editing this file.

Importing app.py runs init_db() at module level; the session-scoped temp-DB
fixture in conftest.py points db.DB_PATH at a throwaway database first, so no
real protek.db is touched and the import is side-effect-safe.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _top_level_modules() -> list[str]:
    # Root *.py only. scripts/ are argv-driven CLIs with import-time arg
    # parsing; bouncers/ is a package exercised via its own adapters. Both are
    # out of scope for a blind import-smoke.
    return sorted(
        p.stem
        for p in ROOT.glob("*.py")
        if not p.stem.startswith("_")
    )


@pytest.mark.parametrize("module", _top_level_modules())
def test_module_imports(module: str) -> None:
    importlib.import_module(module)
