"""Shared test fixtures.

Guarantees no test ever touches the developer's real protek.db (CLAUDE.md:
"never read protek.db"). Every session runs against a throwaway temp DB with a
freshly migrated schema, so tests that read settings/tables don't depend on an
ambient, pre-initialized database — which is exactly what broke in CI where no
protek.db exists.

Tests that want their own per-test DB still override db.DB_PATH via the
function-scoped `monkeypatch` fixture; monkeypatch restores back to this
session default afterward, so the two layers don't conflict.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def _session_temp_db():
    import db

    tmpdir = tempfile.mkdtemp(prefix="protek-test-db-")
    original = db.DB_PATH
    db.DB_PATH = Path(tmpdir) / "protek-test.db"
    db.init_db()
    try:
        yield
    finally:
        db.DB_PATH = original
