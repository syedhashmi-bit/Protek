"""
database.py — Arc 13 phase 75. DB abstraction layer (experimental).

Status: **scaffolding**. SQLite remains the only supported backend in
Protek 2.0. This module exists so the migration to Postgres in a future
release is additive rather than a fork.

The shape we'll keep stable as Postgres support lands:

    from database import get_conn, dialect

    conn = get_conn()            # returns a DB-API-compatible connection
    dialect.name                 # "sqlite" or "postgres"
    dialect.now_expr             # SQL expression for "now" — varies per backend
    dialect.upsert(...)          # helper that emits ON CONFLICT or ON DUPLICATE

`get_conn()` here just forwards to `db.get_conn()` (sqlite) — that's the
only path we ship right now. The Postgres path raises NotImplementedError
with a pointer to the migration script.

When the Postgres work happens (post-2.0):
  1. Add `psycopg[binary]` to requirements.
  2. Implement `_pg_get_conn()` returning a psycopg connection that exposes
     `.execute()` returning rows that behave like sqlite3.Row (dict-style
     access). psycopg's `dict_row` factory does this.
  3. Adapt the schema in db.SCHEMA + EXTRA_TABLES to dialect-tagged variants
     (INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL PRIMARY KEY, etc.).
  4. Port the audit_log triggers (Postgres uses `CREATE FUNCTION` + `CREATE
     TRIGGER` instead of SQLite's BEFORE UPDATE BEGIN ... END syntax).
  5. Migration tool dumps SQLite rows + inserts into Postgres, preserving ids.

Until then, `DATABASE_URL=postgresql://...` is rejected at boot with a
clear error so operators don't think they've enabled something they haven't.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger("protek.database")


def _url() -> str:
    return (os.environ.get("DATABASE_URL", "") or "").split("#", 1)[0].strip()


@dataclass(frozen=True)
class Dialect:
    name: str
    now_expr: str
    autoincrement: str
    json_type: str
    placeholder: str

    @classmethod
    def for_current(cls) -> "Dialect":
        url = _url()
        if url.startswith(("postgres://", "postgresql://")):
            return cls(name="postgres",
                       now_expr="now()",
                       autoincrement="SERIAL",
                       json_type="JSONB",
                       placeholder="%s")
        return cls(name="sqlite",
                   now_expr="datetime('now')",
                   autoincrement="INTEGER PRIMARY KEY AUTOINCREMENT",
                   json_type="TEXT",
                   placeholder="?")


dialect = Dialect.for_current()


def get_conn():
    url = _url()
    if url.startswith(("postgres://", "postgresql://")):
        raise NotImplementedError(
            "Postgres support is scaffolded but not yet implemented. "
            "Unset DATABASE_URL to use SQLite (the supported backend), "
            "or contribute the psycopg implementation per "
            "docs/postgres-migration.md."
        )
    # Default path: forward to the SQLite implementation in db.py
    from db import get_conn as _sqlite
    return _sqlite()


def is_sqlite() -> bool:
    return dialect.name == "sqlite"


def is_postgres() -> bool:
    return dialect.name == "postgres"
