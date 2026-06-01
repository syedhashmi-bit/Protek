# Postgres migration plan (post-2.0)

Phase 75 ships the **abstraction layer** but keeps SQLite as the only
supported backend in 2.0. This document is the contract for finishing the
Postgres path in a future release without breaking existing installs.

## Why we didn't ship Postgres in 2.0

Doing it well requires:
- Schema port (SQLite's INTEGER PRIMARY KEY AUTOINCREMENT → SERIAL; CHECK
  constraint syntax differences; PRAGMA replacements with `SET LOCAL`)
- Trigger port: `audit_log`'s append-only triggers are SQLite-specific
  syntax — Postgres needs `CREATE FUNCTION ... RETURNS trigger` + a
  `CREATE TRIGGER` referencing it.
- Migration tool (dump SQLite, load Postgres, preserve IDs and JSON columns)
- Every `conn.execute("... ?")` becomes parameter-style `... %s` for psycopg
- Datetime handling: SQLite stores text ISO strings; psycopg returns
  datetime objects natively — code that does `row["created_at"][:19]` would
  break

Doing it half-way is worse than not at all — half-broken Postgres would
silently corrupt audit history on the first row that hits an unported
trigger. So 2.0 ships the architectural foundation and ships SQLite-only.

## What's in place

- `database.py` — `get_conn()` + `dialect` selector keyed off `DATABASE_URL`
- Postgres URL → explicit `NotImplementedError` at boot, no silent fallback
- This document, so future work has a clear contract

## What lands in the Postgres-completion phase

### 1. Dependency
```
psycopg[binary]>=3.2,<4.0
```

### 2. Connection factory
```python
def _pg_get_conn():
    import psycopg
    from psycopg.rows import dict_row
    url = _url()
    conn = psycopg.connect(url, autocommit=True, row_factory=dict_row)
    # Match sqlite's foreign_keys=ON behavior — Postgres enforces by default
    # but we set a couple of session knobs for parity.
    conn.execute("SET timezone TO 'UTC'")
    return conn
```

### 3. SQL parameter style
Every `conn.execute("... WHERE x = ?", (v,))` becomes:
- SQLite: `conn.execute("... WHERE x = ?", (v,))`
- Postgres: `conn.execute("... WHERE x = %s", (v,))`

Two ways to bridge:
- **A.** Switch to a query rewriter in `database.execute(sql, params)` that
  replaces `?` with the dialect's placeholder before forwarding.
- **B.** Use SQLAlchemy Core (or `sqlalchemy.text(":x")` named params) and
  let the dialect drive parameter style.

Recommendation: A is less invasive (each callsite stays as-is). B is more
"correct" long-term. Phase choice depends on appetite.

### 4. Schema port
For each statement in `db.SCHEMA` + `db.EXTRA_TABLES`:
- `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY` (Postgres)
- `TEXT` → `TEXT` (no change)
- `INTEGER` → `INTEGER` or `BIGINT` (no change for our row counts)
- `REAL` → `DOUBLE PRECISION`
- `TEXT NOT NULL DEFAULT ''` → `TEXT NOT NULL DEFAULT ''` (no change)
- Boolean-like INTEGER columns stay INTEGER (we use 0/1 throughout)
- CHECK constraints work identically

Triggers (audit_log):
```sql
-- SQLite (current)
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, '...'); END;

-- Postgres equivalent
CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only — % rejected', TG_OP;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_update
BEFORE UPDATE ON audit_log
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
CREATE TRIGGER audit_log_no_delete
BEFORE DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
```

### 5. Migration tool
A `scripts/sqlite_to_postgres.py` script that:
1. Connects to both DBs
2. For each table in dependency order: stream rows from SQLite, INSERT into
   Postgres with `ON CONFLICT DO NOTHING` for idempotent re-runs
3. Resets each Postgres sequence to `MAX(id) + 1` after the dump
4. Verifies row counts match per-table before exiting

### 6. CI matrix
Add a Postgres service to GitHub Actions / your CI; run the full test suite
against both backends. Most tests already work — the SQLite-specific
ones (the trigger test, the WAL-mode test) become dialect-conditional.

## Operator-facing impact

Once Postgres ships:
- Existing SQLite installs: zero change. `DATABASE_URL` unset = SQLite.
- New Postgres installs: `DATABASE_URL=postgresql://user:pw@host/db` →
  Protek targets Postgres. `init_db()` issues the dialect-aware CREATE TABLEs.
- Migrating: stop Protek, run `sqlite_to_postgres.py`, set `DATABASE_URL`,
  start Protek. <5 min for a 100 MB SQLite.

## Why this matters for 2.0

Shipping the abstraction in 2.0 means:
- Future Postgres work is additive (no schema migration breaks SQLite users)
- Operators who want to bench Postgres for their scale can fork from a clean
  hook point rather than from raw `db.py`
- The shape we promise is stable: `get_conn()`, `dialect`, parameter style
  via the placeholder field
