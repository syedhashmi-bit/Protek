"""
db.py — SQLite schema, connection helper, and idempotent migrations.

The connection uses WAL mode (concurrent reads + a single writer); fine for
single-server Protek deployments under any realistic LAPI volume.

All new columns must be added to BOTH the CREATE TABLE block AND the
migration block (PRAGMA-guarded ADD COLUMN). See CLAUDE.md.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

# Phase 95 — Docker image mounts a volume at /data for state.
# PROTEK_DB_PATH overrides the bare-metal default for containerised
# deployments. Bare-metal install.sh / systemd unit don't set this,
# so existing deployments keep the parent-dir layout.
DB_PATH = Path(
    os.environ.get("PROTEK_DB_PATH")
    or (Path(__file__).resolve().parent / "protek.db")
)


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


# ── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = [
    # Decisions mirror — what LAPI currently considers active, plus an audit
    # trail of expired/deleted ones. `origin_source` is here from day one so
    # phase-2 federation is additive, not a migration.
    """
    CREATE TABLE IF NOT EXISTS decisions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        origin_source   TEXT    NOT NULL DEFAULT 'local',
        lapi_id         INTEGER NOT NULL,
        value           TEXT    NOT NULL,
        scope           TEXT    NOT NULL DEFAULT 'Ip',
        type            TEXT    NOT NULL DEFAULT 'ban',
        scenario        TEXT    DEFAULT '',
        origin          TEXT    DEFAULT '',
        duration        TEXT    DEFAULT '',
        until           TEXT    DEFAULT NULL,
        first_seen_at   TEXT    NOT NULL,
        last_seen_at    TEXT    NOT NULL,
        deleted_at      TEXT    DEFAULT NULL,
        UNIQUE (origin_source, lapi_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_decisions_active ON decisions (deleted_at, value)",
    "CREATE INDEX IF NOT EXISTS idx_decisions_value  ON decisions (value)",
    "CREATE INDEX IF NOT EXISTS idx_decisions_scenario ON decisions (scenario)",

    # Alerts (richer event context) — populated when a machine credential is
    # available; with only a bouncer credential this table stays empty.
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        origin_source   TEXT    NOT NULL DEFAULT 'local',
        lapi_id         INTEGER NOT NULL,
        machine_id      TEXT    DEFAULT '',
        scenario        TEXT    DEFAULT '',
        source_ip       TEXT    DEFAULT '',
        source_asn      TEXT    DEFAULT '',
        source_country  TEXT    DEFAULT '',
        events_count    INTEGER DEFAULT 0,
        created_at      TEXT    NOT NULL,
        raw_json        TEXT    DEFAULT '',
        UNIQUE (origin_source, lapi_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at)",

    # Reconcile cycles — one row per cycle (auto or manual). MT pushes hang off
    # a sync_event_id. Phase 3+ will populate; phase 2 leaves duration_ms NULL.
    """
    CREATE TABLE IF NOT EXISTS sync_events (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at   TEXT NOT NULL,
        duration_ms  INTEGER DEFAULT NULL,
        added        INTEGER DEFAULT 0,
        removed      INTEGER DEFAULT 0,
        unchanged    INTEGER DEFAULT 0,
        errors       INTEGER DEFAULT 0,
        source       TEXT NOT NULL DEFAULT 'auto',
        dry_run      INTEGER NOT NULL DEFAULT 1,
        notes        TEXT DEFAULT ''
    )
    """,

    # Per-entry MT push log
    """
    CREATE TABLE IF NOT EXISTS mt_pushes (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        sync_event_id  INTEGER NOT NULL,
        ip             TEXT NOT NULL,
        action         TEXT NOT NULL,
        success        INTEGER NOT NULL DEFAULT 1,
        error          TEXT DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_mt_pushes_event ON mt_pushes (sync_event_id)",

    # Geo cache (used from phase 5; created now so the worker can fill it lazily)
    """
    CREATE TABLE IF NOT EXISTS geo_cache (
        ip          TEXT PRIMARY KEY,
        country     TEXT DEFAULT '',
        country_code TEXT DEFAULT '',
        city        TEXT DEFAULT '',
        lat         REAL DEFAULT NULL,
        lon         REAL DEFAULT NULL,
        asn         TEXT DEFAULT '',
        as_org      TEXT DEFAULT '',
        cached_at   TEXT NOT NULL
    )
    """,

    # Auth: rate-limit + audit
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL,
        attempts     INTEGER DEFAULT 1,
        locked_until TEXT DEFAULT NULL,
        last_attempt TEXT NOT NULL,
        UNIQUE (ip)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS login_audit (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ip         TEXT NOT NULL,
        username   TEXT NOT NULL,
        success    INTEGER NOT NULL,
        reason     TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_login_audit_created ON login_audit (created_at)",

    # Single-row settings store for runtime-tunable knobs (sync interval, etc.).
    # .env is the source of truth for SECRETS only; this is for operational toggles.
    """
    CREATE TABLE IF NOT EXISTS settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,

    # Phase-2 federation table (created now, used later). Local LAPI seeded on
    # first run from .env values.
    """
    CREATE TABLE IF NOT EXISTS sources (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT UNIQUE NOT NULL,
        url           TEXT NOT NULL,
        api_key       TEXT NOT NULL,
        enabled       INTEGER NOT NULL DEFAULT 1,
        last_pull_at  TEXT DEFAULT NULL,
        last_pull_n   INTEGER DEFAULT 0,
        last_error    TEXT DEFAULT '',
        created_at    TEXT NOT NULL
    )
    """,
]


# ── Migrations: idempotent column-adds ──────────────────────────────────────
# Each tuple: (table, column, definition). Skipped if column already exists.

MIGRATIONS: list[tuple[str, str, str]] = [
    # Phase 55 — per-stage sync timing breakdown. snapshot_ms + apply_ms are
    # per-bouncer sums; diff_ms is compute-only; lapi_fetch_ms covers the
    # earlier poller cycle. All start as zero on old rows (no migration data).
    ("sync_events", "lapi_fetch_ms", "INTEGER NOT NULL DEFAULT 0"),
    ("sync_events", "snapshot_ms",   "INTEGER NOT NULL DEFAULT 0"),
    ("sync_events", "diff_ms",       "INTEGER NOT NULL DEFAULT 0"),
    ("sync_events", "apply_ms",      "INTEGER NOT NULL DEFAULT 0"),
    # Arc 2 — Federation
    ("sources", "backoff_until", "TEXT DEFAULT NULL"),
    ("sources", "paused", "INTEGER NOT NULL DEFAULT 0"),
    ("sources", "confidence", "INTEGER NOT NULL DEFAULT 1"),
    # Arc 15 phase 88 — per-source pull duration for /federation latency display
    ("sources", "last_pull_ms", "INTEGER NOT NULL DEFAULT 0"),
    # Arc 3 — Intelligence
    ("decisions", "asn", "TEXT DEFAULT ''"),
    ("decisions", "as_org", "TEXT DEFAULT ''"),
    ("geo_cache", "rdns", "TEXT DEFAULT ''"),
    # Arc 4 — Scenarios & Rules: whitelist, allowlist, approval queue
]


# ── Arc 2/3/4 — extra tables created on init ────────────────────────────────

EXTRA_TABLES = [
    # Per-IP cross-source tracker (phase 10).
    """
    CREATE TABLE IF NOT EXISTS ip_sources (
        ip          TEXT NOT NULL,
        source_name TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (ip, source_name)
    )
    """,
    # CrowdSec CTI / threat-feed cache (phase 13 / 18).
    """
    CREATE TABLE IF NOT EXISTS cti_cache (
        ip          TEXT PRIMARY KEY,
        reputation  TEXT DEFAULT '',
        score       INTEGER DEFAULT 0,
        classifications TEXT DEFAULT '',
        behaviors   TEXT DEFAULT '',
        feeds       TEXT DEFAULT '',
        raw_json    TEXT DEFAULT '',
        cached_at   TEXT NOT NULL
    )
    """,
    # WHOIS cache (phase 16).
    """
    CREATE TABLE IF NOT EXISTS whois_cache (
        ip          TEXT PRIMARY KEY,
        netname     TEXT DEFAULT '',
        org         TEXT DEFAULT '',
        country     TEXT DEFAULT '',
        abuse_email TEXT DEFAULT '',
        raw         TEXT DEFAULT '',
        cached_at   TEXT NOT NULL
    )
    """,
    # Whitelist (phase 24) — per-IP / CIDR / ASN / country.
    """
    CREATE TABLE IF NOT EXISTS whitelist (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        kind        TEXT NOT NULL CHECK (kind IN ('ip','cidr','asn','country')),
        value       TEXT NOT NULL,
        note        TEXT DEFAULT '',
        expires_at  TEXT DEFAULT NULL,
        created_at  TEXT NOT NULL,
        UNIQUE (kind, value)
    )
    """,
    # Whitelist hit log (which rule saved which IP).
    """
    CREATE TABLE IF NOT EXISTS whitelist_hits (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL,
        whitelist_id INTEGER NOT NULL,
        scenario     TEXT DEFAULT '',
        created_at   TEXT NOT NULL
    )
    """,
    # Decision approval queue (phase 26).
    """
    CREATE TABLE IF NOT EXISTS approval_queue (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL,
        scope        TEXT NOT NULL DEFAULT 'Ip',
        scenario     TEXT DEFAULT '',
        origin       TEXT DEFAULT '',
        origin_source TEXT DEFAULT 'local',
        decision_id  INTEGER,
        status       TEXT NOT NULL DEFAULT 'pending',
        decided_by   TEXT DEFAULT '',
        decided_at   TEXT DEFAULT NULL,
        created_at   TEXT NOT NULL
    )
    """,
    # Per-bouncer targets (phase 27/32) — multi-target outputs.
    """
    CREATE TABLE IF NOT EXISTS bouncer_targets (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT UNIQUE NOT NULL,
        kind         TEXT NOT NULL,
        config_json  TEXT NOT NULL DEFAULT '{}',
        enabled      INTEGER NOT NULL DEFAULT 1,
        dry_run      INTEGER NOT NULL DEFAULT 1,
        last_sync_at TEXT DEFAULT NULL,
        last_error   TEXT DEFAULT '',
        created_at   TEXT NOT NULL
    )
    """,
    # SIEM forwarding journal (phase 34) — every shipped event lands here so
    # we can replay the last N to a freshly-pointed syslog target. Bounded
    # by `siem.journal_cap` setting (defaults 10k); oldest rows pruned.
    """
    CREATE TABLE IF NOT EXISTS siem_journal (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at   TEXT NOT NULL,
        event_type   TEXT NOT NULL,
        severity     INTEGER NOT NULL DEFAULT 6,
        payload_json TEXT NOT NULL DEFAULT '{}',
        shipped_at   TEXT DEFAULT NULL,
        ship_error   TEXT DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_siem_journal_created ON siem_journal (created_at)",
    "CREATE INDEX IF NOT EXISTS idx_siem_journal_shipped ON siem_journal (shipped_at)",
    # Audit trail (phase 35) — append-only operator-action log. Never
    # UPDATE'd or DELETE'd in normal code paths; row IDs are durable.
    """
    CREATE TABLE IF NOT EXISTS audit_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at   TEXT NOT NULL,
        actor        TEXT NOT NULL DEFAULT '',
        ip           TEXT NOT NULL DEFAULT '',
        action       TEXT NOT NULL,
        target       TEXT NOT NULL DEFAULT '',
        before_json  TEXT NOT NULL DEFAULT '',
        after_json   TEXT NOT NULL DEFAULT '',
        note         TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log (created_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_log_action  ON audit_log (action)",
    # Composite alerting (phase 38) — per-rule firing state for dedup +
    # auto-resolve, plus an operator-defined silence list.
    """
    CREATE TABLE IF NOT EXISTS alert_states (
        rule_key      TEXT PRIMARY KEY,
        firing        INTEGER NOT NULL DEFAULT 0,
        level         INTEGER NOT NULL DEFAULT 4,
        firing_since  TEXT DEFAULT NULL,
        last_check    TEXT NOT NULL DEFAULT '',
        last_message  TEXT NOT NULL DEFAULT '',
        last_notified TEXT DEFAULT NULL,
        consecutive   INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS alert_silences (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern      TEXT NOT NULL,
        until_at     TEXT NOT NULL,
        reason       TEXT NOT NULL DEFAULT '',
        created_at   TEXT NOT NULL,
        created_by   TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alert_silences_until ON alert_silences (until_at)",
    # ASN auto-ban escalations (phase 57). A rule fires when N distinct IPs
    # from the same ASN have created decisions within `window_hours`.
    # Operator approves the suggestion (creating a permanent block rule) or
    # dismisses it. Dismissals re-suggest only after a fresh trigger.
    """
    CREATE TABLE IF NOT EXISTS asn_escalations (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        asn             TEXT NOT NULL,
        as_org          TEXT NOT NULL DEFAULT '',
        ip_count        INTEGER NOT NULL DEFAULT 0,
        window_hours    INTEGER NOT NULL DEFAULT 24,
        sample_ips      TEXT NOT NULL DEFAULT '',
        first_seen_at   TEXT NOT NULL,
        last_seen_at    TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'pending',
        decided_by      TEXT NOT NULL DEFAULT '',
        decided_at      TEXT DEFAULT NULL,
        note            TEXT NOT NULL DEFAULT ''
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_asn_escalations_status ON asn_escalations (status)",
    "CREATE INDEX IF NOT EXISTS idx_asn_escalations_asn    ON asn_escalations (asn)",
    # Tag store (phase 60). Lightweight per-IP labels: tor-exit, vpn, proxy,
    # honeypot-routed, etc. Multiple tags per IP allowed via (ip, tag) PK.
    """
    CREATE TABLE IF NOT EXISTS ip_tags (
        ip              TEXT NOT NULL,
        tag             TEXT NOT NULL,
        source          TEXT NOT NULL DEFAULT '',
        created_at      TEXT NOT NULL,
        expires_at      TEXT DEFAULT NULL,
        PRIMARY KEY (ip, tag)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_ip_tags_tag ON ip_tags (tag)",
    # ASN reputation memoization (phase 58). Caches the composite score per
    # IP. Recomputed on enrichment events or expiry. Computing on every
    # decision render would be too slow at 19k decisions.
    """
    CREATE TABLE IF NOT EXISTS reputation_cache (
        ip              TEXT PRIMARY KEY,
        score           INTEGER NOT NULL,
        tier            TEXT NOT NULL,
        breakdown_json  TEXT NOT NULL DEFAULT '{}',
        computed_at     TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_reputation_tier ON reputation_cache (tier)",
    # Multi-admin (phase 42) — additional admin accounts beyond the env-anchored
    # one. The env user (APP_USERNAME / APP_PASSWORD_HASH / TOTP_SECRET) still
    # exists as the bootstrap identity and lives in row #1 (mirrored at boot).
    # `role` drives RBAC (phase 43): viewer / operator / admin.
    """
    CREATE TABLE IF NOT EXISTS users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT NOT NULL UNIQUE,
        password_hash   TEXT NOT NULL,
        totp_secret     TEXT NOT NULL,
        role            TEXT NOT NULL DEFAULT 'admin',
        created_at      TEXT NOT NULL,
        last_login_at   TEXT DEFAULT NULL,
        disabled        INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)",
    # API tokens (phase 47 foundation, used by phases 40, 46) — bearer tokens
    # for /api/v1/* + /api/external/* + protekctl. The token itself is never
    # stored; we store only sha256(token).
    """
    CREATE TABLE IF NOT EXISTS api_tokens (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT NOT NULL,
        token_hash      TEXT NOT NULL UNIQUE,
        token_prefix    TEXT NOT NULL,
        scopes          TEXT NOT NULL DEFAULT 'read',
        created_by      TEXT NOT NULL DEFAULT '',
        created_at      TEXT NOT NULL,
        expires_at      TEXT DEFAULT NULL,
        last_used_at    TEXT DEFAULT NULL,
        last_used_ip    TEXT DEFAULT '',
        disabled        INTEGER NOT NULL DEFAULT 0
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens (token_hash)",
    # Outbound webhook subscribers (phase 45) — POSTs sent on decision events.
    """
    CREATE TABLE IF NOT EXISTS webhook_subs (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT NOT NULL UNIQUE,
        url             TEXT NOT NULL,
        hmac_secret     TEXT NOT NULL DEFAULT '',
        event_mask      TEXT NOT NULL DEFAULT '*',
        enabled         INTEGER NOT NULL DEFAULT 1,
        created_at      TEXT NOT NULL,
        last_ok_at      TEXT DEFAULT NULL,
        last_error      TEXT DEFAULT '',
        consec_failures INTEGER NOT NULL DEFAULT 0
    )
    """,
    # DLQ for outbound webhook deliveries that exhausted their retries.
    """
    CREATE TABLE IF NOT EXISTS webhook_dlq (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        sub_id          INTEGER NOT NULL,
        event_type      TEXT NOT NULL,
        payload_json    TEXT NOT NULL,
        last_error      TEXT NOT NULL DEFAULT '',
        attempts        INTEGER NOT NULL DEFAULT 0,
        first_seen_at   TEXT NOT NULL,
        last_attempt_at TEXT DEFAULT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_webhook_dlq_sub ON webhook_dlq (sub_id)",
    # Phase 93 — disk usage samples for the watchdog. Capped at 1440 rows
    # (≈24 h @ 1 sample/min) via pruning inside disk_watchdog.sample().
    """
    CREATE TABLE IF NOT EXISTS disk_samples (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          TEXT    NOT NULL,
        used_pct    REAL    NOT NULL,
        free_bytes  INTEGER NOT NULL,
        total_bytes INTEGER NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_disk_samples_ts ON disk_samples (ts)",
]


def init_db() -> None:
    conn = get_conn()
    try:
        for stmt in SCHEMA:
            conn.execute(stmt)
        for stmt in EXTRA_TABLES:
            conn.execute(stmt)
        # idempotent ALTER TABLEs
        for table, col, defn in MIGRATIONS:
            existing = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
        # Append-only enforcement at the storage layer for the audit log:
        # UPDATE and DELETE on audit_log are rejected by the DB engine itself,
        # so even a renegade code path can't mutate history. RAISE(ABORT, ...)
        # bubbles up as a sqlite3.IntegrityError to the caller.
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only — UPDATE rejected');
            END
            """
        )
        conn.execute(
            """
            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only — DELETE rejected');
            END
            """
        )
    finally:
        conn.close()


# ── Settings convenience ────────────────────────────────────────────────────

def get_setting(key: str, default: str | None = None) -> str | None:
    conn = get_conn()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def set_setting(key: str, value: str) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, now),
        )
    finally:
        conn.close()
