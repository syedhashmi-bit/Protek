"""
connection.py — edit the CrowdSec + MikroTik connection from the browser.

Roadmap #2. The connection settings stay in `.env` — the project rule is that
secrets live there and nowhere else — but Settings → Connection & sync can now
write them, test them first, and apply them without a restart.

    current()            what this worker is using now (secrets: set / not set)
    validate(form, cur)  form → (values, errors); blank secret = keep current
    probe(values)        test the LAPI and the MikroTik with these values
    save(values)         atomic write of the keys into .env, then apply here
    sync_from_file(who)  cheap per-request / per-tick check: if .env changed,
                         reload the browser-saved keys into os.environ

Why a sync step at all: gunicorn runs 2–3 workers, each with its own
os.environ, and only one of them owns the poller. A save lands in one worker;
the others notice that .env's mtime changed (one stat() per request) and
reload. Only keys saved from the browser (`connection.saved_keys`) are forced
from the file — on Docker the host-side env_file and compose `environment:`
would otherwise win over /data/.env forever, and keys nobody edited here keep
whatever the deployment set.

Never logs, flashes or audits a value (CLAUDE.md: never read .env; audit_log
rows are permanent).
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("protek.connection")

ROOT = Path(__file__).resolve().parent

LAPI_KEYS = ("CROWDSEC_LAPI_URL", "CROWDSEC_BOUNCER_KEY")
MT_KEYS = ("MT_HOST", "MT_PORT", "MT_USE_SSL", "MT_USERNAME", "MT_PASSWORD")
KEYS = LAPI_KEYS + MT_KEYS
SECRET_KEYS = {"CROWDSEC_BOUNCER_KEY", "MT_PASSWORD"}

SAVED_KEYS_SETTING = "connection.saved_keys"

_lock = threading.Lock()
_seen_mtime: dict[str, int] = {}     # consumer ("web", "poller") → last mtime_ns seen


def env_file() -> Path:
    """Same resolution as app.ENV_FILE, read per call so tests can repoint it."""
    return Path(os.environ.get("PROTEK_ENV_FILE") or ROOT / ".env")


def writable() -> tuple[bool, str]:
    """Can this process rewrite .env? (A read-only package layout can't.)"""
    p = env_file()
    target = p if p.exists() else p.parent
    if not os.access(target, os.W_OK) or not os.access(p.parent, os.W_OK):
        return False, f"Protek can't write {p}. Edit it by hand and restart Protek."
    return True, ""


def _env(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def current() -> dict[str, Any]:
    """What this worker uses now. Secrets are reported as set/unset only."""
    port = _env("MT_PORT") or "8728"
    return {
        "lapi_url": _env("CROWDSEC_LAPI_URL") or "http://127.0.0.1:8080",
        "lapi_key_set": bool(_env("CROWDSEC_BOUNCER_KEY")),
        "mt_host": _env("MT_HOST"),
        "mt_port": port,
        "mt_use_ssl": _env("MT_USE_SSL").lower() in ("1", "true", "yes"),
        "mt_username": _env("MT_USERNAME"),
        "mt_password_set": bool(os.environ.get("MT_PASSWORD")),
    }


# ── validation ─────────────────────────────────────────────────────────────

_HOST_RE = re.compile(r"^[A-Za-z0-9.:\-\[\]]+$")


def _bad_chars(v: str) -> bool:
    """Characters a .env value can't safely hold. Any non-printable one —
    newline, CR, NUL, Unicode line/paragraph separators — would inject or
    truncate lines (splitlines() splits on U+2028; os.environ rejects NUL).
    A single quote would end the quoting, and a backslash is read literally
    by systemd's EnvironmentFile= but as an escape by python-dotenv, so the
    workers and the service would disagree about the password."""
    return any(c in ("'", "\\") or not c.isprintable() for c in v)


def validate(form, cur: dict[str, Any] | None = None) -> tuple[dict[str, str], list[str]]:
    """Form fields → .env values. Secrets left blank keep their current value.

    Clearing the MikroTik host (and username) turns the .env router off; the
    password is then cleared too.
    """
    errors: list[str] = []
    get = lambda k: (form.get(k) or "").strip()  # noqa: E731

    url = get("lapi_url").rstrip("/")
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.netloc:
        errors.append("CrowdSec LAPI URL must look like http://host:8080.")
    elif "#" in url or _bad_chars(url):
        errors.append("CrowdSec LAPI URL can't contain #, quotes, backslashes or control characters.")

    key = form.get("lapi_key") or ""
    if key and (_bad_chars(key) or "#" in key or " " in key.strip()):
        errors.append("The bouncer key can't contain spaces, #, quotes, backslashes or control characters.")
    key = key.strip() or os.environ.get("CROWDSEC_BOUNCER_KEY", "")
    if not key:
        errors.append("A bouncer key is required (create one with: cscli bouncers add protek).")

    host = get("mt_host")
    username = get("mt_username")
    use_ssl = (form.get("mt_use_ssl") or "") in ("1", "on", "true", "yes")
    port_raw = get("mt_port") or ("8729" if use_ssl else "8728")
    password = form.get("mt_password") or ""

    if host or username:
        if not host:
            errors.append("Router address is required when a username is set.")
        elif not _HOST_RE.match(host):
            errors.append("Router address should be an IP or hostname.")
        if not username:
            errors.append("Router API username is required.")
        elif _bad_chars(username) or "#" in username or " " in username:
            errors.append("Router username can't contain spaces, #, quotes, backslashes or control characters.")
        if not port_raw.isdigit() or not 1 <= int(port_raw) <= 65535:
            errors.append("Router API port must be a number from 1 to 65535.")
        if password and _bad_chars(password):
            errors.append("Router password can't contain a single quote, a backslash or control characters.")
        password = password or os.environ.get("MT_PASSWORD", "")
        if host and username and not password:
            errors.append("Router API password is required.")
    else:
        password = ""

    values = {
        "CROWDSEC_LAPI_URL": url,
        "CROWDSEC_BOUNCER_KEY": key,
        "MT_HOST": host,
        "MT_PORT": port_raw if (host or username) else (port_raw or "8728"),
        "MT_USE_SSL": "true" if use_ssl else "false",
        "MT_USERNAME": username,
        "MT_PASSWORD": password,
    }
    return values, errors


def changed_keys(values: dict[str, str]) -> list[str]:
    return [k for k in KEYS if values.get(k, "") != (os.environ.get(k) or "").strip()]


# ── probes ─────────────────────────────────────────────────────────────────

def probe_lapi(url: str, key: str, timeout: float = 5.0) -> dict[str, Any]:
    """One authenticated GET. Deliberately not LAPIClient.health(): that shares
    the poller's rate-limit bucket, so repeated tests could fail spuriously."""
    import requests
    try:
        r = requests.get(f"{url.rstrip('/')}/v1/decisions", params={"limit": 1},
                         headers={"X-Api-Key": key, "User-Agent": "protek-settings-test"},
                         timeout=timeout)
    except requests.RequestException as e:
        return {"ok": False, "error": f"couldn't reach {url}: {type(e).__name__}"}
    if r.status_code in (401, 403):
        return {"ok": False, "error": "the LAPI rejected the bouncer key"}
    if r.status_code != 200:
        return {"ok": False, "error": f"the LAPI answered HTTP {r.status_code}"}
    return {"ok": True}


def probe_mikrotik(values: dict[str, str], timeout: float = 15.0) -> dict[str, Any]:
    """MikroTik.health() with explicit values, bounded by a timeout — the
    RouterOS client has no connect timeout of its own, and a dead host would
    otherwise hold a gunicorn worker."""
    if not values.get("MT_HOST"):
        return {"ok": True, "skipped": True}
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _Timeout

    from mikrotik import MikroTik
    mt = MikroTik(host=values["MT_HOST"], username=values["MT_USERNAME"],
                  password=values["MT_PASSWORD"], port=int(values["MT_PORT"]),
                  use_ssl=values["MT_USE_SSL"] == "true")
    pool = ThreadPoolExecutor(max_workers=1)
    try:
        h = pool.submit(mt.health).result(timeout=timeout)
    except _Timeout:
        return {"ok": False, "error": f"no answer from the router within {int(timeout)}s"}
    finally:
        pool.shutdown(wait=False)
    if h.get("ok"):
        return {"ok": True, "name": h.get("name"), "version": h.get("version")}
    return {"ok": False, "error": str(h.get("error") or "login failed")[:200]}


def probe(values: dict[str, str]) -> dict[str, dict[str, Any]]:
    return {"lapi": probe_lapi(values["CROWDSEC_LAPI_URL"], values["CROWDSEC_BOUNCER_KEY"]),
            "mikrotik": probe_mikrotik(values)}


# ── write + apply ──────────────────────────────────────────────────────────

_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")


def _quote(v: str) -> str:
    # Single quotes: read literally by systemd EnvironmentFile=, python-dotenv
    # and Compose env_file ('#', '$', spaces safe). validate() rejects "'".
    return f"'{v}'"


def write_env(values: dict[str, str]) -> None:
    """Replace or append each key in .env, keeping every other line. Atomic:
    temp file in the same directory, 0600, then os.replace."""
    os.replace(_prepare_env(values), env_file())


def _prepare_env(values: dict[str, str]) -> str:
    """Build the new .env in a temp file next to it (0600) and return its
    path; the caller os.replace()s it in, or unlinks it."""
    p = env_file()
    lines = [ln.rstrip("\r") for ln in p.read_text().split("\n")] if p.exists() else []
    if lines and lines[-1] == "":
        lines.pop()
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        m = _LINE_RE.match(line)
        if m and m.group(1) in values:
            k = m.group(1)
            if k in seen:
                continue                       # drop duplicate definitions
            out.append(f"{k}={_quote(values[k])}")
            seen.add(k)
        else:
            out.append(line)
    for k, v in values.items():
        if k not in seen:
            out.append(f"{k}={_quote(v)}")
    fd, tmp = tempfile.mkstemp(prefix=".env.", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(out) + "\n")
        os.chmod(tmp, 0o600)
        return tmp
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _saved_keys() -> list[str]:
    from db import get_setting
    try:
        keys = json.loads(get_setting(SAVED_KEYS_SETTING) or "[]")
        return [k for k in keys if k in KEYS]
    except (TypeError, ValueError):
        return []


def save(values: dict[str, str]) -> None:
    """Save the connection keys in `values` — pass only the ones that changed:
    each becomes browser-owned (see the module docstring), and on Docker a
    browser-owned key wins over the deployment's own env from then on.

    Order matters. Other workers react to .env's mtime, so the file is swapped
    in LAST, once saved_keys, this worker's env and the `local` source row are
    final — a worker that sees the new file always sees the new state too.
    """
    from db import set_setting
    if not values:
        return
    tmp = _prepare_env(values)
    try:
        with _lock:
            keys = sorted(set(_saved_keys()) | set(values))
            set_setting(SAVED_KEYS_SETTING, json.dumps(keys))
            for k, v in values.items():
                os.environ[k] = v
        if any(k in LAPI_KEYS for k in values):
            reseed_local_source()
        os.replace(tmp, env_file())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def reseed_local_source() -> None:
    """The poller reads the local LAPI from the `sources` table, not env; a
    stale backoff from the old URL would also keep the new one untried."""
    import federation
    federation.seed_local_source()
    try:
        from db import get_conn
        conn = get_conn()
        try:
            conn.execute("UPDATE sources SET backoff_until = NULL, last_error = '' "
                         "WHERE name = 'local'")
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001
        log.warning("couldn't clear local source backoff: %s", e)


_applied: dict[str, dict[str, str]] = {}   # consumer → saved-key values it last acted on


def sync_from_file(consumer: str) -> bool:
    """Reload browser-saved keys from .env into os.environ when the file has
    changed since this consumer last looked. Returns True when the values
    this consumer acts on changed (so it should drop connection state).

    One stat() per call when nothing changed. Each consumer (the request
    path, the poller) tracks its own view, so both react to one save even
    when they share a process — including the worker that did the save,
    whose os.environ is already current. A consumer's first call only takes
    a baseline (it has no older state to drop).
    """
    p = env_file()
    try:
        mtime = p.stat().st_mtime_ns
    except OSError:
        return False
    if _seen_mtime.get(consumer) == mtime:
        return False
    _seen_mtime[consumer] = mtime
    keys = _saved_keys()
    if not keys:
        # Still a baseline: the first browser save after this must register
        # as a change, not as this consumer's first look.
        _applied.setdefault(consumer, {})
        return False
    from dotenv import dotenv_values
    try:
        file_vals = dotenv_values(p)
    except Exception as e:  # noqa: BLE001
        log.warning("couldn't re-read %s: %s", p.name, e)
        return False
    snap = {k: file_vals[k] for k in keys if file_vals.get(k) is not None}
    with _lock:
        for k, v in list(snap.items()):
            if os.environ.get(k) != v:
                try:
                    os.environ[k] = v
                except ValueError:            # e.g. NUL — can't be in env
                    log.warning("ignoring unusable %s in %s", k, p.name)
                    snap.pop(k)
    first = consumer not in _applied
    changed = _applied.get(consumer) != snap
    _applied[consumer] = snap
    return changed and not first
