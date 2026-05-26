"""
Protek — Flask app entrypoint (phases 0–2).

What's wired here:
- DB init + WAL
- LAPI poller thread (phase 1): pulls decisions every SYNC_INTERVAL_SEC
- MikroTik adapter (phase 2): read-only address-list view + health
- Login + TOTP + rate limiting + IP whitelist + audit (phase 1)
- Pages: /, /login, /logout, /decisions, /alerts, /mikrotik
- APIs:  /api/health, /api/decisions, /api/alerts, /api/sync/status,
         /api/mt/health, /api/crowdsec/health

Phase 3+ adds reconcile.py + mikrotik writes; phase 6 hardens settings/audit.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

# Import after env is loaded so module-level os.environ.get() reads pick it up.
import auth  # noqa: E402
from auth import (client_ip, ip_allowed, is_locked, login_required,
                  record_audit, record_failure, clear_failures, touch_session,
                  verify_password, verify_totp_for, record_user_login,
                  role_required, has_role, seed_env_user,
                  list_users, add_user, set_user_disabled, set_user_role,
                  delete_user)  # noqa: E402
from crowdsec import LAPIClient  # noqa: E402
from db import get_conn, get_setting, init_db, set_setting  # noqa: E402
import federation  # noqa: E402
from geo import GeoWorker, geo_for_ip, points_for_map  # noqa: E402
import intel  # noqa: E402
from mikrotik import MikroTik, address_list_name  # noqa: E402
from poller import Poller  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
)
log = logging.getLogger("protek.app")

# ── Flask ───────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY") or "dev-secret-CHANGE-ME"
if app.secret_key == "dev-secret-CHANGE-ME":
    log.warning("SECRET_KEY missing — running with insecure dev key.")

_session_cookie_domain = (os.environ.get("SESSION_COOKIE_DOMAIN") or "").strip() or None

app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_INSECURE", "0") != "1",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_DOMAIN=_session_cookie_domain,  # phase 74 — set to e.g. ".syedhashmi.trade" to share session with othoni
    WTF_CSRF_TIME_LIMIT=7200,
    WTF_CSRF_SSL_STRICT=False,
)
csrf = CSRFProtect(app)
# By default flask-wtf only protects POST/PUT/PATCH/DELETE — our GET API
# endpoints are unaffected. The only state-changing API call we expose is
# /api/sync/run (POST); the fetch() in mikrotik.html sends the X-CSRFToken
# header so it passes the check.

# CSRF protection is for browser-form POSTs. The JSON API endpoints below
# are session-authenticated and called from our own pages — but a CSRF token
# is still required for state-changing POSTs (like /api/sync/run). The fetch()
# in the dashboard reads the token from the meta tag in base.html.


@app.errorhandler(CSRFError)
def _csrf_error(e):
    if request.path.startswith("/api/") or request.is_json:
        return jsonify(error="csrf", reason=e.description), 400
    flash(f"Security check failed ({e.description}). Reload and try again.", "error")
    return redirect(url_for("dashboard"))


@app.context_processor
def _inject_csrf():
    return {"csrf_token": generate_csrf}


# ── Boot: DB + Poller ───────────────────────────────────────────────────────

PROTEK_VERSION = "2.0.0"

init_db()
seed_env_user()  # idempotent: mirror APP_USERNAME/APP_PASSWORD_HASH/TOTP_SECRET into users row #1

# /api/v1/* (phase 47) — bearer-token-authed REST surface. CSRF-exempt because
# token auth replaces CSRF for this surface.
from api_v1 import bp as _api_v1_bp  # noqa: E402
csrf.exempt(_api_v1_bp)
app.register_blueprint(_api_v1_bp)

# /api/v2/* (phase 79) — versioned surface for breaking-change isolation.
# In 2.0 v2 transparently aliases every v1 route; future v2-only changes
# fork from here without disturbing v1 clients.
import api_v2  # noqa: E402
api_v2.register(app, csrf)


@app.route("/api/version")
def api_version():
    """Tells clients which API versions this Protek speaks + any deprecations."""
    sunset = get_setting("api.v1.sunset_date") or ""
    return jsonify(
        protek_version=PROTEK_VERSION,
        supported_versions=["v1", "v2"],
        default_version="v1",
        v1_sunset=sunset or None,
        notes=("v2 currently aliases v1 transparently. Use v2 for new "
               "clients; v1 stays available through the deprecation window."),
    )


# Expose has_role() to all templates so they can hide affordances by role.
@app.context_processor
def _inject_role_helpers():
    return {"has_role": has_role, "current_role": lambda: session.get("role", "viewer")}


@app.before_request
def _upgrade_legacy_session():
    """Sessions created before multi-admin landed have `logged_in=True` and
    `username` but no `role` or `user_id`. Re-attach those from the users
    table so the RBAC gates don't silently treat them as viewers.

    Runs cheaply — only does a DB lookup when role is missing AND we're
    logged in, then never again until the next login."""
    if not session.get("logged_in"):
        return
    if "role" in session and "user_id" in session:
        return
    uname = session.get("username", "")
    if not uname:
        return
    try:
        from auth import get_user
        u = get_user(uname)
    except Exception:  # noqa: BLE001
        u = None
    if u:
        session["user_id"] = u["id"]
        session["role"] = u["role"]
    else:
        # Username doesn't resolve any more — force re-login.
        session.clear()

def _envstr(name: str, default: str = "") -> str:
    """Read env var, tolerating inline-comment trailing whitespace."""
    raw = os.environ.get(name, default)
    if raw is None:
        return ""
    # python-dotenv leaves the value including any trailing comment if there's
    # no quoting; strip "  # ..." suffixes manually.
    raw = raw.split("#", 1)[0].strip()
    return raw


def _audit(action: str, *, target: str = "", before=None, after=None, note: str = "") -> None:
    """Thin wrapper that auto-fills actor + IP from request/session."""
    try:
        import audit as _a
        _a.record(
            action,
            actor=session.get("username", "") if session else "",
            ip=request.remote_addr or "" if request else "",
            target=target,
            before=before,
            after=after,
            note=note,
        )
    except Exception:  # noqa: BLE001
        pass


def _envint(name: str, default: int) -> int:
    v = _envstr(name, "")
    try:
        return int(v) if v else default
    except ValueError:
        return default


LAPI_URL = _envstr("CROWDSEC_LAPI_URL", "http://127.0.0.1:8080")
LAPI_KEY = _envstr("CROWDSEC_BOUNCER_KEY", "")
SYNC_INTERVAL = max(2, _envint("SYNC_INTERVAL_SEC", 10))
BATCH_CAP = max(1, _envint("BATCH_CAP", 200))
DRY_RUN = _envstr("DRY_RUN", "true").lower() in ("1", "true", "yes")

# Seed local source row from .env so federation has a starting point.
federation.seed_local_source()

# Legacy single-client handle — kept for the /crowdsec explorer and health checks.
# The poller iterates federation.list_sources() instead.
lapi_client = LAPIClient(LAPI_URL, LAPI_KEY, name="local") if LAPI_KEY else None
poller: Poller | None = None

# Only one worker should run the background poller. We elect a single owner via
# a non-blocking flock on a sentinel file. The other gunicorn workers serve
# HTTP but skip starting their own poller — they read the same DB.
import fcntl  # noqa: E402

_POLLER_LOCK_PATH = ROOT / ".poller.lock"
_poller_lock_fd: int | None = None

def _try_acquire_poller_lock() -> bool:
    global _poller_lock_fd
    try:
        fd = os.open(str(_POLLER_LOCK_PATH), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        return False
    _poller_lock_fd = fd
    os.write(fd, f"{os.getpid()}\n".encode())
    return True


geo_worker: GeoWorker | None = None
GEO_TTL_DAYS = max(1, _envint("GEO_CACHE_TTL_DAYS", 7))

intel_worker: intel.IntelWorker | None = None

if _try_acquire_poller_lock():
    poller = Poller(interval_sec=SYNC_INTERVAL, dry_run=DRY_RUN, batch_cap=BATCH_CAP)
    poller.start()
    geo_worker = GeoWorker(ttl_days=GEO_TTL_DAYS, interval_sec=30)
    geo_worker.start()
    intel_worker = intel.IntelWorker(interval_sec=60, per_cycle=20)
    intel_worker.start()
    # SIEM worker — shares the singleton election so we don't end up with
    # three queues across the three gunicorn workers (only one ever ships).
    import siem as _siem
    _siem.get_siem()
    log.info("poller + geo + intel + siem started (owner pid=%s, interval=%ss, dry_run=%s)",
             os.getpid(), SYNC_INTERVAL, DRY_RUN)
else:
    log.info("poller already owned by another worker — skipping in pid=%s", os.getpid())


@app.context_processor
def _inject_globals():
    return {
        "active": "",
        "dry_run": DRY_RUN,
    }


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if app.config.get("SESSION_COOKIE_SECURE"):
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return resp


# ── Helpers ─────────────────────────────────────────────────────────────────

SCENARIO_FAMILIES = [
    (re.compile(r"http", re.I), "http"),
    (re.compile(r"ssh", re.I), "ssh"),
    (re.compile(r"^lists?:", re.I), "list"),
    (re.compile(r"^crowdsecurity/", re.I), "cs"),
]


def scenario_fam(scenario: str | None) -> str:
    if not scenario:
        return ""
    for rx, fam in SCENARIO_FAMILIES:
        if rx.search(scenario):
            return fam
    return "cust"


def rel_time(iso_str: str | None) -> str:
    if not iso_str:
        return "—"
    try:
        # Allow both timezone-aware ISO and naive Z suffix.
        ts = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except ValueError:
        return iso_str[:19]
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - ts
    s = int(delta.total_seconds())
    if s < 0:
        # future timestamp — print absolute remaining
        s = -s
        unit = (("h", 3600), ("m", 60), ("s", 1))
        for u, n in unit:
            if s >= n:
                return f"in {s // n}{u}"
        return "now"
    if s < 60: return f"{s}s ago"
    if s < 3600: return f"{s // 60}m ago"
    if s < 86400: return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


def has_machine_credentials() -> bool:
    """True when both CROWDSEC_MACHINE_LOGIN + CROWDSEC_MACHINE_PASSWORD are
    set in the environment. Gates the alerts mirror in the poller and the
    "machine credential required" notice on the /alerts page."""
    return bool(_envstr("CROWDSEC_MACHINE_LOGIN", "")) and bool(
        _envstr("CROWDSEC_MACHINE_PASSWORD", "")
    )


def poller_status() -> dict[str, object]:
    """Read poller state from the settings table (works across workers)."""
    return {
        "last_at": get_setting("poller.last_at"),
        "last_ok": (get_setting("poller.last_ok") or "0") == "1",
        "last_error": get_setting("poller.last_error") or "",
        "cycles": int(get_setting("poller.cycles") or "0"),
        "interval_sec": int(get_setting("poller.interval") or str(SYNC_INTERVAL)),
        "active_total": int(get_setting("poller.active_total") or "0"),
    }


def reconcile_status() -> dict[str, object]:
    return {
        "last_at": get_setting("reconcile.last_at"),
        "last_at_rel": rel_time(get_setting("reconcile.last_at")),
        "duration_ms": int(get_setting("reconcile.last_duration_ms") or "0"),
        "to_add": int(get_setting("reconcile.last_to_add") or "0"),
        "to_remove": int(get_setting("reconcile.last_to_remove") or "0"),
        "unchanged": int(get_setting("reconcile.last_unchanged") or "0"),
        "errors": int(get_setting("reconcile.last_errors") or "0"),
        "dry_run": (get_setting("reconcile.last_dry_run") or "1") == "1",
        "notes": get_setting("reconcile.last_notes") or "",
    }


# ── Routes: auth ────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = client_ip()
    if not ip_allowed(ip):
        return render_template("blocked.html", ip=ip), 403

    locked, lockout_mins = is_locked(ip)
    error = None

    if request.method == "POST":
        if locked:
            error = f"Too many failures. Try again in {lockout_mins} minutes."
        else:
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            code = (request.form.get("totp") or "").strip()
            user = verify_password(username, password)
            if not user:
                record_failure(ip)
                record_audit(ip, username, False, "bad credentials")
                error = "Invalid credentials."
            elif not verify_totp_for(user, code):
                record_failure(ip)
                record_audit(ip, username, False, "bad TOTP")
                error = "Invalid TOTP code."
            else:
                clear_failures(ip)
                record_audit(ip, username, True)
                record_user_login(user["id"])
                try:
                    import siem as _siem
                    _siem.ship("auth.success", {"ip": ip, "actor": username, "role": user["role"]})
                except Exception:  # noqa: BLE001
                    pass
                session.clear()
                session["logged_in"] = True
                session["username"] = username
                session["user_id"] = user["id"]
                session["role"] = user["role"]
                touch_session()
                return redirect(request.args.get("next") or url_for("dashboard"))
            locked, lockout_mins = is_locked(ip)

    return render_template("login.html", error=error, locked=locked, lockout_mins=lockout_mins,
                            sso_configured=_oidc.is_configured(),
                            username=request.form.get("username", ""))


# ── OIDC / SSO (phase 70) ─────────────────────────────────────────────────

import oidc as _oidc  # noqa: E402
_oauth = _oidc.init_oauth(app)

# ── Threat intel publishing (phase 78) ────────────────────────────────────

@app.route("/feed/banned-ips.signed.json")
@csrf.exempt
def intel_feed_signed():
    """Public signed feed. Anonymous, but rate-limited per `subscriber` query."""
    import intel_publish, ratelimit
    if not intel_publish.is_enabled():
        return jsonify(error="intel publishing not enabled on this instance"), 404
    sub = (request.args.get("subscriber") or "anonymous")[:80]
    bucket_name = f"feed.{sub}"
    if not ratelimit.acquire(bucket_name):
        return jsonify(error="rate limited", retry_after=60), 429
    feed = intel_publish.signed_feed()
    try:
        import siem as _siem
        _siem.ship("intel.feed.served",
                   {"subscriber": sub, "count": feed.get("body", {}).get("count", 0)},
                   severity=6)
    except Exception:  # noqa: BLE001
        pass
    return jsonify(feed)


@app.route("/feed/pubkey")
@csrf.exempt
def intel_feed_pubkey():
    """Public — anyone subscribing to the feed needs the pub key to verify
    signatures. Distribute it out-of-band ideally; this endpoint is the
    convenience path."""
    import intel_publish
    s = intel_publish.status()
    if not s["pub_key_b64"]:
        return jsonify(error="not initialized"), 404
    return jsonify(
        algorithm="ed25519",
        public_key_b64=s["pub_key_b64"],
        fingerprint=s["fingerprint"],
        issuer=s["issuer"],
    )


@app.route("/intel-publish")
@login_required
@role_required("admin")
def intel_publish_page():
    import intel_publish
    return render_template("intel_publish.html",
                           active="intel_publish",
                           status=intel_publish.status())


@app.route("/intel-publish/toggle", methods=["POST"])
@login_required
@role_required("admin")
def intel_publish_toggle():
    enabled = "1" if request.form.get("enabled") == "1" else "0"
    set_setting("intel.publish.enabled", enabled)
    if enabled == "1":
        import intel_publish
        intel_publish._ensure_keypair()
    _audit("intel.publish.toggle", after={"enabled": enabled})
    flash(f"Intel publishing {'enabled' if enabled == '1' else 'disabled'}.", "info")
    return redirect(url_for("intel_publish_page"))


@app.route("/intel-publish/rotate", methods=["POST"])
@login_required
@role_required("admin")
def intel_publish_rotate():
    import intel_publish
    new_pub = intel_publish.rotate_keypair()
    _audit("intel.publish.rotate",
           note=f"new fingerprint: {hashlib.sha256(base64.b64decode(new_pub)).hexdigest()[:16]}"
                if new_pub else "rotated")
    flash("Signing key rotated. Subscribers must fetch the new public key.", "info")
    return redirect(url_for("intel_publish_page"))


@app.route("/intel-publish/save", methods=["POST"])
@login_required
@role_required("admin")
def intel_publish_save():
    issuer = (request.form.get("issuer") or "protek").strip()[:80]
    scenarios = (request.form.get("scenarios") or "").strip()
    excludes = (request.form.get("exclude_origins") or "lists:").strip()
    set_setting("intel.publish.issuer", issuer)
    set_setting("intel.publish.scenarios", scenarios)
    set_setting("intel.publish.exclude_origins", excludes)
    _audit("intel.publish.config", after={"issuer": issuer,
                                          "scenarios": scenarios,
                                          "excludes": excludes})
    flash("Intel publishing config saved.", "info")
    return redirect(url_for("intel_publish_page"))


# ── Protek peer aggregation (phase 76) ────────────────────────────────────

@app.route("/peers")
@login_required
def peers_page():
    import peers as _peers
    return render_template("peers.html",
                           active="peers",
                           kpis=_peers.aggregated_kpis())


@app.route("/peers/add", methods=["POST"])
@login_required
@role_required("admin")
def peers_add():
    import peers as _peers
    name = (request.form.get("name") or "").strip()
    url = (request.form.get("url") or "").strip()
    token = (request.form.get("token") or "").strip()
    if not (name and url and token):
        flash("name, url, and token are all required.", "error")
        return redirect(url_for("peers_page"))
    try:
        pid = _peers.add_peer(name, url, token)
        _audit("peer.add", target=name, after={"url": url})
        flash(f"Peer {name} added (id={pid}). Refresh will pick it up within 60s.", "info")
    except Exception as e:  # noqa: BLE001
        flash(f"Add failed: {e}", "error")
    return redirect(url_for("peers_page"))


@app.route("/peers/toggle/<int:pid>", methods=["POST"])
@login_required
@role_required("admin")
def peers_toggle(pid: int):
    import peers as _peers
    enabled = request.form.get("enabled") == "1"
    _peers.toggle_peer(pid, enabled)
    _audit("peer.toggle", target=str(pid), after={"enabled": enabled})
    return redirect(url_for("peers_page"))


@app.route("/peers/delete/<int:pid>", methods=["POST"])
@login_required
@role_required("admin")
def peers_delete(pid: int):
    import peers as _peers
    _peers.delete_peer(pid)
    _audit("peer.delete", target=str(pid))
    flash("Peer removed.", "info")
    return redirect(url_for("peers_page"))


@app.route("/peers/refresh", methods=["POST"])
@login_required
@role_required("operator")
def peers_refresh():
    import peers as _peers
    out = _peers.refresh_all()
    flash(f"Refreshed {out['refreshed']} peer(s), {out['failed']} failed.", "info")
    return redirect(url_for("peers_page"))


# ── Othoni cross-app drilldown (phase 74) ─────────────────────────────────

@app.route("/from-othoni")
def from_othoni():
    """Othoni's tile click lands here with `?ctx=<one of: dashboard, ip, scenario>`
    and (optionally) a value. We route to the right Protek view, preserving
    the shared session set via SESSION_COOKIE_DOMAIN.

    Examples:
      /from-othoni                          → /
      /from-othoni?ctx=ip&v=1.2.3.4         → /attackers/1.2.3.4
      /from-othoni?ctx=scenario&v=ssh-bf    → /scenarios?q=ssh-bf
      /from-othoni?ctx=alerts               → /alerts
      /from-othoni?ctx=bouncers             → /bouncers
    """
    if not session.get("logged_in"):
        # Shared SESSION_COOKIE_DOMAIN means if user is signed into othoni
        # on a sibling subdomain they're already logged in here. If not, fall
        # through to local login which preserves the next= param.
        return redirect(url_for("login", next=request.full_path))
    ctx = (request.args.get("ctx") or "").strip().lower()
    v = (request.args.get("v") or "").strip()
    if ctx == "ip" and v and re.match(r"^[0-9a-fA-F.:/]+$", v):
        return redirect(url_for("attacker_page", ip=v))
    if ctx == "scenario" and v:
        return redirect(url_for("scenarios_page", q=v))
    if ctx == "alerts":
        return redirect(url_for("alerts_page"))
    if ctx == "bouncers":
        return redirect(url_for("bouncers_page"))
    if ctx == "perf":
        return redirect(url_for("perf_page"))
    return redirect(url_for("dashboard"))


# ── GraphQL surface (phase 73) ────────────────────────────────────────────
try:
    import graphql_api  # noqa: E402
    graphql_api.register(app, csrf)
    log.info("graphql: /api/graphql + /api/graphql/explorer registered")
except Exception as e:  # noqa: BLE001
    log.warning("graphql registration skipped: %s", e)


@app.route("/honeypot")
@login_required
def honeypot_page():
    """Phase 85 — honeypot knob page. All knobs live in the settings
    table (not .env) so we can read AND write from the UI."""
    import honeypot as hp
    cfg = {
        "enabled":         hp.is_enabled(),
        "url":             get_setting("honeypot.url") or "",
        "min_reputation":  int(get_setting("honeypot.min_reputation") or 80),
        "max_targets":     int(get_setting("honeypot.max_targets") or 1000),
        "target_count":    len(hp.list_targets(limit=10000)),
    }
    targets = hp.list_targets(limit=200) if cfg["enabled"] else []
    return render_template(
        "honeypot.html",
        cfg=cfg,
        targets=targets,
        flash_msg=session.pop("honeypot_flash", None),
        active="honeypot",
    )


@app.route("/honeypot/save", methods=["POST"])
@login_required
@role_required("operator")
def honeypot_save():
    enabled = "enabled" in request.form
    url = (request.form.get("url") or "").strip()
    try:
        min_rep = max(0, min(100, int(request.form.get("min_reputation") or 80)))
    except ValueError:
        min_rep = 80
    try:
        max_t = max(0, int(request.form.get("max_targets") or 1000))
    except ValueError:
        max_t = 1000
    set_setting("honeypot.enabled", "1" if enabled else "0")
    set_setting("honeypot.url", url)
    set_setting("honeypot.min_reputation", str(min_rep))
    set_setting("honeypot.max_targets", str(max_t))
    _audit("honeypot.save", target="settings",
           after={"enabled": enabled, "min_reputation": min_rep,
                  "max_targets": max_t, "url_set": bool(url)})
    session["honeypot_flash"] = "Saved. Next poller cycle picks up the new knobs."
    return redirect(url_for("honeypot_page"))


@app.route("/honeypot/refresh", methods=["POST"])
@login_required
@role_required("operator")
def honeypot_refresh():
    import honeypot as hp
    try:
        result = hp.refresh_targets()
        session["honeypot_flash"] = (
            f"Refreshed: {result.get('tagged', 0)} tagged, "
            f"{result.get('cleared', 0)} cleared."
        )
    except Exception as e:  # noqa: BLE001
        session["honeypot_flash"] = f"Refresh failed: {e}"
    return redirect(url_for("honeypot_page"))


@app.route("/admin/sso")
@login_required
@role_required("admin")
def admin_sso():
    """Phase 85 — read-only SSO config display + Test login button.
    Config values themselves stay in .env (security: never expose the
    client_secret in a form). The Test button (admin_sso_test) opens
    the full OIDC dance and reports the claims/role back to this page."""
    callback_url = url_for("sso_callback", _external=True)
    return render_template(
        "admin_sso.html",
        status=_oidc.status(),
        callback_url=callback_url,
        test_result=session.pop("sso_test_result", None),
        active="admin_sso",
    )


@app.route("/admin/sso/test")
@login_required
@role_required("admin")
def admin_sso_test():
    """Trigger an OIDC login flow but capture the result instead of
    granting the session. Marks the session with `sso_test_mode=True`
    so the callback knows to render the result on /admin/sso rather
    than performing a real login."""
    if not _oidc.is_configured() or _oauth is None:
        flash("OIDC not configured — set OIDC_ISSUER / CLIENT_ID / CLIENT_SECRET in .env first.", "error")
        return redirect(url_for("admin_sso"))
    session["sso_test_mode"] = True
    redirect_uri = url_for("sso_callback", _external=True)
    return _oauth.oidc.authorize_redirect(redirect_uri)


@app.route("/sso/login")
def sso_login():
    if not _oidc.is_configured() or _oauth is None:
        return jsonify(error="SSO not configured"), 503
    redirect_uri = url_for("sso_callback", _external=True)
    return _oauth.oidc.authorize_redirect(redirect_uri)


@app.route("/sso/callback")
def sso_callback():
    if not _oidc.is_configured() or _oauth is None:
        return jsonify(error="SSO not configured"), 503
    ip = client_ip()
    # Phase 85 — if this callback is for a Test login (initiated via
    # /admin/sso/test by an already-logged-in admin), capture the
    # result in the session and redirect back to /admin/sso instead of
    # establishing a real SSO session.
    test_mode = bool(session.pop("sso_test_mode", False))
    try:
        token = _oauth.oidc.authorize_access_token()
    except Exception as e:  # noqa: BLE001
        log.warning("OIDC token exchange failed: %s", e)
        record_audit(ip, "(sso)", False, "OIDC token exchange failed")
        if test_mode:
            session["sso_test_result"] = {"ok": False, "error": f"token exchange failed: {e!s}"[:300]}
            return redirect(url_for("admin_sso"))
        flash("SSO login failed: " + str(e)[:200], "error")
        return redirect(url_for("login"))

    # userinfo claims come either embedded or via userinfo endpoint
    claims = token.get("userinfo") or {}
    if not claims:
        try:
            claims = _oauth.oidc.userinfo(token=token) or {}
        except Exception as e:  # noqa: BLE001
            log.warning("OIDC userinfo fetch failed: %s", e)

    email = (claims.get("email") or "").lower().strip()
    if not email:
        record_audit(ip, "(sso)", False, "OIDC missing email claim")
        if test_mode:
            session["sso_test_result"] = {"ok": False, "error": "provider returned no email claim"}
            return redirect(url_for("admin_sso"))
        flash("SSO failed: provider returned no email.", "error")
        return redirect(url_for("login"))

    role = _oidc.role_for_claims(claims)
    if test_mode:
        # In test mode we never establish a session, even on success — just
        # report the resolved role + raw claims back so the admin can verify
        # their group-mapping config without actually logging in as that user.
        groups_claim = _oidc._envstr("OIDC_GROUPS_CLAIM") or "groups"
        groups = claims.get(groups_claim) or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        session["sso_test_result"] = {
            "ok": True,
            "claims": {
                "sub":             claims.get("sub", ""),
                "email":           email,
                "email_verified":  bool(claims.get("email_verified")),
                "name":            claims.get("name", ""),
                "hd":              claims.get("hd", ""),
            },
            "groups": groups,
            "role":   role,  # may be None — that's a real rejection signal
        }
        return redirect(url_for("admin_sso"))

    if role is None:
        record_audit(ip, email, False, "OIDC role mapping denied")
        try:
            import siem as _siem
            _siem.ship("auth.sso_denied",
                       {"ip": ip, "email": email, "reason": "role-deny"},
                       severity=4)
        except Exception:  # noqa: BLE001
            pass
        flash("SSO denied — your account isn't authorized for this Protek instance.", "error")
        return redirect(url_for("login"))

    try:
        user = _oidc.upsert_sso_user(email, role, claims.get("sub", ""))
    except PermissionError:
        record_audit(ip, email, False, "OIDC user disabled")
        flash("Your Protek account is disabled.", "error")
        return redirect(url_for("login"))

    record_audit(ip, email, True, "sso")
    try:
        import siem as _siem
        _siem.ship("auth.sso_success",
                   {"ip": ip, "actor": email, "role": role}, severity=6)
    except Exception:  # noqa: BLE001
        pass
    session.clear()
    session["logged_in"] = True
    session["username"]  = email
    session["user_id"]   = user["id"]
    session["role"]      = role
    session["auth_source"] = "sso"
    touch_session()
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Signed out.", "info")
    return redirect(url_for("login"))


# ── Routes: pages ───────────────────────────────────────────────────────────

@app.route("/")
@login_required
def dashboard():
    conn = get_conn()
    try:
        active_total = conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()[0]
        sources = conn.execute(
            "SELECT COUNT(DISTINCT origin_source) FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()[0] or 1
        scen_24h = conn.execute(
            "SELECT COUNT(DISTINCT scenario) FROM decisions "
            "WHERE last_seen_at > datetime('now','-1 day')"
        ).fetchone()[0]
        attk_24h = conn.execute(
            "SELECT COUNT(DISTINCT value) FROM decisions "
            "WHERE last_seen_at > datetime('now','-1 day')"
        ).fetchone()[0]
        top_row = conn.execute(
            """
            SELECT scenario, COUNT(*) AS n FROM decisions
            WHERE deleted_at IS NULL AND scenario != ''
            GROUP BY scenario ORDER BY n DESC LIMIT 1
            """
        ).fetchone()
        top_scen = top_row["scenario"] if top_row else ""
        top_count = top_row["n"] if top_row else 0

        recent_rows = conn.execute(
            """
            SELECT d.value, d.scope, d.scenario, d.origin, d.duration, d.first_seen_at,
                   g.country_code AS country
            FROM decisions d
            LEFT JOIN geo_cache g ON g.ip = d.value
            WHERE d.deleted_at IS NULL
            ORDER BY d.id DESC LIMIT 20
            """
        ).fetchall()
        last_sync_row = conn.execute("SELECT id FROM sync_events ORDER BY id DESC LIMIT 1").fetchone()
        top_scen_rows = conn.execute(
            """
            SELECT scenario, COUNT(*) AS n FROM decisions
            WHERE deleted_at IS NULL AND scenario != ''
            GROUP BY scenario ORDER BY n DESC LIMIT 10
            """
        ).fetchall()
    finally:
        conn.close()

    recent = [
        {
            "key": f"{r['value']}|{r['scenario']}|{r['first_seen_at']}",
            "value": r["value"],
            "scope": r["scope"],
            "scenario": r["scenario"],
            "origin": r["origin"],
            "duration": r["duration"],
            "country": r["country"] or "",
            "first_seen_rel": rel_time(r["first_seen_at"]),
            "fam": scenario_fam(r["scenario"]),
        }
        for r in recent_rows
    ]
    top_scenarios = [
        {"scenario": r["scenario"], "n": r["n"], "fam": scenario_fam(r["scenario"])}
        for r in top_scen_rows
    ]

    mt_list_size = _cached_mt_count()
    rs = reconcile_status()

    kpis = {
        "lapi_active": active_total,
        "lapi_sources": sources,
        "mt_list_size": mt_list_size if mt_list_size is not None else "—",
        "mt_list_name": address_list_name(),
        "last_poll_rel": rel_time(poller_status()["last_at"]) if lapi_client else "—",
        "cycles": poller_status()["cycles"] if lapi_client else 0,
        "recon_duration": rs["duration_ms"],
        "scenarios_24h": scen_24h,
        "attackers_24h": attk_24h,
        "top_scenario": top_scen,
        "top_scenario_count": top_count,
        "last_sync_event_id": last_sync_row["id"] if last_sync_row else 0,
    }
    return render_template("dashboard.html", kpis=kpis, recent=recent, top_scenarios=top_scenarios, active="dashboard")


@app.route("/decisions")
@login_required
def decisions_page():
    q = (request.args.get("q") or "").strip()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    per_page = 50
    conn = get_conn()
    try:
        where = ["deleted_at IS NULL"]
        params: list = []
        if q:
            where.append("(value LIKE ? OR scenario LIKE ? OR origin LIKE ?)")
            qq = f"%{q}%"
            params.extend([qq, qq, qq])
        where_sql = " AND ".join(where)
        total = conn.execute(f"SELECT COUNT(*) FROM decisions WHERE {where_sql}", params).fetchone()[0]
        rows = conn.execute(
            f"""SELECT value, scope, scenario, origin, origin_source, duration, until, first_seen_at
                FROM decisions WHERE {where_sql}
                ORDER BY id DESC LIMIT ? OFFSET ?""",
            params + [per_page, (page - 1) * per_page],
        ).fetchall()
    finally:
        conn.close()

    pages = max(1, (total + per_page - 1) // per_page)
    rows = [
        {
            "value": r["value"],
            "scope": r["scope"],
            "scenario": r["scenario"],
            "origin": r["origin"],
            "origin_source": r["origin_source"],
            "duration": r["duration"],
            "first_seen_rel": rel_time(r["first_seen_at"]),
            "until_rel": rel_time(r["until"]) if r["until"] else None,
            "fam": scenario_fam(r["scenario"]),
        }
        for r in rows
    ]
    return render_template("decisions.html", rows=rows, total=total, page=page, pages=pages, q=q, active="decisions")


@app.route("/alerts")
@login_required
def alerts_page():
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT created_at, source_ip, source_country, source_asn, scenario, events_count "
            "FROM alerts ORDER BY id DESC LIMIT 100"
        ).fetchall()
    finally:
        conn.close()
    out = [
        {
            "created_rel": rel_time(r["created_at"]),
            "source_ip": r["source_ip"],
            "source_country": r["source_country"],
            "source_asn": r["source_asn"],
            "scenario": r["scenario"],
            "events_count": r["events_count"],
            "fam": scenario_fam(r["scenario"]),
        }
        for r in rows
    ]
    return render_template("alerts.html", rows=out, has_machine_creds=has_machine_credentials(), active="alerts")


@app.route("/scenarios")
@login_required
def scenarios_page():
    conn = get_conn()
    try:
        top_rows = conn.execute(
            """
            SELECT scenario, COUNT(*) AS n, COUNT(DISTINCT value) AS unique_ips
            FROM decisions
            WHERE last_seen_at > datetime('now', '-1 day') AND scenario != ''
            GROUP BY scenario
            ORDER BY n DESC LIMIT 20
            """
        ).fetchall()
        heat_rows = conn.execute(
            """
            SELECT scenario,
                   CAST(strftime('%H', last_seen_at) AS INTEGER) AS hr,
                   COUNT(*) AS n
            FROM decisions
            WHERE last_seen_at > datetime('now', '-7 days') AND scenario != ''
            GROUP BY scenario, hr
            """
        ).fetchall()
    finally:
        conn.close()

    max_n = max((r["n"] for r in top_rows), default=1)
    top = [
        {"scenario": r["scenario"], "n": r["n"], "unique_ips": r["unique_ips"],
         "fam": scenario_fam(r["scenario"]), "pct": int(100 * r["n"] / max_n)}
        for r in top_rows
    ]
    total_count = sum(r["n"] for r in top_rows)
    unique_count = len(top_rows)
    top_family = ""
    if top:
        fam_counts: dict[str, int] = {}
        for r in top:
            fam_counts[r["fam"]] = fam_counts.get(r["fam"], 0) + r["n"]
        top_family = max(fam_counts, key=lambda k: fam_counts[k])

    # Heat rows: scenario × 24 cells
    scen_cells: dict[str, list[int]] = {}
    for r in heat_rows:
        scen_cells.setdefault(r["scenario"], [0] * 24)[r["hr"]] = r["n"]
    grand_max = max((max(cells) for cells in scen_cells.values()), default=1)
    heat: list[dict] = []
    # Sort by total fires desc, cap to top 25 rows so the grid stays scannable.
    sorted_scen = sorted(scen_cells.items(), key=lambda kv: -sum(kv[1]))[:25]
    for scenario, cells in sorted_scen:
        levels = []
        for v in cells:
            if v == 0:
                levels.append(0)
            else:
                # 1..6 bucketing
                lvl = min(6, max(1, int(round(v / grand_max * 6))))
                levels.append(lvl)
        heat.append({"scenario": scenario, "cells": cells, "levels": levels})

    return render_template("scenarios.html",
                           top=top,
                           heat_rows=heat,
                           total_count=total_count,
                           unique_count=unique_count,
                           top_family=top_family,
                           active="scenarios")


@app.route("/mikrotik")
@login_required
def mikrotik_page():
    mt = MikroTik()
    health = mt.health()
    list_name = address_list_name()

    list_total = 0
    owned_entries: list[dict] = []
    foreign_total = 0
    if health.get("ok"):
        try:
            entries = mt.get_address_list(list_name)
            list_total = len(entries)
            owned = [e for e in entries if (e.get("comment") or "").startswith("protek:")]
            foreign_total = list_total - len(owned)
            owned_entries = [
                {
                    "address": e.get("address", ""),
                    "comment": e.get("comment", ""),
                    "disabled": e.get("disabled", "false"),
                    "creation_time": e.get("creation-time"),
                }
                for e in owned[:200]
            ]
        except Exception as e:  # noqa: BLE001
            health["ok"] = False
            health["error"] = str(e)

    conn = get_conn()
    try:
        lapi_active = conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()[0]
    finally:
        conn.close()

    # Phase-3+ diff comes from the reconciler (cached in settings rows).
    recon = reconcile_status()
    owned_total = len(owned_entries)
    to_add = recon["to_add"] if recon["last_at"] else max(0, lapi_active - owned_total)
    to_remove = recon["to_remove"] if recon["last_at"] else 0

    # Initial-sync banner: shown when MT is live, list is far behind LAPI, and
    # there's still meaningful headroom to catch up.
    initial_sync = bool(health.get("ok")) and lapi_active > 500 and owned_total < lapi_active * 0.95
    initial_pct = 0
    initial_eta = "—"
    if initial_sync and lapi_active:
        initial_pct = max(0, min(100, int(owned_total * 100 / lapi_active)))
        # ETA = remaining_adds / batch_cap * interval
        remaining = max(0, lapi_active - owned_total)
        cycles_remaining = (remaining + BATCH_CAP - 1) // BATCH_CAP
        eta_sec = cycles_remaining * SYNC_INTERVAL
        if eta_sec >= 3600:
            initial_eta = f"~{eta_sec // 3600}h{(eta_sec % 3600) // 60}m"
        elif eta_sec >= 60:
            initial_eta = f"~{eta_sec // 60}m"
        else:
            initial_eta = f"~{eta_sec}s"

    # Recent sync events for the history table.
    conn2 = get_conn()
    try:
        ev_rows = conn2.execute(
            "SELECT id, started_at, duration_ms, added, removed, unchanged, errors, source, dry_run, notes "
            "FROM sync_events ORDER BY id DESC LIMIT 20"
        ).fetchall()
    finally:
        conn2.close()
    events = [
        {
            "id": r["id"],
            "started_rel": rel_time(r["started_at"]),
            "duration_ms": r["duration_ms"] or 0,
            "added": r["added"],
            "removed": r["removed"],
            "unchanged": r["unchanged"],
            "errors": r["errors"],
            "source": r["source"],
            "dry_run": bool(r["dry_run"]),
            "notes": r["notes"] or "",
        }
        for r in ev_rows
    ]

    return render_template(
        "mikrotik.html",
        mt=health,
        list_name=list_name,
        list_total=list_total,
        owned_total=owned_total,
        owned_entries=owned_entries,
        foreign_total=foreign_total,
        lapi_active=lapi_active,
        to_add=to_add,
        to_remove=to_remove,
        recon=recon,
        events=events,
        initial_sync=initial_sync,
        initial_pct=initial_pct,
        initial_eta=initial_eta,
        batch_cap=BATCH_CAP,
        active="mikrotik",
    )


# ── Routes: APIs ────────────────────────────────────────────────────────────

@app.route("/health")
def health_public():
    """Liveness probe. Returns 503 when LAPI poll is stale, MT is down, or
    the reconciler hasn't run in 3x its interval. nginx upstream checks rely
    on this; never include sensitive details in the body."""
    ps = poller_status()
    rs = reconcile_status()
    issues: list[str] = []
    interval = ps["interval_sec"] or SYNC_INTERVAL
    # Staleness budget = 3x interval, but a long-running reconcile (initial
    # sync of a community blocklist can take tens of seconds on a busy
    # router) legitimately delays the next poll. So expand the budget to
    # cover at least 2x the most recent reconcile duration, capped at 10
    # minutes so a wedged poller still trips the alarm.
    last_reconcile_ms = rs.get("duration_ms") or 0
    stale_budget_sec = min(600, max(3 * interval, int(2 * last_reconcile_ms / 1000) + interval))
    if not lapi_client:
        issues.append("poller_disabled")
    elif not ps["last_at"]:
        issues.append("poller_not_started")
    else:
        try:
            last_dt = datetime.fromisoformat(ps["last_at"].replace("Z", "+00:00"))
            if (datetime.now(timezone.utc) - last_dt).total_seconds() > stale_budget_sec:
                issues.append("poll_stale")
        except Exception:  # noqa: BLE001
            issues.append("poll_unparseable")
    if not ps["last_ok"]:
        issues.append("lapi_degraded")
    # MT only degrades when configured + last reconcile reports problems with it
    mt = MikroTik()
    if mt.is_configured() and not _mt_quick_ok():
        issues.append("mt_unreachable")
    code = 503 if issues else 200
    return jsonify(
        status="degraded" if issues else "ok",
        phase=6,
        service="protek",
        issues=issues,
        dry_run=DRY_RUN,
    ), code


@app.route("/metrics")
def metrics_export():
    """Prometheus scrape endpoint.

    Auth: bearer token in `Authorization: Bearer <METRICS_TOKEN>` when the
    env var is set. When unset, only localhost may scrape (the typical
    "Prometheus on the same box" deployment). CSRF doesn't apply (GET).
    """
    import metrics as _metrics
    token_expected = _envstr("METRICS_TOKEN", "")
    if token_expected:
        auth = request.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and auth[7:] == token_expected):
            return ("forbidden\n", 403, {"Content-Type": "text/plain; charset=utf-8"})
    else:
        # No token configured — restrict to localhost (Prometheus on same box).
        client_ip = request.headers.get("X-Real-IP") or request.remote_addr or ""
        if client_ip not in ("127.0.0.1", "::1", "localhost"):
            return ("forbidden: set METRICS_TOKEN to scrape from off-box\n",
                    403, {"Content-Type": "text/plain; charset=utf-8"})
    body = _metrics.render()
    return (body, 200, {"Content-Type": "text/plain; version=0.0.4; charset=utf-8"})


@app.route("/api/siem/status")
@login_required
def api_siem_status():
    import siem as _siem
    conn = get_conn()
    try:
        total = conn.execute("SELECT COUNT(*) AS n FROM siem_journal").fetchone()["n"]
        shipped = conn.execute(
            "SELECT COUNT(*) AS n FROM siem_journal WHERE shipped_at IS NOT NULL"
        ).fetchone()["n"]
        last = conn.execute(
            "SELECT created_at, event_type, severity, shipped_at, ship_error "
            "FROM siem_journal ORDER BY id DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()
    return jsonify(
        queue=_siem.get_siem().stats(),
        journal_total=total,
        journal_shipped=shipped,
        recent=[dict(r) for r in last],
        forwarders={
            "syslog": bool(_envstr("SYSLOG_HOST", "")),
            "webhook": bool(_envstr("SIEM_WEBHOOK_URL", "")),
        },
    )


@app.route("/api/siem/replay", methods=["POST"])
@login_required
@role_required("operator")
def api_siem_replay():
    import siem as _siem
    try:
        n = int(request.form.get("n") or request.json.get("n") if request.is_json else request.form.get("n", "100"))
    except (TypeError, ValueError):
        n = 100
    n = max(1, min(10000, n))
    count = _siem.get_siem().replay(n)
    import audit as _audit
    _audit.record("siem.replay", actor=session.get("username", ""),
                  ip=request.remote_addr or "",
                  target=f"n={n}", note=f"replayed {count} events")
    return jsonify(replayed=count)


@app.route("/siem")
@login_required
def siem_page():
    import siem as _siem
    conn = get_conn()
    try:
        recent = conn.execute(
            "SELECT created_at, event_type, severity, shipped_at, ship_error, payload_json "
            "FROM siem_journal ORDER BY id DESC LIMIT 200"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS n FROM siem_journal").fetchone()["n"]
        shipped = conn.execute(
            "SELECT COUNT(*) AS n FROM siem_journal WHERE shipped_at IS NOT NULL"
        ).fetchone()["n"]
    finally:
        conn.close()
    return render_template(
        "siem.html",
        recent=[dict(r) for r in recent],
        total=total,
        shipped=shipped,
        forwarders={
            "syslog": _envstr("SYSLOG_HOST", ""),
            "syslog_port": _envint("SYSLOG_PORT", 514),
            "syslog_proto": _envstr("SYSLOG_PROTO", "udp"),
            "webhook": _envstr("SIEM_WEBHOOK_URL", ""),
        },
        stats=_siem.get_siem().stats(),
        active="siem",
    )


@app.route("/alerts/rules")
@login_required
def alerts_rules_page():
    import alerting
    states = alerting.tick()  # always show the freshest evaluation
    silences = alerting.list_silences(include_expired=False)
    # Per-rule channel overrides (phase 56)
    for r in states:
        r["channels_override"] = get_setting(f"alerting.rule.{r['rule_key']}.channels") or ""
    return render_template(
        "alerts_rules.html",
        rules=states,
        silences=silences,
        active="alerts_rules",
    )


@app.route("/alerts/rules/channels", methods=["POST"])
@login_required
@role_required("operator")
def alerts_rules_channels():
    rule_key = (request.form.get("rule_key") or "").strip()
    channels = (request.form.get("channels") or "").strip()  # "" clears the override
    if not rule_key:
        flash("rule_key required", "error")
        return redirect(url_for("alerts_rules_page"))
    if channels:
        # Validate against known channels (and 'all' shortcut)
        valid = {"discord", "telegram", "email"}
        chs = [c.strip() for c in channels.split(",") if c.strip()]
        bad = [c for c in chs if c not in valid]
        if bad:
            flash(f"unknown channel(s): {', '.join(bad)}. Valid: {', '.join(sorted(valid))}", "error")
            return redirect(url_for("alerts_rules_page"))
    set_setting(f"alerting.rule.{rule_key}.channels", channels)
    _audit("alert.channels", target=rule_key, after={"channels": channels or "(default)"})
    flash(f"channels for '{rule_key}' set to: {channels or 'default'}", "info")
    return redirect(url_for("alerts_rules_page"))


@app.route("/alerts/silence/add", methods=["POST"])
@login_required
@role_required("operator")
def alerts_silence_add():
    import alerting
    pattern = (request.form.get("pattern") or "").strip()
    duration_min = max(1, min(43200, int(request.form.get("duration_min", "60"))))
    reason = (request.form.get("reason") or "").strip()
    if not pattern:
        flash("pattern required", "error")
        return redirect(url_for("alerts_rules_page"))
    until = (datetime.now(timezone.utc) + timedelta(minutes=duration_min)).isoformat()
    sid = alerting.add_silence(pattern, until, reason, session.get("username", ""))
    _audit("alert.silence.add", target=pattern,
           after={"pattern": pattern, "until": until, "reason": reason},
           note=f"silence id={sid}")
    flash(f"silenced '{pattern}' for {duration_min} minutes", "info")
    return redirect(url_for("alerts_rules_page"))


@app.route("/alerts/silence/delete/<int:sid>", methods=["POST"])
@login_required
@role_required("operator")
def alerts_silence_delete(sid: int):
    import alerting
    alerting.remove_silence(sid)
    _audit("alert.silence.delete", target=str(sid))
    flash("silence removed", "info")
    return redirect(url_for("alerts_rules_page"))


@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users_page():
    return render_template("admin_users.html",
                           users=list_users(),
                           active="admin_users")


@app.route("/admin/users/add", methods=["POST"])
@login_required
@role_required("admin")
def admin_users_add():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role = (request.form.get("role") or "viewer").strip()
    try:
        result = add_user(username, password, role)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin_users_page"))
    _audit("user.add", target=username,
           after={"username": username, "role": role})
    # Stash the one-time TOTP secret + URI in the session for the next render
    # (NOT in flash — flash messages can be retrieved by re-rendering, and
    # this is a one-shot secret we don't want lingering).
    session["_pending_user_secret"] = {
        "username": result["username"], "totp_secret": result["totp_secret"],
        "totp_uri": result["totp_uri"], "role": result["role"],
    }
    flash(f"User '{username}' created. TOTP secret shown below — capture now.", "info")
    return redirect(url_for("admin_users_page"))


@app.route("/admin/users/role/<int:uid>", methods=["POST"])
@login_required
@role_required("admin")
def admin_users_role(uid: int):
    new_role = (request.form.get("role") or "").strip()
    try:
        set_user_role(uid, new_role)
        _audit("user.role", target=str(uid), after={"role": new_role})
        flash(f"role set to {new_role}", "info")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("admin_users_page"))


@app.route("/admin/users/toggle/<int:uid>", methods=["POST"])
@login_required
@role_required("admin")
def admin_users_toggle(uid: int):
    disable = request.form.get("disable", "0") == "1"
    try:
        set_user_disabled(uid, disable)
        _audit("user.disable" if disable else "user.enable", target=str(uid))
        flash("updated", "info")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("admin_users_page"))


@app.route("/admin/users/delete/<int:uid>", methods=["POST"])
@login_required
@role_required("admin")
def admin_users_delete(uid: int):
    try:
        delete_user(uid)
        _audit("user.delete", target=str(uid))
        flash("user removed", "info")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("admin_users_page"))


@app.route("/admin/backup")
@login_required
@role_required("admin")
def admin_backup_page():
    return render_template("admin_backup.html",
                           last_import=session.pop("_last_import_summary", None),
                           active="admin_backup")


@app.route("/admin/backup/export", methods=["POST"])
@login_required
@role_required("admin")
def admin_backup_export():
    import bundle as _bundle
    passphrase = request.form.get("passphrase") or ""
    try:
        blob = _bundle.export_bundle(passphrase)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin_backup_page"))
    _audit("backup.export", note=f"{len(blob)} bytes")
    from flask import Response
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        blob,
        mimetype="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="protek-backup-{stamp}.bin"'},
    )


@app.route("/admin/backup/import", methods=["POST"])
@login_required
@role_required("admin")
def admin_backup_import():
    import bundle as _bundle
    f = request.files.get("file")
    passphrase = request.form.get("passphrase") or ""
    overwrite = request.form.get("overwrite", "0") == "1"
    if not f:
        flash("file required", "error")
        return redirect(url_for("admin_backup_page"))
    blob = f.read()
    try:
        summary = _bundle.import_bundle(blob, passphrase, overwrite=overwrite)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin_backup_page"))
    _audit("backup.import",
           note=f"overwrite={overwrite} summary={summary['summary']}")
    session["_last_import_summary"] = summary
    flash(f"Import applied ({'overwrite' if overwrite else 'additive'} mode).", "info")
    return redirect(url_for("admin_backup_page"))


@app.route("/admin/backup-automation")
@login_required
@role_required("admin")
def admin_backup_automation_page():
    import backup as _bk
    import litestream as _ls
    return render_template(
        "admin_backup_automation.html",
        active="admin_backup_auto",
        status=_bk.status(),
        runs=_bk.list_runs(30),
        litestream=_ls.status(),
    )


@app.route("/admin/backup-automation/settings", methods=["POST"])
@login_required
@role_required("admin")
def admin_backup_automation_settings():
    enabled = "1" if request.form.get("enabled") == "1" else "0"
    backend = (request.form.get("backend") or "local").strip().lower()
    if backend not in ("local", "s3"):
        backend = "local"
    local_path = (request.form.get("local_path") or "").strip()
    daily_keep = (request.form.get("daily_keep") or "30").strip()
    monthly_keep = (request.form.get("monthly_keep") or "12").strip()
    before = {
        "enabled": get_setting("backup.enabled") or "0",
        "backend": get_setting("backup.backend") or "local",
        "local_path": get_setting("backup.local_path") or "",
        "daily_keep": get_setting("backup.daily_keep") or "30",
        "monthly_keep": get_setting("backup.monthly_keep") or "12",
    }
    set_setting("backup.enabled", enabled)
    set_setting("backup.backend", backend)
    if local_path:
        set_setting("backup.local_path", local_path)
    try:
        set_setting("backup.daily_keep", str(max(1, min(365, int(daily_keep)))))
        set_setting("backup.monthly_keep", str(max(1, min(120, int(monthly_keep)))))
    except ValueError:
        pass
    _audit("backup.config", before=before, after={
        "enabled": enabled, "backend": backend, "local_path": local_path,
        "daily_keep": daily_keep, "monthly_keep": monthly_keep,
    })
    flash("Backup automation settings saved.", "info")
    return redirect(url_for("admin_backup_automation_page"))


@app.route("/admin/backup-automation/run", methods=["POST"])
@login_required
@role_required("admin")
def admin_backup_automation_run():
    import backup as _bk
    kind = (request.form.get("kind") or "manual").strip().lower()
    if kind not in ("manual", "daily", "monthly"):
        kind = "manual"
    row = _bk.run_backup(kind)
    if row.get("status") == "ok":
        flash(f"Backup ok — {row.get('size_bytes', 0):,} bytes → {row.get('dest', '')}", "info")
    else:
        flash(f"Backup failed: {row.get('error', 'unknown')}", "error")
    _audit("backup.run_manual", note=f"kind={kind} status={row.get('status')}")
    return redirect(url_for("admin_backup_automation_page"))


@app.route("/admin/backup-automation/test", methods=["POST"])
@login_required
@role_required("admin")
def admin_backup_automation_test():
    import backup as _bk
    row = _bk.restore_test()
    if row.get("status") == "ok":
        flash(f"Restore-test ok — verified {row.get('dest', '')}", "info")
    else:
        flash(f"Restore-test failed: {row.get('error', 'unknown')}", "error")
    _audit("backup.restore_test_manual", note=f"status={row.get('status')}")
    return redirect(url_for("admin_backup_automation_page"))


@app.route("/admin/dr-drill")
@login_required
@role_required("admin")
def admin_dr_drill_page():
    # Recent drill rows = audit entries with action='dr.drill.completed'
    conn = get_conn()
    try:
        drills = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_log WHERE action = 'dr.drill.completed' "
            "ORDER BY id DESC LIMIT 12"
        ).fetchall()]
    finally:
        conn.close()
    return render_template("admin_dr_drill.html",
                           active="dr_drill",
                           drills=drills)


@app.route("/admin/dr-drill/complete", methods=["POST"])
@login_required
@role_required("admin")
def admin_dr_drill_complete():
    import json as _json
    checks = {
        "restore_to_scratch": request.form.get("restore_to_scratch") == "1",
        "restore_test_ok":    request.form.get("restore_test_ok") == "1",
        "synthetic_passed":   request.form.get("synthetic_passed") == "1",
        "litestream_restore": request.form.get("litestream_restore") == "1",
        "notifications_tested": request.form.get("notifications_tested") == "1",
        "mt_replacement":     request.form.get("mt_replacement") == "1",
    }
    note = (request.form.get("note") or "").strip()[:500]
    pass_rate = sum(1 for v in checks.values() if v)
    _audit("dr.drill.completed",
           note=f"{pass_rate}/6 passed",
           after={"checks": checks, "note": note})
    flash(f"Drill recorded — {pass_rate}/6 checks passed.", "info")
    return redirect(url_for("admin_dr_drill_page"))


@app.route("/synthetic")
@login_required
def synthetic_page():
    import synthetic
    return render_template(
        "synthetic.html",
        active="synthetic",
        status=synthetic.status(),
        runs=synthetic.list_runs(30),
    )


@app.route("/synthetic/run", methods=["POST"])
@login_required
@role_required("operator")
def synthetic_run():
    import synthetic
    row = synthetic.run_test()
    flash(f"Synthetic test {row['status']} — {row.get('ok_n', 0)}/{row.get('targets_n', 0)} bouncers ok.",
          "info" if row["status"] == "ok" else "error")
    _audit("synthetic.run_manual",
           note=f"status={row['status']} ok={row.get('ok_n')} of {row.get('targets_n')}")
    return redirect(url_for("synthetic_page"))


@app.route("/synthetic/toggle", methods=["POST"])
@login_required
@role_required("admin")
def synthetic_toggle():
    enabled = "1" if request.form.get("enabled") == "1" else "0"
    set_setting("synthetic.enabled", enabled)
    _audit("synthetic.toggle", after={"enabled": enabled})
    flash(f"Synthetic self-test {'enabled' if enabled == '1' else 'disabled'}.", "info")
    return redirect(url_for("synthetic_page"))


@app.route("/admin/tokens")
@login_required
@role_required("admin")
def admin_tokens_page():
    import api_tokens as at
    tokens = at.list_tokens()
    # Pull one-time-display token from session if just created
    new_token = session.pop("_just_created_token", None)
    return render_template("admin_tokens.html",
                           tokens=tokens, new_token=new_token,
                           active="admin_tokens")


@app.route("/admin/tokens/add", methods=["POST"])
@login_required
@role_required("admin")
def admin_tokens_add():
    import api_tokens as at
    name = (request.form.get("name") or "").strip()
    scopes = (request.form.get("scopes") or "read").strip()
    expires = (request.form.get("expires_at") or "").strip() or None
    try:
        result = at.create_token(name, scopes, created_by=session.get("username", ""),
                                  expires_at=expires)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("admin_tokens_page"))
    _audit("token.create", target=name, after={"scopes": scopes, "expires_at": expires})
    session["_just_created_token"] = result
    flash(f"Token '{name}' created. Captured below — won't be shown again.", "info")
    return redirect(url_for("admin_tokens_page"))


@app.route("/admin/tokens/revoke/<int:tid>", methods=["POST"])
@login_required
@role_required("admin")
def admin_tokens_revoke(tid: int):
    import api_tokens as at
    at.revoke_token(tid)
    _audit("token.revoke", target=str(tid))
    flash("token revoked", "info")
    return redirect(url_for("admin_tokens_page"))


@app.route("/admin/tokens/delete/<int:tid>", methods=["POST"])
@login_required
@role_required("admin")
def admin_tokens_delete(tid: int):
    import api_tokens as at
    at.delete_token(tid)
    _audit("token.delete", target=str(tid))
    flash("token deleted", "info")
    return redirect(url_for("admin_tokens_page"))


# ── Webhooks out (phase 45) ─────────────────────────────────────────────────

@app.route("/webhooks")
@login_required
def webhooks_page():
    import webhooks_out as wo
    return render_template(
        "webhooks.html",
        subs=wo.list_subs(),
        dlq=wo.list_dlq(limit=50),
        new_sub=session.pop("_just_created_sub", None),
        active="webhooks",
    )


@app.route("/webhooks/add", methods=["POST"])
@login_required
@role_required("operator")
def webhooks_add():
    import webhooks_out as wo
    name = (request.form.get("name") or "").strip()
    url = (request.form.get("url") or "").strip()
    event_mask = (request.form.get("event_mask") or "*").strip()
    try:
        result = wo.add_sub(name, url, event_mask)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("webhooks_page"))
    _audit("webhook.add", target=name, after={"url": url, "event_mask": event_mask})
    session["_just_created_sub"] = result
    flash(f"Webhook '{name}' created. HMAC secret shown below — capture now.", "info")
    return redirect(url_for("webhooks_page"))


@app.route("/webhooks/toggle/<int:sid>", methods=["POST"])
@login_required
@role_required("operator")
def webhooks_toggle(sid: int):
    import webhooks_out as wo
    enabled = request.form.get("enabled", "1") == "1"
    wo.toggle_sub(sid, enabled)
    _audit("webhook.toggle", target=str(sid), after={"enabled": enabled})
    flash("updated", "info")
    return redirect(url_for("webhooks_page"))


@app.route("/webhooks/delete/<int:sid>", methods=["POST"])
@login_required
@role_required("operator")
def webhooks_delete(sid: int):
    import webhooks_out as wo
    wo.delete_sub(sid)
    _audit("webhook.delete", target=str(sid))
    flash("removed", "info")
    return redirect(url_for("webhooks_page"))


@app.route("/webhooks/dlq/replay/<int:eid>", methods=["POST"])
@login_required
@role_required("operator")
def webhooks_dlq_replay(eid: int):
    import webhooks_out as wo
    result = wo.replay_dlq(eid)
    _audit("webhook.replay", target=str(eid), note=str(result))
    if result.get("ok"):
        flash("delivered", "info")
    else:
        flash(f"failed: {result.get('error')}", "error")
    return redirect(url_for("webhooks_page"))


# ── External API (phase 46) — webhook inputs ────────────────────────────────

@app.route("/api/external/decisions", methods=["POST"])
@csrf.exempt
def api_external_decisions():
    """Accept ban requests from external systems (atom, custom scripts, etc.).

    Auth: API token with `write` scope. Decisions enter the same pipeline as
    CrowdSec-sourced ones, attributed `origin_source = external:<token_name>`.

    Body shape (JSON):
        {"ip": "1.2.3.4", "scope": "Ip", "scenario": "...", "duration": "4h",
         "reason": "...", "queue": false}
    """
    import api_tokens as at
    raw = ""
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        raw = auth_hdr[7:].strip()
    elif request.headers.get("X-Protek-Token"):
        raw = request.headers.get("X-Protek-Token", "").strip()
    tok = at.lookup(raw) if raw else None
    if not tok:
        return jsonify(error="unauthorized"), 401
    if not at.has_scope(tok, "write"):
        return jsonify(error="insufficient_scope", required="write"), 403

    data = request.get_json(silent=True) or {}
    ip_val = (data.get("ip") or data.get("value") or "").strip()
    if not ip_val:
        return jsonify(error="ip required"), 400
    scope = (data.get("scope") or "Ip").strip()
    scenario = (data.get("scenario") or "external/manual").strip()
    duration = (data.get("duration") or "4h").strip()
    reason = (data.get("reason") or "").strip()
    queue = bool(data.get("queue", False))

    # Go-style duration parse — accept "4h", "30m", "1h30m".
    def _parse_duration(s: str) -> int:
        import re as _re
        total = 0
        for amount, unit in _re.findall(r"(\d+)([hms])", s):
            n = int(amount)
            if unit == "h": total += n * 3600
            elif unit == "m": total += n * 60
            else: total += n
        return total or 14400
    until_dt = datetime.now(timezone.utc) + timedelta(seconds=_parse_duration(duration))
    until = until_dt.isoformat()
    now = datetime.now(timezone.utc).isoformat()
    origin_source = f"external:{tok['name']}"

    conn = get_conn()
    try:
        import time as _time
        synthetic_id = int(_time.time() * 1000)
        for _ in range(50):
            if not conn.execute(
                "SELECT 1 FROM decisions WHERE origin_source = ? AND lapi_id = ?",
                (origin_source, synthetic_id),
            ).fetchone():
                break
            synthetic_id += 1

        require_approval = queue or (get_setting("settings.approval_required") == "1")
        if require_approval:
            cur = conn.execute(
                """INSERT INTO approval_queue
                     (ip, scope, scenario, origin, origin_source, decision_id, status, created_at)
                   VALUES (?, ?, ?, ?, ?, NULL, 'pending', ?)""",
                (ip_val, scope, scenario, "external", origin_source, now),
            )
            qid = cur.lastrowid
        else:
            qid = None
            conn.execute(
                """INSERT INTO decisions
                     (origin_source, lapi_id, value, scope, type, scenario, origin,
                      duration, until, first_seen_at, last_seen_at)
                   VALUES (?, ?, ?, ?, 'ban', ?, 'external', ?, ?, ?, ?)""",
                (origin_source, synthetic_id, ip_val, scope, scenario, duration,
                 until, now, now),
            )
    finally:
        conn.close()

    try:
        import siem
        siem.ship("decision.created", {
            "ip": ip_val, "scope": scope, "scenario": scenario,
            "origin": "external", "source": origin_source, "reason": reason,
            "queued": bool(qid),
        })
    except Exception:  # noqa: BLE001
        pass
    try:
        import audit as _audit_mod
        _audit_mod.record(
            "external.ban" + (".queued" if qid else ""),
            actor=f"token:{tok['name']}",
            ip=request.remote_addr or "",
            target=ip_val,
            after={"scope": scope, "scenario": scenario, "duration": duration},
            note=reason,
        )
    except Exception:  # noqa: BLE001
        pass

    return jsonify(
        accepted=True, ip=ip_val, scope=scope, scenario=scenario,
        origin_source=origin_source, until=until,
        queued=bool(qid), approval_queue_id=qid,
    ), 202


@app.route("/api/external/health")
def api_external_health():
    """Public health probe — no auth, no sensitive data."""
    return jsonify(ok=True, service="protek", api="external"), 200


@app.route("/api/external/introspect", methods=["POST"])
@csrf.exempt
def api_external_introspect():
    """Phase 72 — payload-shape inspector for integrators.

    Echoes back what Protek saw (headers, parsed body, the field it would
    use as `ip`) without persisting anything. Lets the operator validate
    their n8n/Zapier/Make template before sending real bans.

    Auth: any valid bearer token (read scope is enough).
    """
    import api_tokens as at
    raw = ""
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        raw = auth_hdr[7:].strip()
    elif request.headers.get("X-Protek-Token"):
        raw = request.headers.get("X-Protek-Token", "").strip()
    tok = at.lookup(raw) if raw else None
    if not tok:
        return jsonify(error="unauthorized",
                       hint="set Authorization: Bearer <token> header"), 401
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(error="body must be JSON object",
                       received_content_type=request.content_type), 400
    # Detect which field Protek would treat as the IP — covers common shapes
    ip = (body.get("ip") or body.get("source_ip") or body.get("client_ip")
          or body.get("remote_addr") or "")
    return jsonify(
        ok=True,
        token_name=tok.get("name"),
        token_scopes=tok.get("scopes"),
        detected_ip=ip,
        detected_scope=body.get("scope") or "Ip",
        detected_duration=body.get("duration") or "4h",
        detected_scenario=body.get("scenario") or "external",
        parsed_keys=sorted(body.keys()),
        headers_seen={k: v for k, v in request.headers.items()
                      if k.lower() in ("content-type", "user-agent",
                                       "x-protek-event", "x-protek-token",
                                       "x-protek-signature", "x-protek-timestamp")},
        note="this is a dry-run — no decision was created. Hit /api/external/decisions to ban for real.",
    )


@app.route("/api/external/honeypot/callback", methods=["POST"])
@csrf.exempt
def api_external_honeypot_callback():
    """Operator's honeypot reports a verified attacker (phase 61).
    Auth: API token with `write` scope. Body: {"ip": "...", "metadata": {...}}.
    Tags the IP as `honeypot-confirmed` and ships a SIEM event."""
    import api_tokens as at
    raw = ""
    auth_hdr = request.headers.get("Authorization", "")
    if auth_hdr.startswith("Bearer "):
        raw = auth_hdr[7:].strip()
    elif request.headers.get("X-Protek-Token"):
        raw = request.headers.get("X-Protek-Token", "").strip()
    tok = at.lookup(raw) if raw else None
    if not tok:
        return jsonify(error="unauthorized"), 401
    if not at.has_scope(tok, "write"):
        return jsonify(error="insufficient_scope", required="write"), 403
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify(error="ip required"), 400
    import honeypot
    honeypot.record_callback(ip, data.get("metadata") or data)
    return jsonify(ok=True, ip=ip, tagged="honeypot-confirmed"), 202


@app.route("/audit")
@login_required
def audit_page():
    import audit as _audit
    q = request.args.get("q", "").strip()
    rows = _audit.recent(limit=300, action_filter=q)
    return render_template("audit.html", rows=rows, q=q, active="audit")


@app.route("/perf")
@login_required
def perf_page():
    import perf
    import slo as _slo
    import ratelimit
    return render_template(
        "perf.html",
        stats=perf.cycle_stats(hours=24),
        slow=perf.slow_cycles(limit=20),
        recent=perf.recent_cycles(limit=60),
        breakdown=perf.stage_breakdown(),
        stages=perf.stage_timings(hours=24),
        slo=_slo.summary(window_hours=24),
        buckets=ratelimit.all_status(),
        active="perf",
    )


@app.route("/api/perf/buckets")
@login_required
def api_perf_buckets():
    import ratelimit
    return jsonify(buckets=ratelimit.all_status())


@app.route("/api/perf/sample")
@login_required
def api_perf_sample():
    """JSON: hourly cycle metrics for the last N hours."""
    import perf
    try:
        hours = max(1, min(168, int(request.args.get("hours", "24"))))
    except (TypeError, ValueError):
        hours = 24
    return jsonify(perf.cycle_stats(hours=hours))


@app.route("/api/slo")
@login_required
def api_slo():
    """JSON: SLO compliance + burn rates over a configurable window."""
    import slo as _slo
    try:
        hours = max(1, min(720, int(request.args.get("hours", "24"))))
    except (TypeError, ValueError):
        hours = 24
    return jsonify(_slo.summary(window_hours=hours))


@app.route("/api/health")
@login_required
def api_health():
    ps = poller_status()
    lapi_state = "ok" if (lapi_client and ps["last_ok"]) else ("warn" if lapi_client else "down")
    sync_state = "ok" if (lapi_client and ps["last_ok"]) else "warn"
    # MT pill: snapshot from cached lookup; OFF when not configured.
    mt = MikroTik()
    if not mt.is_configured():
        mt_state = "warn"
    else:
        mt_state = "ok" if _mt_quick_ok() else "down"
    return jsonify(lapi=lapi_state, mikrotik=mt_state, sync=sync_state)


@app.route("/api/decisions")
@login_required
def api_decisions():
    try:
        limit = max(1, min(500, int(request.args.get("limit", "100"))))
    except ValueError:
        limit = 100
    conn = get_conn()
    try:
        active_total = conn.execute(
            "SELECT COUNT(*) FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()[0]
        rows = conn.execute(
            """
            SELECT d.value, d.scope, d.scenario, d.origin, d.origin_source, d.duration, d.until, d.first_seen_at,
                   g.country_code AS country
            FROM decisions d
            LEFT JOIN geo_cache g ON g.ip = d.value
            WHERE d.deleted_at IS NULL ORDER BY d.id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    items = [
        {
            "value": r["value"],
            "scope": r["scope"],
            "scenario": r["scenario"],
            "origin": r["origin"],
            "origin_source": r["origin_source"],
            "duration": r["duration"],
            "until": r["until"],
            "country": r["country"] or "",
            "first_seen_rel": rel_time(r["first_seen_at"]),
            "fam": scenario_fam(r["scenario"]),
        }
        for r in rows
    ]
    return jsonify(active_total=active_total, items=items)


@app.route("/api/alerts")
@login_required
def api_alerts():
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT created_at, source_ip, source_country, source_asn, scenario, events_count "
            "FROM alerts ORDER BY id DESC LIMIT 100"
        ).fetchall()
    finally:
        conn.close()
    return jsonify(items=[dict(r) for r in rows], has_machine_creds=has_machine_credentials())


@app.route("/api/crowdsec/health")
@login_required
def api_crowdsec_health():
    if not lapi_client:
        return jsonify(ok=False, error="CROWDSEC_BOUNCER_KEY not set"), 503
    return jsonify(lapi_client.health())


@app.route("/api/mt/health")
@login_required
def api_mt_health():
    return jsonify(MikroTik().health())


@app.route("/api/geo/points")
@login_required
def api_geo_points():
    try:
        limit = max(1, min(2000, int(request.args.get("limit", "500"))))
    except ValueError:
        limit = 500
    return jsonify(items=points_for_map(limit=limit))


@app.route("/api/geo/<ip>")
@login_required
def api_geo_ip(ip: str):
    row = geo_for_ip(ip)
    if not row:
        return jsonify(ok=False, ip=ip), 404
    return jsonify(ok=True, **row)


@app.route("/api/scenarios")
@login_required
def api_scenarios():
    """Scenarios firing over a time window — counts + hour-of-day distribution."""
    try:
        hours = max(1, min(24 * 7, int(request.args.get("hours", "24"))))
    except ValueError:
        hours = 24
    conn = get_conn()
    try:
        # Top scenarios in window
        top = conn.execute(
            """
            SELECT scenario, COUNT(*) AS n, COUNT(DISTINCT value) AS unique_ips
            FROM decisions
            WHERE last_seen_at > datetime('now', ?)
              AND scenario != ''
            GROUP BY scenario
            ORDER BY n DESC
            LIMIT 20
            """,
            (f'-{hours} hours',),
        ).fetchall()
        # Heatmap: scenario × hour-of-day (UTC), last 7d
        heat = conn.execute(
            """
            SELECT scenario,
                   CAST(strftime('%H', last_seen_at) AS INTEGER) AS hr,
                   COUNT(*) AS n
            FROM decisions
            WHERE last_seen_at > datetime('now', '-7 days')
              AND scenario != ''
            GROUP BY scenario, hr
            """,
        ).fetchall()
        # Sync activity (24h, 30 buckets)
        sync_buckets = conn.execute(
            """
            SELECT CAST((strftime('%s', started_at) - strftime('%s', 'now', '-24 hours')) / 2880 AS INTEGER) AS bucket,
                   SUM(added) AS adds, SUM(removed) AS rems
            FROM sync_events
            WHERE started_at > datetime('now', '-24 hours')
            GROUP BY bucket
            ORDER BY bucket
            """
        ).fetchall()
    finally:
        conn.close()

    top_list = [{"scenario": r["scenario"], "n": r["n"], "unique_ips": r["unique_ips"]} for r in top]
    heatmap = [{"scenario": r["scenario"], "hr": r["hr"], "n": r["n"]} for r in heat]
    sync = [{"bucket": r["bucket"], "adds": r["adds"] or 0, "rems": r["rems"] or 0} for r in sync_buckets]
    return jsonify(top=top_list, heatmap=heatmap, sync_buckets=sync, hours=hours)


@app.route("/api/sync/status")
@login_required
def api_sync_status():
    """Combined LAPI-poll + reconcile status — read from settings rows so any worker can serve."""
    if not lapi_client:
        return jsonify(ok=False, reason="poller disabled")
    ps = poller_status()
    rs = reconcile_status()
    return jsonify(
        ok=ps["last_ok"],
        last_at=ps["last_at"],
        last_error=ps["last_error"],
        cycles=ps["cycles"],
        interval_sec=ps["interval_sec"],
        active_total=ps["active_total"],
        dry_run=DRY_RUN,
        reconcile=rs,
    )


@app.route("/api/sync/run", methods=["POST"])
@login_required
@role_required("operator")
def api_sync_run():
    """Trigger a single immediate reconcile cycle. Runs synchronously and
    returns the same shape api_sync_status does. Respects DRY_RUN."""
    from reconciler import run_once
    result = run_once(source="manual", dry_run=DRY_RUN, batch_cap=BATCH_CAP)
    return jsonify(result)


@app.route("/api/sync/events")
@login_required
def api_sync_events():
    """Recent reconcile cycles for the sync-history table."""
    try:
        limit = max(1, min(200, int(request.args.get("limit", "50"))))
    except ValueError:
        limit = 50
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id, started_at, duration_ms, added, removed, unchanged, errors, source, dry_run, notes "
            "FROM sync_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "started_at": r["started_at"],
            "started_rel": rel_time(r["started_at"]),
            "duration_ms": r["duration_ms"],
            "added": r["added"],
            "removed": r["removed"],
            "unchanged": r["unchanged"],
            "errors": r["errors"],
            "source": r["source"],
            "dry_run": bool(r["dry_run"]),
            "notes": r["notes"] or "",
        })
    return jsonify(items=items)


# ── Federation page ───────────────────────────────────────────────────────

@app.route("/bouncers")
@login_required
def bouncers_page():
    import bouncers as bmod
    import json as _json
    targets = bmod.load_all_targets()
    # Pull DB rows too so we can show their id + dry_run / last_sync_at
    conn = get_conn()
    try:
        db_rows = {r["name"]: dict(r) for r in conn.execute(
            "SELECT * FROM bouncer_targets ORDER BY id"
        ).fetchall()}
    finally:
        conn.close()

    view = []
    total_entries = 0
    online = 0
    errors_n = 0
    for t in targets:
        h = t.health()
        ok = bool(h.get("ok"))
        if ok:
            online += 1
        else:
            errors_n += 1
        db_row = db_rows.get(t.name)
        size = h.get("size") if "size" in h else (h.get("v4_size", 0) + h.get("v6_size", 0) if "v4_size" in h else None)
        if size is not None:
            total_entries += int(size)
        view.append({
            "id": db_row["id"] if db_row else 0,
            "name": t.name,
            "kind": t.kind,
            "ok": ok,
            "error": h.get("error", ""),
            "size": size,
            "dry_run": bool(db_row["dry_run"]) if db_row else DRY_RUN,
            "last_sync_rel": rel_time(db_row["last_sync_at"]) if db_row and db_row["last_sync_at"] else "—",
            "removable": db_row is not None,
        })
    kpis = {"total": len(view), "online": online, "errors": errors_n, "total_entries": total_entries}
    from bouncers.plugin_loader import list_loaded, plugin_dir
    plugins = list_loaded()
    # Phase 82 migration banner — flagged when the env-driven legacy MT
    # adapter is in play AND the operator hasn't acked the migration to
    # the DB-driven `mikrotik` adapter. Banner is non-dismissable until
    # explicitly suppressed via /settings → set
    # 'mikrotik_env_migration_ack' to '1'.
    migration_banner = (
        any(t["kind"] == "mikrotik_env" for t in view)
        and (get_setting("mikrotik_env_migration_ack") or "0") != "1"
    )
    return render_template("bouncers.html", targets=view, kpis=kpis,
                           plugins=plugins, plugin_dir=str(plugin_dir()),
                           migration_banner=migration_banner,
                           active="bouncers")


def _onboarding_steps() -> list[dict]:
    """Phase 86 — compute the first-run setup state for each step.
    Pure runtime check: looks at the actual config, no per-step persisted
    "done" flag (you can't fake done by setting a bit). Skips are
    operator-explicit and persisted in the `settings` table.

    Returns: [{id, title, why, action_href, action_label, status, detail}]
    where status ∈ {'done', 'skipped', 'pending'}.
    """
    import crowdsec
    skipped = set(
        (get_setting("onboarding.skipped") or "").split(",")
    ) - {""}

    def status(step_id: str, done: bool, detail: str = ""):
        if done:
            return "done", detail
        if step_id in skipped:
            return "skipped", ""
        return "pending", ""

    # 1. LAPI reachable
    try:
        from crowdsec import LAPIClient
        lapi_url = os.environ.get("CROWDSEC_LAPI_URL") or "http://127.0.0.1:8080"
        lapi_key = os.environ.get("CROWDSEC_BOUNCER_KEY") or ""
        c = LAPIClient(url=lapi_url, api_key=lapi_key, name="onboarding-probe")
        h = c.health()
        lapi_ok = bool(h.get("ok"))
        lapi_detail = f"{lapi_url} · v{h.get('version', '?')}" if lapi_ok else ""
    except Exception:  # noqa: BLE001
        lapi_ok, lapi_detail = False, ""

    # 2. Has at least one bouncer target (legacy MT counts)
    bouncer_count, live_bouncer_count = 0, 0
    try:
        import bouncers as bmod
        for b in bmod.load_all_targets():
            bouncer_count += 1
            # Live = enabled + not dry-run (per the same rules as
            # synthetic._live_bouncers).
            if b.kind == "mikrotik_env":
                sd = get_setting("settings.dry_run")
                if sd in ("0", "1"):
                    live = (sd == "0")
                else:
                    env_dry = (os.environ.get("DRY_RUN", "true") or "true").strip().lower()
                    live = env_dry not in ("1", "true", "yes")
                if live:
                    live_bouncer_count += 1
            else:
                conn = get_conn()
                try:
                    row = conn.execute(
                        "SELECT dry_run FROM bouncer_targets WHERE name=?", (b.name,)
                    ).fetchone()
                finally:
                    conn.close()
                if row and not int(row["dry_run"] or 0):
                    live_bouncer_count += 1
    except Exception:  # noqa: BLE001
        pass

    # 4. Federation sources count
    fed_count = 0
    try:
        conn = get_conn()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM sources WHERE name != 'local'"
            ).fetchone()
            fed_count = int(row["n"]) if row else 0
        finally:
            conn.close()
    except Exception:  # noqa: BLE001
        pass

    # 5. At least one notification channel configured
    try:
        import notifications as nmod
        notif_ok = any([
            nmod.channel_configured("discord"),
            nmod.channel_configured("telegram"),
            nmod.channel_configured("email"),
        ])
    except Exception:  # noqa: BLE001
        notif_ok = False

    # Build the steps. action_href/label only matter when status==pending.
    s1_status, s1_detail = status("lapi", lapi_ok, lapi_detail)
    s2_status, s2_detail = status("bouncer", bouncer_count > 0,
                                  f"{bouncer_count} configured")
    s3_status, s3_detail = status("live", live_bouncer_count > 0,
                                  f"{live_bouncer_count} live")
    s4_status, s4_detail = status("federation", fed_count > 0,
                                  f"{fed_count} sources")
    s5_status, s5_detail = status("notifications", notif_ok, "configured")

    return [
        {
            "id": "lapi", "status": s1_status, "detail": s1_detail,
            "title": "Confirm CrowdSec LAPI reachable",
            "why": "Protek needs to read decisions from a CrowdSec LAPI. "
                   "This step is automatic — we probe the LAPI URL from .env "
                   "and the bouncer key. If pending, check CROWDSEC_LAPI_URL "
                   "and CROWDSEC_BOUNCER_KEY in /var/www/Protek/.env and "
                   "restart the service.",
            "action_href": "/crowdsec",
            "action_label": "Open /crowdsec",
        },
        {
            "id": "bouncer", "status": s2_status, "detail": s2_detail,
            "title": "Add the first bouncer target",
            "why": "A bouncer is a downstream firewall (MikroTik, pfSense, "
                   "OPNsense, iptables, or Cloudflare) Protek pushes decisions "
                   "to. The wizard at /bouncers/add walks you through it.",
            "action_href": url_for("bouncers_add"),
            "action_label": "Add bouncer →",
        },
        {
            "id": "live", "status": s3_status, "detail": s3_detail,
            "title": "Promote the bouncer to LIVE",
            "why": "New bouncers default to dry-run for safety. Once you've "
                   "verified the diff looks right in /mikrotik (or the target's "
                   "page), promote it to LIVE so it starts pushing real bans.",
            "action_href": url_for("bouncers_page"),
            "action_label": "Open /bouncers",
        },
        {
            "id": "federation", "status": s4_status, "detail": s4_detail,
            "title": "Add a federation source (optional)",
            "why": "If you have multiple CrowdSec instances across your fleet, "
                   "you can federate them — Protek pulls from each, dedupes, "
                   "and pushes the union. Skip this if you only have one LAPI.",
            "action_href": url_for("federation_add"),
            "action_label": "Add source →",
        },
        {
            "id": "notifications", "status": s5_status, "detail": s5_detail,
            "title": "Configure at least one notification channel",
            "why": "Discord, Telegram, or SMTP — pick one (or more). Protek "
                   "alerts on sync errors, LAPI/MT outages, login lockouts, "
                   "and daily digests. The /notifications page has Test "
                   "buttons for each.",
            "action_href": url_for("notifications_page")
                          if "notifications_page" in app.view_functions else "/notifications",
            "action_label": "Open /notifications",
        },
    ]


def _onboarding_summary() -> dict:
    """Counts done / skipped / pending steps. Used by the topbar banner
    via the context processor + by the onboarding page itself."""
    steps = _onboarding_steps()
    done_n = sum(1 for s in steps if s["status"] == "done")
    skipped_n = sum(1 for s in steps if s["status"] == "skipped")
    pending_n = sum(1 for s in steps if s["status"] == "pending")
    return {
        "steps": steps,
        "done_n": done_n,
        "skipped_n": skipped_n,
        "pending_n": pending_n,
        "total": len(steps),
        "all_resolved": pending_n == 0,
    }


@app.context_processor
def _onboarding_context():
    """Expose the setup banner state to every template. Banner shows
    while settings.first_run_done != '1', linking to /onboarding."""
    try:
        done = (get_setting("first_run_done") or "0") == "1"
        if done:
            return {"onboarding_banner": None}
        summary = _onboarding_summary()
        return {"onboarding_banner": {
            "done_n": summary["done_n"], "total": summary["total"],
            "pending_n": summary["pending_n"],
        }}
    except Exception:  # noqa: BLE001
        return {"onboarding_banner": None}


@app.route("/onboarding")
@login_required
def onboarding():
    summary = _onboarding_summary()
    return render_template(
        "onboarding.html",
        steps=summary["steps"],
        done_n=summary["done_n"],
        skipped_n=summary["skipped_n"],
        pending_n=summary["pending_n"],
        all_resolved=summary["all_resolved"],
        active="onboarding",
    )


@app.route("/onboarding/skip/<step>", methods=["POST"])
@login_required
@role_required("operator")
def onboarding_skip(step):
    skipped = set(
        (get_setting("onboarding.skipped") or "").split(",")
    ) - {""}
    skipped.add(step)
    set_setting("onboarding.skipped", ",".join(sorted(skipped)))
    return redirect(url_for("onboarding"))


@app.route("/onboarding/complete", methods=["POST"])
@login_required
@role_required("operator")
def onboarding_complete():
    summary = _onboarding_summary()
    if not summary["all_resolved"]:
        flash("Finish or skip the remaining steps before dismissing.", "error")
        return redirect(url_for("onboarding"))
    set_setting("first_run_done", "1")
    _audit("onboarding.complete", target="self", after={"done_n": summary["done_n"],
                                                         "skipped_n": summary["skipped_n"]})
    flash("Setup complete. Banner dismissed — re-open /onboarding any time.", "info")
    return redirect(url_for("dashboard") if "dashboard" in app.view_functions else "/")


def _detect_private_ip() -> str:
    """Best-effort: return the wg0 interface's IPv4 if present, otherwise
    the first non-loopback IPv4. Used by the federation/add wizard to
    pre-fill the `sudo ufw allow from <ip>` line in the bash block.
    Returns "" if no candidate is found — caller renders a placeholder.
    """
    import socket
    import subprocess
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "wg0"],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "inet":
                    return parts[3].split("/")[0]
    except Exception:  # noqa: BLE001
        pass
    try:
        # Fallback: ask the kernel which IP we'd use to reach an arbitrary
        # public address. No packets are actually sent (UDP socket connect).
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:  # noqa: BLE001
        return ""


def _bouncer_kinds_for_wizard():
    """Pull display metadata + field_schema from each registered adapter.
    Adapters without field_schema (e.g. mikrotik_env which is env-driven
    only) are excluded — they shouldn't appear in the add wizard.
    """
    import bouncers as bmod
    blurbs = {
        "mikrotik":       ("MikroTik RouterOS", "Additional RouterOS router via API (multi-router setup). The legacy mikrotik_env adapter still serves the .env-configured primary router."),
        "cloudflare":     ("Cloudflare WAF",    "Account-level Rules List, fronted by a WAF Custom Rule the operator wires manually."),
        "pfsense":        ("pfSense",           "Uses the pfsense-pkg-RESTAPI v2 package. PATCHes the whole alias array per cycle and triggers /firewall/apply."),
        "opnsense":       ("OPNsense",          "Built-in REST API, no plugin required. Per-entry add/delete via alias_util."),
        "iptables_ipset": ("iptables / ipset",  "Local-host firewall via ipset. Auto-manages v4 + v6 sets; operator owns the consuming match-set rules."),
    }
    out = []
    for kind, cls in bmod.KINDS.items():
        schema = getattr(cls, "field_schema", None)
        if schema is None:
            continue
        title, blurb = blurbs.get(kind, (kind, ""))
        out.append({"kind": kind, "title": title, "blurb": blurb, "fields": schema})
    return out


def _coerce_field(value, kind):
    """Apply field_schema's `coerce` rule to a posted form string."""
    if value is None:
        return None
    if kind == "int":
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    if kind == "int_or_none":
        s = (value or "").strip()
        if not s:
            return None
        try:
            return int(s)
        except (TypeError, ValueError):
            return None
    if kind == "bool":
        # Checkboxes post their value when checked, omit when unchecked.
        # When this coercer is called, presence already implies True.
        return str(value).lower() in ("1", "true", "yes", "on")
    if kind == "csv":
        return [s.strip() for s in (value or "").split(",") if s.strip()]
    return value  # default: pass-through string


@app.route("/bouncers/add", methods=["GET", "POST"])
@login_required
@role_required("operator")
def bouncers_add():
    import bouncers as bmod
    import json as _json

    if request.method == "GET":
        if request.args.get("advanced"):
            # Legacy one-shot form still rendered inline on the /bouncers page.
            return redirect(url_for("bouncers_page", advanced="1"))
        return render_template(
            "bouncers_add.html",
            kinds=_bouncer_kinds_for_wizard(),
            form_error=None, form_name="",
        )

    name = (request.form.get("name") or "").strip()
    kind = (request.form.get("kind") or "").strip()
    dry_run = (request.form.get("dry_run") or "1") == "1"

    if not (name and kind):
        flash("name + kind required", "error")
        return redirect(url_for("bouncers_page"))
    if kind not in bmod.KINDS:
        flash("unknown kind", "error")
        return redirect(url_for("bouncers_page"))

    # Two posting shapes:
    #   (1) wizard:    cfg__<kind>__<field>=<value> for each schema entry
    #   (2) advanced:  config_json=<raw JSON string>
    legacy_json = request.form.get("config_json")
    if legacy_json is not None:
        try:
            cfg = _json.loads(legacy_json or "{}")
        except _json.JSONDecodeError as e:
            flash(f"invalid JSON: {e}", "error")
            return redirect(url_for("bouncers_page"))
    else:
        cls = bmod.KINDS[kind]
        schema = getattr(cls, "field_schema", None) or []
        cfg = {}
        for f in schema:
            field_name = f["name"]
            posted_key = f"cfg__{kind}__{field_name}"
            if f.get("type") == "checkbox":
                cfg[field_name] = posted_key in request.form
                continue
            raw = request.form.get(posted_key, "").strip()
            if raw == "" and not f.get("required"):
                # Don't write empty strings — let the adapter use its default.
                continue
            cfg[field_name] = _coerce_field(raw, f.get("coerce", ""))

    probe = bmod.make_bouncer(name, kind, cfg)
    if not probe:
        return render_template(
            "bouncers_add.html",
            kinds=_bouncer_kinds_for_wizard(),
            form_error="could not instantiate bouncer with given config",
            form_name=name,
        ) if legacy_json is None else _bouncer_add_fail("could not instantiate bouncer with given config")
    h = probe.health() if probe.is_configured() else {"ok": False, "error": "not configured"}
    if not h.get("ok"):
        msg = f"health check failed: {h.get('error')}"
        if legacy_json is None:
            return render_template(
                "bouncers_add.html",
                kinds=_bouncer_kinds_for_wizard(),
                form_error=msg, form_name=name,
            )
        return _bouncer_add_fail(msg)

    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    try:
        try:
            conn.execute(
                """INSERT INTO bouncer_targets (name, kind, config_json, enabled, dry_run, created_at)
                   VALUES (?, ?, ?, 1, ?, ?)""",
                (name, kind, _json.dumps(cfg), 1 if dry_run else 0, now),
            )
        except Exception as e:  # noqa: BLE001
            flash(f"insert failed: {e}", "error")
            return redirect(url_for("bouncers_page"))
    finally:
        conn.close()
    flash(f"target '{name}' added ({kind}) — applies on next reconcile cycle.", "info")
    _audit("bouncer.add", target=name,
           after={"name": name, "kind": kind, "dry_run": dry_run,
                  "config_keys": list(cfg.keys())})
    return redirect(url_for("bouncers_page"))


def _bouncer_add_fail(msg: str):
    flash(msg, "error")
    return redirect(url_for("bouncers_page"))


@app.route("/api/intel/test/<provider>", methods=["POST"])
@login_required
@role_required("operator")
def api_intel_test(provider):
    """Phase 85 — probe an intel provider's configured key without
    waiting for a real lookup. Uses a well-known benign IP (1.1.1.1)
    so we never report a real attacker IP just to test the wiring.

    Providers:
      abuseipdb — requires ABUSEIPDB_API_KEY; HTTP 401/403 means bad key
      otx       — no key needed (general endpoint); HTTP 200 expected
      proxycheck — requires PROXYCHECK_API_KEY; 200 expected
      spamhaus  — bulk-download path; we just HEAD the URL
      tor       — bulk-download path; HEAD the URL
    """
    import intel_providers
    test_ip = "1.1.1.1"
    provider = (provider or "").lower()
    try:
        if provider == "abuseipdb":
            result = intel_providers.abuseipdb_lookup(test_ip)
        elif provider == "otx":
            result = intel_providers.otx_lookup(test_ip)
        elif provider == "proxycheck":
            result = intel_providers.proxycheck_lookup(test_ip)
        elif provider in ("spamhaus", "tor"):
            # Bulk-download providers — probe the URL with HEAD.
            import requests
            urls = {
                "spamhaus": "https://www.spamhaus.org/drop/drop.txt",
                "tor": "https://check.torproject.org/torbulkexitlist",
            }
            try:
                r = requests.head(urls[provider], timeout=5, allow_redirects=True)
                result = {"ok": r.status_code < 400,
                          "status_code": r.status_code,
                          "url": urls[provider]}
                if r.status_code >= 400:
                    result["error"] = f"HTTP {r.status_code}"
            except Exception as e:  # noqa: BLE001
                result = {"ok": False, "error": str(e)}
        else:
            return jsonify({"ok": False, "error": f"unknown provider '{provider}'"}), 400
    except Exception as e:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(e)}), 500
    return jsonify(result)


@app.route("/api/peers/test", methods=["POST"])
@login_required
@role_required("admin")
def api_peers_test():
    """Phase 85 — pre-add diagnostic probe for a peer Protek instance.
    Reuses the phase-84 ladder. Token goes in Authorization header."""
    import diagnostic
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip().rstrip("/")
    token = (payload.get("token") or "").strip()
    if not url or not token:
        return jsonify({"ok": False, "error": "url + token required"}), 400
    rows = diagnostic.diagnose_url(
        url, api_key=f"Bearer {token}",
        auth_header="Authorization",
        api_smoke_path="/api/v1/tile/summary",
        api_smoke_query={},
    )
    return jsonify({"rows": rows, "summary": diagnostic.summary(rows)})


@app.route("/api/diagnose", methods=["POST"])
@login_required
@role_required("operator")
def api_diagnose():
    """Phase 84 — JSON endpoint backing the diagnostic ladder UI.
    Accepts {url, api_key?, kind?} and returns {rows: [...], summary: {...}}.

    Bouncer/federation pages call this on a button click; the wizard
    surfaces the structured failure inline. No DB writes, no audit
    entries — it's just a probe.
    """
    import diagnostic
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    api_key = (payload.get("api_key") or "").strip() or None
    if not url:
        return jsonify({"ok": False, "error": "url is required"}), 400
    # Per-kind tweaks: bouncer adapters use different auth headers /
    # smoke paths than the CrowdSec LAPI. Default = LAPI shape.
    kind = (payload.get("kind") or "").strip().lower()
    kwargs = {}
    if kind == "cloudflare":
        # Cloudflare uses bearer auth; the diagnose path probes the
        # IPs/lists root.
        kwargs["auth_header"] = "Authorization"
        if api_key and not api_key.startswith("Bearer "):
            api_key = f"Bearer {api_key}"
        kwargs["api_smoke_path"] = "/client/v4/user/tokens/verify"
        kwargs["api_smoke_query"] = {}
    elif kind in ("pfsense",):
        kwargs["auth_header"] = "X-API-Key"
        kwargs["api_smoke_path"] = "/api/v2/status/system"
        kwargs["api_smoke_query"] = {}
    elif kind in ("opnsense",):
        # OPNsense uses HTTP basic; we can't model that with a header
        # field cleanly. Skip auth probing — TLS + reachability is the
        # value here.
        kwargs["api_smoke_path"] = "/api/diagnostics/interface/getInterfaceNames"
        kwargs["api_smoke_query"] = {}
    rows = diagnostic.diagnose_url(url, api_key=api_key, **kwargs)
    return jsonify({"rows": rows, "summary": diagnostic.summary(rows)})


@app.route("/bouncers/promote/<int:tid>", methods=["POST"])
@login_required
@role_required("operator")
def bouncers_promote(tid):
    """Flip a bouncer target from dry_run=1 to dry_run=0 after explicit
    operator confirmation (the promote-to-live affordance, phase 82).
    Audited so the timing is recoverable."""
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT name, kind, dry_run FROM bouncer_targets WHERE id = ?",
            (tid,),
        ).fetchone()
        if not row:
            flash("target not found", "error")
            return redirect(url_for("bouncers_page"))
        if not int(row["dry_run"] or 0):
            flash(f"'{row['name']}' is already live (dry_run=0)", "info")
            return redirect(url_for("bouncers_page"))
        conn.execute(
            "UPDATE bouncer_targets SET dry_run = 0 WHERE id = ?", (tid,),
        )
    finally:
        conn.close()
    flash(f"'{row['name']}' promoted to LIVE — next reconcile cycle will push.", "info")
    _audit("bouncer.promote", target=row["name"],
           before={"dry_run": 1}, after={"dry_run": 0})
    return redirect(url_for("bouncers_page"))


@app.route("/api/search")
@login_required
def api_search():
    """Session-auth global search for the in-browser cmd-K palette.

    Same response shape as /api/v1/search (which requires a bearer token).
    Splitting the surfaces keeps in-browser cmd-K from needing a token while
    the bearer API stays clean for external integrators.
    """
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify(items=[], count=0)
    try:
        limit_per_kind = max(1, min(50, int(request.args.get("limit", "8"))))
    except (TypeError, ValueError):
        limit_per_kind = 8
    pat = f"%{q}%"
    out: list = []
    conn = get_conn()
    try:
        for r in conn.execute(
            "SELECT DISTINCT value, scenario, origin FROM decisions "
            "WHERE deleted_at IS NULL AND (value LIKE ? OR scenario LIKE ?) "
            "ORDER BY id DESC LIMIT ?", (pat, pat, limit_per_kind),
        ).fetchall():
            out.append({"kind": "decision", "label": r["value"],
                        "hint": f"{r['scenario']} · {r['origin']}",
                        "href": f"/attackers/{r['value']}"})
        for r in conn.execute(
            "SELECT source_ip, scenario, source_country FROM alerts "
            "WHERE source_ip LIKE ? OR scenario LIKE ? "
            "ORDER BY id DESC LIMIT ?", (pat, pat, limit_per_kind),
        ).fetchall():
            if not r["source_ip"]:
                continue
            out.append({"kind": "alert", "label": r["source_ip"],
                        "hint": f"{r['scenario']} · {r['source_country'] or '?'}",
                        "href": f"/attackers/{r['source_ip']}"})
        for r in conn.execute(
            "SELECT id, kind, value, note FROM whitelist "
            "WHERE (value LIKE ? OR note LIKE ?) "
            "AND (expires_at IS NULL OR expires_at > datetime('now')) "
            "ORDER BY id DESC LIMIT ?", (pat, pat, limit_per_kind),
        ).fetchall():
            out.append({"kind": "whitelist", "label": f"{r['kind']}={r['value']}",
                        "hint": r["note"] or "whitelist rule",
                        "href": "/whitelist"})
        for r in conn.execute(
            "SELECT id, name, kind FROM bouncer_targets WHERE name LIKE ? "
            "ORDER BY id LIMIT ?", (pat, limit_per_kind),
        ).fetchall():
            out.append({"kind": "bouncer", "label": r["name"], "hint": r["kind"],
                        "href": f"/bouncers/edit/{r['id']}"})
        for r in conn.execute(
            "SELECT action, target, actor, created_at FROM audit_log "
            "WHERE action LIKE ? OR target LIKE ? OR actor LIKE ? "
            "ORDER BY id DESC LIMIT ?", (pat, pat, pat, limit_per_kind),
        ).fetchall():
            out.append({"kind": "audit", "label": r["action"],
                        "hint": f"{r['target'] or '—'} · {r['actor'] or '?'} · {r['created_at'][:19]}",
                        "href": f"/audit?q={r['action']}"})
    finally:
        conn.close()
    return jsonify(items=out, count=len(out), q=q)


@app.route("/asn-escalations")
@login_required
def asn_escalations_page():
    import asn_detector
    pending = asn_detector.list_escalations(status="pending", limit=200)
    decided = asn_detector.list_escalations(status=None, limit=50)
    decided = [d for d in decided if d["status"] != "pending"]
    return render_template(
        "asn_escalations.html",
        pending=pending,
        decided=decided[:50],
        active="asn_escalations",
    )


@app.route("/asn-escalations/decide/<int:eid>", methods=["POST"])
@login_required
@role_required("operator")
def asn_escalations_decide(eid: int):
    import asn_detector
    decision = (request.form.get("decision") or "").strip()
    note = (request.form.get("note") or "").strip()
    try:
        result = asn_detector.decide(eid, decision,
                                      decided_by=session.get("username", ""),
                                      note=note)
        flash(f"ASN {result['asn']} {decision}.", "info")
    except ValueError as e:
        flash(str(e), "error")
    return redirect(url_for("asn_escalations_page"))


@app.route("/decisions/bulk", methods=["POST"])
@login_required
@role_required("operator")
def decisions_bulk():
    """Bulk operations on /decisions. Accepts a form with `ips` (comma-separated)
    and an `action` (delete / whitelist / extend)."""
    raw_ips = (request.form.get("ips") or "").strip()
    action = (request.form.get("action") or "").strip()
    ips = [ip.strip() for ip in raw_ips.split(",") if ip.strip()]
    if not ips:
        flash("no IPs selected", "error")
        return redirect(url_for("decisions_page"))
    if action not in ("delete", "whitelist", "extend"):
        flash(f"unknown action: {action}", "error")
        return redirect(url_for("decisions_page"))

    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    affected = 0
    try:
        if action == "delete":
            placeholders = ",".join("?" * len(ips))
            cur = conn.execute(
                f"UPDATE decisions SET deleted_at = ? "
                f"WHERE value IN ({placeholders}) AND deleted_at IS NULL",
                [now] + ips,
            )
            affected = cur.rowcount
        elif action == "whitelist":
            import scenarios_admin as sa
            for ip in ips:
                res = sa.add_whitelist("ip", ip, note=f"bulk whitelist via /decisions", expires_at=None)
                if res.get("ok"):
                    affected += 1
            # Also soft-delete the active decisions for those IPs so they
            # leave the bouncers on the next cycle.
            placeholders = ",".join("?" * len(ips))
            conn.execute(
                f"UPDATE decisions SET deleted_at = ? "
                f"WHERE value IN ({placeholders}) AND deleted_at IS NULL",
                [now] + ips,
            )
        elif action == "extend":
            try:
                extend_h = max(1, min(720, int(request.form.get("extend_hours", "24"))))
            except (TypeError, ValueError):
                extend_h = 24
            new_until = (datetime.now(timezone.utc) + timedelta(hours=extend_h)).isoformat()
            placeholders = ",".join("?" * len(ips))
            cur = conn.execute(
                f"UPDATE decisions SET until = ? "
                f"WHERE value IN ({placeholders}) AND deleted_at IS NULL",
                [new_until] + ips,
            )
            affected = cur.rowcount
    finally:
        conn.close()

    _audit(f"decisions.bulk.{action}", target=f"{len(ips)} IPs",
           note=f"affected={affected}, sample={ips[:5]}")
    try:
        import siem as _siem
        _siem.ship(f"decisions.bulk.{action}", {"count": len(ips), "affected": affected,
                                                  "sample": ips[:10]})
    except Exception:  # noqa: BLE001
        pass
    flash(f"bulk {action}: {affected} rows affected ({len(ips)} IPs)", "info")
    return redirect(url_for("decisions_page"))


@app.route("/bouncers/edit/<int:tid>", methods=["GET", "POST"])
@login_required
@role_required("operator")
def bouncers_edit(tid: int):
    """In-place edit — change name/config/dry_run without losing sync state.

    Secret fields (api_token, api_secret, password) are write-only: shown
    masked, replaced ONLY when the operator submits a non-empty new value
    (matches the /notifications credentials pattern).
    """
    import bouncers as bmod
    import json as _json
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT * FROM bouncer_targets WHERE id = ?", (tid,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        flash("target not found", "error")
        return redirect(url_for("bouncers_page"))

    current_cfg = {}
    try:
        current_cfg = _json.loads(row["config_json"] or "{}")
    except _json.JSONDecodeError:
        current_cfg = {}

    SECRET_KEYS = ("api_token", "api_secret", "password", "hmac_secret")

    if request.method == "POST":
        new_name = (request.form.get("name") or row["name"]).strip()
        new_dry = (request.form.get("dry_run") or "1") == "1"
        raw_cfg = (request.form.get("config_json") or "").strip()
        try:
            new_cfg = _json.loads(raw_cfg) if raw_cfg else dict(current_cfg)
        except _json.JSONDecodeError as e:
            flash(f"invalid JSON: {e}", "error")
            return redirect(url_for("bouncers_edit", tid=tid))

        # For each secret key, blank submission = keep current.
        for k in SECRET_KEYS:
            if k in current_cfg and not new_cfg.get(k):
                new_cfg[k] = current_cfg[k]

        # Probe the new config before persisting so the operator catches
        # bad creds immediately.
        probe = bmod.make_bouncer(new_name, row["kind"], new_cfg)
        if not probe:
            flash("could not instantiate bouncer with given config", "error")
            return redirect(url_for("bouncers_edit", tid=tid))
        if probe.is_configured():
            h = probe.health()
            if not h.get("ok"):
                flash(f"health check failed: {h.get('error', '?')}", "error")
                return redirect(url_for("bouncers_edit", tid=tid))

        conn = get_conn()
        try:
            conn.execute(
                "UPDATE bouncer_targets SET name = ?, config_json = ?, dry_run = ? WHERE id = ?",
                (new_name, _json.dumps(new_cfg), 1 if new_dry else 0, tid),
            )
        finally:
            conn.close()
        # Build a redacted diff for the audit log — never log raw secrets.
        before_san = {k: ("••••" if k in SECRET_KEYS else v) for k, v in current_cfg.items()}
        after_san  = {k: ("••••" if k in SECRET_KEYS else v) for k, v in new_cfg.items()}
        changed = [k for k in set(list(before_san) + list(after_san))
                   if before_san.get(k) != after_san.get(k)]
        _audit("bouncer.edit", target=new_name,
               before={"name": row["name"], "dry_run": bool(row["dry_run"]), "cfg": before_san},
               after={"name": new_name, "dry_run": new_dry, "cfg": after_san},
               note=f"changed fields: {', '.join(changed) if changed else '(none)'}")
        flash(f"target '{new_name}' updated. Effective on next reconcile cycle.", "info")
        return redirect(url_for("bouncers_page"))

    # GET — render the edit form. Mask secrets in the JSON display + provide
    # a separate hint for what's currently set.
    display_cfg = dict(current_cfg)
    masked_summary = {}
    for k in SECRET_KEYS:
        if k in display_cfg and display_cfg[k]:
            v = display_cfg[k]
            masked_summary[k] = "•••• " + (v[-4:] if len(v) >= 4 else "••")
            display_cfg[k] = ""  # blank in the JSON shown to the operator
    return render_template(
        "bouncers_edit.html",
        target=dict(row),
        display_cfg=_json.dumps(display_cfg, indent=2),
        masked_summary=masked_summary,
        active="bouncers",
    )


@app.route("/bouncers/delete/<int:tid>", methods=["POST"])
@login_required
@role_required("operator")
def bouncers_delete(tid: int):
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT name, kind FROM bouncer_targets WHERE id = ?", (tid,)
        ).fetchone()
        conn.execute("DELETE FROM bouncer_targets WHERE id = ?", (tid,))
    finally:
        conn.close()
    flash("target removed", "info")
    _audit("bouncer.delete", target=str(tid),
           before={"name": row["name"] if row else "", "kind": row["kind"] if row else ""})
    return redirect(url_for("bouncers_page"))


@app.route("/scenarios/catalog")
@login_required
def scenarios_catalog():
    import scenarios_admin as sa
    hub = sa.hub_list()
    cat = (request.args.get("cat") or "scenarios").strip()
    categories = ["scenarios", "parsers", "collections", "postoverflows", "contexts"]
    if cat not in categories:
        cat = "scenarios"
    items = hub.get(cat, []) or []
    counts = {k: len(v or []) for k, v in hub.items()}
    counts["noisy"] = len(sa.noisy_scenarios())
    counts["sleeping"] = len(sa.sleeping_scenarios())
    custom_files = sa.list_custom_scenarios()
    return render_template(
        "scenarios_catalog.html",
        items=items, active_cat=cat, categories=categories,
        counts=counts, custom_files=custom_files,
        active="scenarios",
    )


@app.route("/scenarios/action", methods=["POST"])
@login_required
@role_required("operator")
def scenarios_action():
    import scenarios_admin as sa
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    action = (request.form.get("action") or "").strip()
    if action == "install":
        res = sa.hub_install(kind, name)
    elif action == "remove":
        res = sa.hub_remove(kind, name)
    else:
        flash("unknown action", "error")
        return redirect(url_for("scenarios_catalog", cat=kind))
    if not res.get("ok"):
        flash(f"{action} failed: {res.get('error')}", "error")
    else:
        flash(f"{action} of {name} succeeded.", "info")
        sa.reload_agent()
    return redirect(url_for("scenarios_catalog", cat=kind))


@app.route("/scenarios/editor", methods=["GET", "POST"])
@login_required
def scenarios_editor():
    import scenarios_admin as sa
    test_result = None
    if request.method == "POST":
        fname = (request.form.get("filename") or "").strip()
        content = request.form.get("content") or ""
        res = sa.save_custom_scenario(fname, content)
        if not res.get("ok"):
            flash(f"save failed: {res.get('error')}", "error")
            return render_template("scenarios_editor.html",
                                   filename=fname, content=content,
                                   test_result=None, active="scenarios")
        flash(f"saved {fname}", "info")
        if request.form.get("reload"):
            test_result = sa.reload_agent()
            if test_result.get("ok"):
                flash("agent reloaded", "info")
            else:
                flash(f"reload failed: {test_result.get('error')}", "error")
        return render_template("scenarios_editor.html",
                               filename=fname, content=content,
                               test_result=test_result, active="scenarios")

    fname = (request.args.get("file") or "").strip()
    content = ""
    if fname:
        content = sa.read_custom_scenario(fname) or ""
    else:
        # Sensible template
        content = (
            "# Custom CrowdSec scenario template.\n"
            "# See https://docs.crowdsec.net/docs/scenarios/intro/\n\n"
            "type: leaky\n"
            "name: yourname/example-scenario\n"
            "description: \"example — replace me\"\n"
            "filter: \"evt.Meta.log_type == 'http_access' && evt.Parsed.verb == 'POST'\"\n"
            "groupby: evt.Meta.source_ip\n"
            "leakspeed: 10s\n"
            "capacity: 5\n"
            "blackhole: 1m\n"
            "labels:\n"
            "  service: http\n"
            "  type: attack\n"
        )
    return render_template("scenarios_editor.html",
                           filename=fname, content=content,
                           test_result=None, active="scenarios")


@app.route("/whitelist")
@login_required
def whitelist_page():
    import scenarios_admin as sa
    rules = sa.list_whitelist()
    conn = get_conn()
    try:
        hits_24h = conn.execute(
            "SELECT COUNT(*) FROM whitelist_hits WHERE created_at > datetime('now', '-1 day')"
        ).fetchone()[0]
        hits_7d = conn.execute(
            "SELECT COUNT(*) FROM whitelist_hits WHERE created_at > datetime('now', '-7 days')"
        ).fetchone()[0]
        hit_rows = conn.execute(
            """
            SELECT h.created_at, h.ip, h.scenario, w.kind, w.value
            FROM whitelist_hits h JOIN whitelist w ON w.id = h.whitelist_id
            ORDER BY h.id DESC LIMIT 50
            """
        ).fetchall()
    finally:
        conn.close()
    hits = [
        {"created_rel": rel_time(r["created_at"]), "ip": r["ip"],
         "scenario": r["scenario"] or "", "fam": scenario_fam(r["scenario"]),
         "kind": r["kind"], "value": r["value"]}
        for r in hit_rows
    ]
    kpis = {"active": len(rules), "hits_24h": hits_24h, "hits_7d": hits_7d}
    return render_template("whitelist.html",
                           rules=rules, hits=hits, kpis=kpis,
                           approval_required=sa.approval_required(),
                           active="whitelist")


@app.route("/whitelist/add", methods=["POST"])
@login_required
@role_required("operator")
def whitelist_add():
    import scenarios_admin as sa
    kind = (request.form.get("kind") or "").strip()
    value = (request.form.get("value") or "").strip()
    note = (request.form.get("note") or "").strip()
    expires = (request.form.get("expires_at") or "").strip() or None
    res = sa.add_whitelist(kind, value, note, expires)
    if not res.get("ok"):
        flash(f"add failed: {res.get('error')}", "error")
    else:
        flash(f"whitelist {kind}={value} added", "info")
    _audit("whitelist.add", target=f"{kind}={value}",
           after={"kind": kind, "value": value, "note": note, "expires": expires},
           note=res.get("error", ""))
    return redirect(url_for("whitelist_page"))


@app.route("/whitelist/delete/<int:wid>", methods=["POST"])
@login_required
@role_required("operator")
def whitelist_delete(wid: int):
    import scenarios_admin as sa
    sa.delete_whitelist(wid)
    flash("rule removed", "info")
    _audit("whitelist.delete", target=f"id={wid}")
    return redirect(url_for("whitelist_page"))


@app.route("/whitelist/mode", methods=["POST"])
@login_required
@role_required("operator")
def whitelist_toggle_mode():
    cur = (get_setting("settings.approval_required") or "0") == "1"
    set_setting("settings.approval_required", "0" if cur else "1")
    _audit("whitelist.mode_toggle",
           before={"approval_required": cur},
           after={"approval_required": not cur})
    flash(f"queue mode → {'AUTO' if cur else 'SEMI-AUTO'}", "info")
    return redirect(url_for("whitelist_page"))


@app.route("/approvals")
@login_required
def approvals_page():
    import scenarios_admin as sa
    pending_rows = sa.list_queue("pending", limit=200)
    pending = [
        {**p, "created_rel": rel_time(p["created_at"]), "fam": scenario_fam(p.get("scenario"))}
        for p in pending_rows
    ]
    conn = get_conn()
    try:
        approved_24h = conn.execute(
            "SELECT COUNT(*) FROM approval_queue WHERE status='approved' AND decided_at > datetime('now','-1 day')"
        ).fetchone()[0]
        rejected_24h = conn.execute(
            "SELECT COUNT(*) FROM approval_queue WHERE status='rejected' AND decided_at > datetime('now','-1 day')"
        ).fetchone()[0]
        recent = conn.execute(
            "SELECT ip, status, decided_by, decided_at FROM approval_queue "
            "WHERE status != 'pending' ORDER BY decided_at DESC LIMIT 20"
        ).fetchall()
    finally:
        conn.close()
    recent_decisions = [
        {"ip": r["ip"], "status": r["status"], "decided_by": r["decided_by"],
         "decided_rel": rel_time(r["decided_at"])}
        for r in recent
    ]
    kpis = {"pending": len(pending_rows), "approved_24h": approved_24h, "rejected_24h": rejected_24h}
    return render_template("approvals.html",
                           pending=pending, recent_decisions=recent_decisions,
                           kpis=kpis, approval_required=sa.approval_required(),
                           active="approvals")


@app.route("/approvals/decide/<int:qid>", methods=["POST"])
@login_required
@role_required("operator")
def approvals_decide(qid: int):
    import scenarios_admin as sa
    decision = (request.form.get("decision") or "").strip()
    if decision not in ("approved", "rejected"):
        abort(400)
    try:
        sa.decide(qid, decision, decided_by=session.get("username", ""))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("approvals_page"))
    # On reject, auto-add a whitelist IP rule so the same IP won't re-queue.
    if decision == "rejected":
        conn = get_conn()
        try:
            row = conn.execute("SELECT ip, scenario FROM approval_queue WHERE id = ?", (qid,)).fetchone()
        finally:
            conn.close()
        if row:
            sa.add_whitelist("ip", row["ip"], note=f"auto: rejected from approval queue", expires_at=None)
    flash(f"decision recorded: {decision}", "info")
    _audit(f"approval.{decision}", target=f"qid={qid}")
    return redirect(url_for("approvals_page"))


@app.route("/attackers/<ip>")
@login_required
def attacker_page(ip: str):
    """Per-IP dossier. Reads cached enrichment; never blocks on a network call.
    Use the Refresh button to force live lookups."""
    # Validate IP-ish input
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        # accept CIDR for /decisions filter pass-through
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            abort(404)

    data = intel.enrichment_for_ip(ip)
    geo = data.get("geo") or {}
    cti = data.get("cti") or {}
    whois = data.get("whois") or {}
    scenarios_rows = data.get("scenarios") or []
    sources_seen_rows = data.get("sources_seen") or []

    # Compute stats
    hits = len(scenarios_rows)
    active = any(s.get("deleted_at") is None for s in scenarios_rows)
    first_seen = min((s.get("first_seen_at") for s in scenarios_rows if s.get("first_seen_at")), default=None)
    last_seen = max((s.get("last_seen_at") for s in scenarios_rows if s.get("last_seen_at")), default=None)
    sources_seen_names = [s.get("source_name") for s in sources_seen_rows]

    scenarios = []
    for s in scenarios_rows:
        scenarios.append({
            "scenario": s.get("scenario"), "origin": s.get("origin"),
            "origin_source": s.get("origin_source"), "duration": s.get("duration"),
            "last_seen_rel": rel_time(s.get("last_seen_at")),
            "deleted_at": s.get("deleted_at"),
            "fam": scenario_fam(s.get("scenario")),
        })
    sources_seen = [{"source_name": r["source_name"], "last_seen_rel": rel_time(r["last_seen_at"])}
                    for r in sources_seen_rows]

    reputation = (cti.get("reputation") or "").lower() if cti else ""
    cti_score = cti.get("score") if cti else 0
    rep_color = "var(--muted)"
    if reputation == "malicious":
        rep_color = "var(--red)"
    elif reputation == "suspicious":
        rep_color = "var(--amber)"
    elif reputation == "known":
        rep_color = "var(--cyan)"
    elif reputation == "safe":
        rep_color = "var(--green)"

    import json as _json
    cti_raw_pretty = ""
    if cti and cti.get("raw"):
        try:
            cti_raw_pretty = _json.dumps(cti.get("raw"), indent=2)[:6000]
        except Exception:  # noqa: BLE001
            cti_raw_pretty = "(unparseable)"

    abuse_subject = f"Abuse report for {ip}"
    abuse_body = (
        f"Hello,\n\nIP {ip} attacked our infrastructure with the following scenarios:\n\n"
        + "\n".join(f"- {s['scenario']} (last seen {s['last_seen_rel']})" for s in scenarios[:10])
        + "\n\nDecisions logged via CrowdSec on Protek.\n\nThanks."
    )

    return render_template(
        "attacker.html",
        ip=ip,
        geo=geo, cti=cti, whois=whois,
        scenarios=scenarios,
        sources_seen=sources_seen,
        stats={
            "hits": hits, "active": active,
            "first_seen_rel": rel_time(first_seen),
            "last_seen_rel": rel_time(last_seen),
            "sources_seen": len(sources_seen_names),
            "sources_seen_list": ", ".join(sources_seen_names) or "—",
        },
        reputation=reputation or "unknown",
        reputation_color=rep_color,
        cti_score=cti_score,
        cti_raw_pretty=cti_raw_pretty,
        abuse_subject=abuse_subject,
        abuse_body=abuse_body,
        atom_url=(get_setting("integrations.atom_url") or _envstr("ATOM_URL", "")),
        othoni_url=(get_setting("integrations.othoni_url") or _envstr("OTHONI_URL", "")),
        rep_score=_reputation_for(ip),
        ip_tags=_tags_for(ip),
        active="attackers",
    )


def _reputation_for(ip: str) -> dict:
    try:
        import reputation as _rep
        return _rep.get_or_compute(ip)
    except Exception:  # noqa: BLE001
        return {"score": 0, "tier": "monitor", "breakdown": {}}


def _tags_for(ip: str) -> list:
    try:
        import intel_providers
        return intel_providers.ip_tags(ip)
    except Exception:  # noqa: BLE001
        return []


@app.route("/attackers/<ip>/refresh", methods=["POST"])
@login_required
@role_required("operator")
def attacker_refresh(ip: str):
    """Force live lookups bypassing cache. Returns to the attacker page."""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
    except ValueError:
        abort(404)
    try:
        intel.rdns_lookup(ip)
        res = intel.cymru_lookup(ip)
        if res.get("ok"):
            intel._persist_asn(ip, res.get("asn", ""), res.get("as_org", ""))  # noqa: SLF001
        intel.whois_lookup(ip)
        intel.cti_lookup(ip, force=True)
        flash(f"Enrichment refreshed for {ip}.", "info")
    except Exception as e:  # noqa: BLE001
        flash(f"Refresh failed: {e}", "error")
    return redirect(url_for("attacker_page", ip=ip))


@app.route("/intel")
@login_required
def intel_page():
    conn = get_conn()
    try:
        # Top ASNs in 24h (uses decisions.asn populated by intel worker)
        top_asn = conn.execute(
            """
            SELECT asn, MAX(as_org) AS as_org, COUNT(*) AS bans, COUNT(DISTINCT value) AS uniq
            FROM decisions
            WHERE last_seen_at > datetime('now', '-1 day')
              AND asn IS NOT NULL AND asn != ''
            GROUP BY asn ORDER BY bans DESC LIMIT 15
            """
        ).fetchall()
        # Top countries in 24h
        top_country = conn.execute(
            """
            SELECT g.country_code AS cc, MAX(g.country) AS country,
                   COUNT(*) AS bans, COUNT(DISTINCT d.value) AS uniq
            FROM decisions d
            JOIN geo_cache g ON g.ip = d.value
            WHERE d.last_seen_at > datetime('now', '-1 day')
              AND g.country_code IS NOT NULL AND g.country_code != ''
            GROUP BY g.country_code ORDER BY bans DESC LIMIT 15
            """
        ).fetchall()
        # Country × hour heat
        heat_country_rows = conn.execute(
            """
            SELECT g.country_code AS cc,
                   CAST(strftime('%H', d.last_seen_at) AS INTEGER) AS hr,
                   COUNT(*) AS n
            FROM decisions d JOIN geo_cache g ON g.ip = d.value
            WHERE d.last_seen_at > datetime('now', '-7 days')
              AND g.country_code IS NOT NULL AND g.country_code != ''
            GROUP BY g.country_code, hr
            """
        ).fetchall()
        # ASN × scenario heat (top 12 of each)
        heat_asn_rows = conn.execute(
            """
            SELECT asn, MAX(as_org) AS as_org, scenario, COUNT(*) AS n
            FROM decisions
            WHERE last_seen_at > datetime('now', '-7 days')
              AND asn IS NOT NULL AND asn != ''
              AND scenario IS NOT NULL AND scenario != ''
            GROUP BY asn, scenario
            """
        ).fetchall()
    finally:
        conn.close()

    # KPIs
    countries_24h = len({r["cc"] for r in top_country})
    asns_24h = len({r["asn"] for r in top_asn})
    top_country_label = top_country[0]["cc"] if top_country else ""
    top_asn_label = top_asn[0]["asn"] if top_asn else ""
    top_asn_org = top_asn[0]["as_org"] if top_asn else ""
    kpis = {
        "countries": countries_24h, "asns": asns_24h,
        "top_country": top_country_label,
        "top_asn": top_asn_label, "top_asn_org": top_asn_org,
    }

    # Country × hour heatmap
    country_cells: dict[str, list[int]] = {}
    for r in heat_country_rows:
        country_cells.setdefault(r["cc"], [0] * 24)[r["hr"]] = r["n"]
    sorted_cc = sorted(country_cells.items(), key=lambda kv: -sum(kv[1]))[:18]
    grand_max = max((max(cells) for _cc, cells in sorted_cc), default=1)
    heat_country = []
    for cc, cells in sorted_cc:
        levels = [0 if v == 0 else min(6, max(1, int(round(v / grand_max * 6)))) for v in cells]
        heat_country.append({"cc": cc, "cells": cells, "levels": levels})

    # ASN × scenario heatmap
    asn_set: dict[str, int] = {}
    scen_set: dict[str, int] = {}
    for r in heat_asn_rows:
        asn_set[r["asn"]] = asn_set.get(r["asn"], 0) + r["n"]
        scen_set[r["scenario"]] = scen_set.get(r["scenario"], 0) + r["n"]
    top_asn_list = [k for k, _ in sorted(asn_set.items(), key=lambda kv: -kv[1])[:12]]
    top_scen_list = [k for k, _ in sorted(scen_set.items(), key=lambda kv: -kv[1])[:12]]
    asn_org_lookup = {r["asn"]: r["as_org"] for r in heat_asn_rows}
    cell_map: dict[tuple[str, str], int] = {(r["asn"], r["scenario"]): r["n"] for r in heat_asn_rows}
    max_cell = max(cell_map.values(), default=1)
    heat_asn = []
    for asn_v in top_asn_list:
        row = []
        for scen in top_scen_list:
            v = cell_map.get((asn_v, scen), 0)
            lvl = 0 if v == 0 else min(6, max(1, int(round(v / max_cell * 6))))
            row.append((v, lvl))
        heat_asn.append({"asn": asn_v, "as_org": asn_org_lookup.get(asn_v, ""), "row": row})

    return render_template(
        "intel.html",
        kpis=kpis,
        top_asn_rows=[dict(r) for r in top_asn],
        top_country_rows=[dict(r) for r in top_country],
        heat_country=heat_country,
        heat_asn=heat_asn,
        heat_scens=top_scen_list,
        active="intel",
    )


@app.route("/federation")
@login_required
def federation_page():
    from datetime import datetime as _dt, timezone as _tz
    sources_raw = federation.list_sources(include_disabled=True)
    now = _dt.now(_tz.utc)
    # Build per-source dashboard view
    conn = get_conn()
    try:
        # Per-source counts: live + 7d total + unique
        contrib_rows = conn.execute(
            """
            SELECT origin_source, COUNT(*) AS n
            FROM decisions WHERE deleted_at IS NULL
            GROUP BY origin_source
            """
        ).fetchall()
        contrib = {r["origin_source"]: r["n"] for r in contrib_rows}

        # IP × source matrix data
        ip_src_rows = conn.execute(
            "SELECT ip, source_name FROM ip_sources "
            "WHERE last_seen_at > datetime('now', '-7 days')"
        ).fetchall()

        # Active distinct count (union)
        active_total = conn.execute(
            "SELECT COUNT(DISTINCT value) FROM decisions WHERE deleted_at IS NULL"
        ).fetchone()[0]

        # 2+ source agreement
        agree_2plus = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT ip FROM ip_sources
                WHERE last_seen_at > datetime('now', '-7 days')
                GROUP BY ip HAVING COUNT(DISTINCT source_name) >= 2
            )
            """
        ).fetchone()[0]
    finally:
        conn.close()

    sources_view = []
    healthy = paused = failing = 0
    for s in sources_raw:
        backoff_active = False
        if s.backoff_until:
            try:
                backoff_active = _dt.fromisoformat(s.backoff_until.replace("Z", "+00:00")) > now
            except ValueError:
                backoff_active = False
        ok = (not s.last_error) and (not backoff_active) and (not s.paused)
        if s.paused:
            paused += 1
        elif s.last_error:
            failing += 1
        elif ok:
            healthy += 1
        contribution = contrib.get(s.name, 0)
        sources_view.append({
            "id": s.id,
            "name": s.name,
            "url": s.url,
            "paused": s.paused,
            "error": s.last_error if not s.paused else "",
            "healthy": ok,
            "backoff_active": backoff_active,
            "last_pull_rel": rel_time(s.last_pull_at),
            "last_pull_ms": s.last_pull_ms,  # phase 88 latency display
            "contribution": contribution,
            "confidence": s.confidence,
        })

    confidence_threshold = int(get_setting("federation.confidence_threshold") or "1")
    kpis = {
        "total_sources": len(sources_raw),
        "healthy": healthy, "paused": paused, "failing": failing,
        "active_total": active_total,
        "agreed_2plus": agree_2plus,
        "confidence_threshold": confidence_threshold,
    }

    # Overlap matrix: count of IPs both A and B have seen
    names = [s.name for s in sources_raw if not s.paused]
    matrix_data = {"sources": names, "rows": []}
    if len(names) > 1:
        # Build per-source IP set
        per_source: dict[str, set[str]] = {n: set() for n in names}
        for r in ip_src_rows:
            if r["source_name"] in per_source:
                per_source[r["source_name"]].add(r["ip"])
        max_v = 1
        cells: list[list[tuple[int, int, int]]] = []
        for i, a in enumerate(names):
            row = []
            for j, b in enumerate(names):
                if i == j:
                    v = len(per_source[a])
                else:
                    v = len(per_source[a] & per_source[b])
                if v > max_v:
                    max_v = v
                row.append((j, v, 0))
            cells.append(row)
        # Quantize each cell into a level 1-4
        out_rows = []
        for i, row in enumerate(cells):
            new_row = []
            for j, v, _lvl in row:
                if i == j or v == 0:
                    lvl = 0
                else:
                    lvl = min(4, max(1, int(round(v / max_v * 4))))
                new_row.append((j, v, lvl))
            out_rows.append((i, new_row))
        matrix_data["rows"] = out_rows

    # Scorecards
    scorecards = []
    for s in sources_view:
        ips_this = {r["ip"] for r in ip_src_rows if r["source_name"] == s["name"]}
        ips_other = {r["ip"] for r in ip_src_rows if r["source_name"] != s["name"]}
        unique_n = len(ips_this - ips_other)
        shared_n = len(ips_this & ips_other)
        total_n = len(ips_this)
        redundancy = int(shared_n * 100 / total_n) if total_n else 0
        recommendation = ""
        if total_n >= 500 and redundancy >= 90:
            recommendation = "Highly redundant — most IPs already covered by other sources. Consider pausing."
        elif total_n >= 100 and unique_n / max(1, total_n) >= 0.6:
            recommendation = "Highly complementary — contributes mostly unique IPs."
        # Health pct: rough — 100 if no last_error, else 50
        scorecards.append({
            "name": s["name"], "url": s["url"], "confidence": s["confidence"],
            "total": total_n, "unique": unique_n, "shared": shared_n,
            "redundancy_pct": redundancy,
            "health_pct": 100 if not s["error"] else 50,
            "recommendation": recommendation,
        })

    return render_template(
        "federation.html",
        sources=sources_view,
        kpis=kpis,
        matrix=matrix_data,
        scorecards=scorecards,
        mt_list_name=address_list_name(),
        active="federation",
    )


@app.route("/federation/add", methods=["GET", "POST"])
@login_required
@role_required("operator")
def federation_add():
    # GET renders the phase-81 wizard (3 steps). `?advanced=1` falls back
    # to the single one-shot form for operators who already know all the
    # values. The POST handler is shared so both forms write through the
    # same code path.
    if request.method == "GET":
        if request.args.get("advanced"):
            return render_template("federation_add_advanced.html")
        # Best-effort: surface our own WG/private IP in the bash block so
        # the operator doesn't have to look it up. Falls back to a
        # placeholder if we can't find one.
        protek_host_ip = _detect_private_ip()
        return render_template("federation_add.html",
                               protek_host_ip=protek_host_ip)
    name = (request.form.get("name") or "").strip()
    url = (request.form.get("url") or "").strip()
    api_key = (request.form.get("api_key") or "").strip()
    try:
        confidence = max(1, min(10, int(request.form.get("confidence", "1"))))
    except ValueError:
        confidence = 1
    if not (name and url and api_key):
        flash("name + url + api_key are all required.", "error")
        return redirect(url_for("federation_page"))
    if not name.replace("-", "").replace("_", "").isalnum():
        flash("name must be alphanumeric (plus _ and -).", "error")
        return redirect(url_for("federation_page"))
    # Health probe before save. Phase 84 — run the structured ladder
    # alongside the legacy single-shot probe so failure messages can
    # name the failing rung instead of just "Connection failed: …".
    probe = federation.test_connection(url, api_key)
    if not probe.get("ok"):
        try:
            import diagnostic
            rows = diagnostic.diagnose_url(url, api_key=api_key)
            summary = diagnostic.summary(rows)
            detail = summary["headline"]
            if summary["fail_hint"]:
                detail += f" — {summary['fail_hint']}"
        except Exception:  # noqa: BLE001
            detail = probe.get("error") or "unknown"
        flash(f"Connection failed: {detail}", "error")
        return redirect(url_for("federation_page"))
    try:
        federation.add_source(name=name, url=url, api_key=api_key, confidence=confidence)
        flash(f"Source '{name}' added — bootstrap will begin on next cycle.", "info")
        _audit("federation.add", target=name,
               after={"name": name, "url": url, "confidence": confidence})
    except Exception as e:  # noqa: BLE001
        flash(f"Could not save source: {e}", "error")
    return redirect(url_for("federation_page"))


@app.route("/federation/action", methods=["POST"])
@login_required
@role_required("operator")
def federation_action():
    try:
        source_id = int(request.form.get("source_id", "0"))
    except ValueError:
        flash("invalid source id", "error")
        return redirect(url_for("federation_page"))
    action = (request.form.get("action") or "").strip()
    try:
        if action == "pause":
            federation.set_paused(source_id, True)
        elif action == "unpause":
            federation.set_paused(source_id, False)
        elif action == "delete":
            federation.delete_source(source_id)
        elif action == "enable":
            federation.set_enabled(source_id, True)
        elif action == "disable":
            federation.set_enabled(source_id, False)
        else:
            flash("unknown action", "error")
            return redirect(url_for("federation_page"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("federation_page"))
    flash(f"source {action} applied", "info")
    _audit(f"federation.{action}", target=f"id={source_id}")
    return redirect(url_for("federation_page"))


@app.route("/federation/threshold", methods=["POST"])
@login_required
@role_required("operator")
def federation_set_threshold():
    before = int(get_setting("federation.confidence_threshold") or "1")
    try:
        t = max(1, min(10, int(request.form.get("threshold", "1"))))
    except ValueError:
        t = 1
    set_setting("federation.confidence_threshold", str(t))
    flash(f"Confidence threshold set to {t}.", "info")
    _audit("federation.threshold", before={"threshold": before}, after={"threshold": t})
    return redirect(url_for("federation_page"))


# ── CrowdSec LAPI explorer ─────────────────────────────────────────────────
# This is an authenticated reverse-proxy from Protek to the local LAPI. The
# bouncer key never leaves the server; the user's browser only ever talks to
# protek.syedhashmi.trade with Protek's session cookie. Read-only — writes
# still go through cscli on the VPS shell.

CROWDSEC_ENDPOINTS = [
    {"method": "GET", "path": "/v1/decisions",
     "qs": "type=ban&scope=Ip", "auth": "bouncer",
     "desc": "Full active snapshot of bans (IP scope)"},
    {"method": "GET", "path": "/v1/decisions",
     "qs": "scope=Range", "auth": "bouncer",
     "desc": "CIDR-range bans"},
    {"method": "GET", "path": "/v1/decisions/stream",
     "qs": "startup=true", "auth": "bouncer",
     "desc": "Delta-stream snapshot (entire active set on startup=true)"},
    {"method": "GET", "path": "/v1/alerts",
     "qs": "limit=50", "auth": "machine",
     "desc": "Rich event context — needs machine credentials, will 401 with bouncer key"},
    {"method": "GET", "path": "/v1/bouncers",
     "qs": "", "auth": "machine",
     "desc": "Registered bouncers (machine-only)"},
    {"method": "GET", "path": "/v1/machines",
     "qs": "", "auth": "machine",
     "desc": "Registered machines/agents (machine-only)"},
]


@app.route("/crowdsec")
@login_required
def crowdsec_page():
    if not lapi_client:
        return render_template("crowdsec.html",
                               lapi_url=LAPI_URL,
                               lapi_ok=False,
                               summary={"decisions": 0, "bouncers": 0, "has_machine": False},
                               endpoints=CROWDSEC_ENDPOINTS,
                               sample_json="",
                               active="crowdsec")
    # Cheap health + sample.
    health = lapi_client.health()
    lapi_ok = bool(health.get("ok"))
    decisions_count = 0
    sample_json = ""
    if lapi_ok:
        try:
            sample = lapi_client.decisions()
            decisions_count = len(sample)
            # Just the first 10 for the preview.
            import json as _json
            sample_json = _json.dumps(sample[:10], indent=2)
        except Exception as e:  # noqa: BLE001
            sample_json = f"// error: {e}"
    summary = {
        "decisions": decisions_count,
        "bouncers": 1,  # at minimum, Protek itself
        "has_machine": False,
    }
    return render_template("crowdsec.html",
                           lapi_url=LAPI_URL,
                           lapi_ok=lapi_ok,
                           summary=summary,
                           endpoints=CROWDSEC_ENDPOINTS,
                           sample_json=sample_json,
                           active="crowdsec")


@app.route("/crowdsec/api/<path:path>")
@login_required
def crowdsec_proxy(path: str):
    """Authenticated GET proxy to LAPI. Only GETs — never accepts writes."""
    import json as _json
    import time as _time
    if not lapi_client:
        return render_template("crowdsec_proxy.html",
                               method="GET", path="/" + path, qs="",
                               status=503, duration_ms=0, size=0,
                               error="LAPI client not configured (CROWDSEC_BOUNCER_KEY unset).",
                               body=""), 503

    # Reject anything that isn't under /v1/ to keep this from becoming a general proxy.
    if not path.startswith("v1/"):
        abort(404)

    full_path = "/" + path
    qs = request.query_string.decode() if request.query_string else ""

    t0 = _time.monotonic()
    try:
        import requests
        url = f"{LAPI_URL.rstrip('/')}{full_path}"
        params = dict(request.args)
        r = requests.get(
            url,
            headers={"X-Api-Key": LAPI_KEY, "Accept": "application/json",
                     "User-Agent": "protek-explorer/1.0"},
            params=params,
            timeout=15,
        )
        duration_ms = int((_time.monotonic() - t0) * 1000)
        body_text = r.text or ""
        # Try to pretty-print JSON; fall back to raw text.
        try:
            body_text = _json.dumps(r.json(), indent=2)
        except Exception:  # noqa: BLE001
            pass
        # Cap body size to keep template render cheap.
        if len(body_text) > 200_000:
            body_text = body_text[:200_000] + "\n\n... (truncated at 200KB)"
        return render_template("crowdsec_proxy.html",
                               method="GET", path=full_path, qs=qs,
                               status=r.status_code, duration_ms=duration_ms,
                               size=len(r.content or b""),
                               error="" if r.status_code < 400 else f"HTTP {r.status_code}",
                               body=body_text), r.status_code
    except Exception as e:  # noqa: BLE001
        duration_ms = int((_time.monotonic() - t0) * 1000)
        return render_template("crowdsec_proxy.html",
                               method="GET", path=full_path, qs=qs,
                               status=599, duration_ms=duration_ms, size=0,
                               error=f"network error: {e}",
                               body=""), 599


# ── Notifications / Settings / Security pages ─────────────────────────────

@app.route("/notifications", methods=["GET", "POST"])
@login_required
@role_required("operator")
def notifications_page():
    import notifications as notif
    if request.method == "POST":
        form_section = request.form.get("section", "toggles")

        # ── Credentials submission (one channel at a time) ─────────────────
        if form_section == "credentials":
            channel = (request.form.get("channel") or "").strip()
            schema = notif.CREDENTIAL_SCHEMA.get(channel)
            if not schema:
                flash("unknown channel", "error")
                return redirect(url_for("notifications_page"))
            changed: list[str] = []
            for f in schema:
                field = f["field"]
                form_key = f"cred_{channel}_{field}"
                if form_key not in request.form:
                    continue
                new_value = (request.form.get(form_key) or "").strip()
                # Secret + blank input means "keep current" — do NOT clear.
                if f.get("secret") and new_value == "":
                    continue
                old_value = notif.get_credential(channel, field)
                if new_value != old_value:
                    notif.set_credential(channel, field, new_value)
                    changed.append(field)
            if changed:
                # Audit log records WHICH fields changed; never the values.
                _audit("notify.credentials",
                       target=channel,
                       after={"channel": channel, "fields_changed": changed})
                flash(f"{channel.title()} credentials updated ({', '.join(changed)}).", "info")
            else:
                flash(f"No changes to {channel.title()} credentials.", "info")
            return redirect(url_for("notifications_page"))

        # ── Toggles + thresholds submission ────────────────────────────────
        for ev in notif.EVENTS:
            for ch in notif.CHANNELS:
                val = request.form.get(f"toggle_{ch}_{ev}") == "on"
                notif.set_event_enabled(ch, ev, val)
            tval = request.form.get(f"threshold_{ev}")
            if tval is not None and tval.strip():
                try:
                    from db import set_setting
                    set_setting(f"notify.threshold.{ev}", str(int(tval)))
                except ValueError:
                    pass
        _audit("notify.toggles", note="per-event/channel toggles saved")
        flash("Notification settings saved.", "info")
        return redirect(url_for("notifications_page"))

    # ── Render ────────────────────────────────────────────────────────────
    channels = {}
    for ch in notif.CHANNELS:
        schema = notif.CREDENTIAL_SCHEMA.get(ch, [])
        channels[ch] = {
            "configured": notif.channel_configured(ch),
            "fields": [
                {
                    "field": f["field"],
                    "label": f["label"],
                    "placeholder": f.get("placeholder", ""),
                    "secret": f.get("secret", False),
                    "display": notif.mask_credential(ch, f["field"]),
                    "raw": "" if f.get("secret") else notif.get_credential(ch, f["field"]),
                    "is_set": bool(notif.get_credential(ch, f["field"])),
                }
                for f in schema
            ],
        }
    events = []
    threshold_events = {"sync_threshold": 50, "new_ban": 5}
    for ev in notif.EVENTS:
        events.append({
            "name": ev,
            "toggles": {ch: notif.is_event_enabled(ch, ev) for ch in notif.CHANNELS},
            "threshold_default": ev in threshold_events,
            "threshold": notif.get_threshold(ev, threshold_events.get(ev, 0)),
        })
    return render_template("notifications.html",
                           channels=channels,
                           channel_names=list(notif.CHANNELS.keys()),
                           events=events,
                           active="notifications")


@app.route("/notifications/test", methods=["POST"])
@login_required
@role_required("operator")
def notifications_test():
    import notifications as notif
    ch = (request.form.get("channel") or "").strip()
    result = notif.test_channel(ch)
    if result.get("ok"):
        flash(f"Test sent via {ch}.", "info")
    else:
        flash(f"Test failed for {ch}: {result.get('error')}", "error")
    return redirect(url_for("notifications_page"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
@role_required("operator")
def settings_page():
    from db import set_setting
    if request.method == "POST":
        # Persist runtime-tunable knobs. .env stays the source of truth for
        # secrets only; these override .env on the next reconcile cycle.
        before_snapshot = {
            "sync_interval_sec": _setting_int("settings.sync_interval_sec", SYNC_INTERVAL),
            "batch_cap": _setting_int("settings.batch_cap", BATCH_CAP),
            "mt_address_list": get_setting("settings.mt_address_list") or address_list_name(),
            "dry_run": (get_setting("settings.dry_run") or ("1" if DRY_RUN else "0")) == "1",
        }
        try:
            sync_interval = max(2, min(3600, int(request.form.get("sync_interval_sec", str(SYNC_INTERVAL)))))
        except ValueError:
            sync_interval = SYNC_INTERVAL
        try:
            batch_cap = max(1, min(10000, int(request.form.get("batch_cap", str(BATCH_CAP)))))
        except ValueError:
            batch_cap = BATCH_CAP
        addr_list = (request.form.get("mt_address_list") or address_list_name()).strip()
        dry = (request.form.get("dry_run", "true").lower() in ("1", "true", "yes"))
        atom_url = (request.form.get("atom_url") or "").strip()
        othoni_url = (request.form.get("othoni_url") or "").strip()
        set_setting("settings.sync_interval_sec", str(sync_interval))
        set_setting("settings.batch_cap", str(batch_cap))
        set_setting("settings.mt_address_list", addr_list)
        set_setting("settings.dry_run", "1" if dry else "0")
        set_setting("integrations.atom_url", atom_url)
        set_setting("integrations.othoni_url", othoni_url)
        # Apply to live poller if owned by this worker
        if poller:
            poller.interval = sync_interval
            poller.batch_cap = batch_cap
            poller.dry_run = dry
        after_snapshot = {
            "sync_interval_sec": sync_interval,
            "batch_cap": batch_cap,
            "mt_address_list": addr_list,
            "dry_run": dry,
        }
        _audit("settings.update", before=before_snapshot, after=after_snapshot)
        flash("Settings saved. Active on next reconcile cycle.", "info")
        return redirect(url_for("settings_page"))

    ps = poller_status()
    lapi_key = LAPI_KEY or ""
    values = {
        "sync_interval_sec": _setting_int("settings.sync_interval_sec", SYNC_INTERVAL),
        "batch_cap": _setting_int("settings.batch_cap", BATCH_CAP),
        "mt_address_list": get_setting("settings.mt_address_list") or address_list_name(),
        "dry_run": (get_setting("settings.dry_run") or ("1" if DRY_RUN else "0")) == "1",
        "lapi_url": LAPI_URL,
        "lapi_key_tail": lapi_key[-4:] if lapi_key else "",
        "mt_host": _envstr("MT_HOST", ""),
        "mt_port": _envint("MT_PORT", 8728),
        "mt_use_ssl": _envstr("MT_USE_SSL", "false").lower() in ("1", "true", "yes"),
        "last_poll_rel": rel_time(ps["last_at"]),
        "active_total": ps["active_total"],
        "atom_url": get_setting("integrations.atom_url") or _envstr("ATOM_URL", ""),
        "othoni_url": get_setting("integrations.othoni_url") or _envstr("OTHONI_URL", ""),
    }
    return render_template("settings.html", values=values, active="settings")


def _setting_int(key: str, default: int) -> int:
    v = get_setting(key)
    try:
        return int(v) if v else default
    except (ValueError, TypeError):
        return default


@app.route("/security")
@login_required
def security_page():
    conn = get_conn()
    try:
        success_24h = conn.execute(
            "SELECT COUNT(*) FROM login_audit WHERE success = 1 AND created_at > datetime('now', '-1 day')"
        ).fetchone()[0]
        fail_24h = conn.execute(
            "SELECT COUNT(*) FROM login_audit WHERE success = 0 AND created_at > datetime('now', '-1 day')"
        ).fetchone()[0]
        audit_rows = conn.execute(
            "SELECT created_at, ip, username, success, reason FROM login_audit ORDER BY id DESC LIMIT 50"
        ).fetchall()
        locked_rows = conn.execute(
            "SELECT ip, attempts, locked_until FROM login_attempts "
            "WHERE locked_until IS NOT NULL AND locked_until > datetime('now') "
            "ORDER BY locked_until DESC"
        ).fetchall()
    finally:
        conn.close()
    whitelist = _envstr("IP_WHITELIST", "")
    stats = {
        "success_24h": success_24h,
        "fail_24h": fail_24h,
        "locked_now": len(locked_rows),
        "whitelist_on": bool(whitelist),
        "whitelist": whitelist or "all IPs allowed",
        "session_timeout": _envint("SESSION_TIMEOUT_MIN", 30),
        "max_attempts": _envint("MAX_LOGIN_ATTEMPTS", 5),
        "lockout_minutes": _envint("LOCKOUT_MINUTES", 15),
    }
    audit = [
        {"rel": rel_time(r["created_at"]), "ip": r["ip"], "username": r["username"],
         "success": bool(r["success"]), "reason": r["reason"] or ""}
        for r in audit_rows
    ]
    locked = [
        {"ip": r["ip"], "attempts": r["attempts"], "until_rel": rel_time(r["locked_until"])}
        for r in locked_rows
    ]
    return render_template("security.html", stats=stats, audit=audit, locked=locked, active="security")


@app.route("/security/unlock", methods=["POST"])
@login_required
@role_required("operator")
def security_unlock():
    conn = get_conn()
    try:
        conn.execute("UPDATE login_attempts SET locked_until = NULL, attempts = 0")
    finally:
        conn.close()
    flash("All IP locks cleared.", "info")
    _audit("security.unlock_all")
    return redirect(url_for("security_page"))


# ── MikroTik quick-cache (avoid hammering the router on every pageview) ─────

_MT_CACHE: dict[str, object] = {"at": None, "ok": False, "count": None}


def _mt_quick_ok() -> bool:
    """Return cached health; refresh at most once per 30s."""
    now = datetime.now(timezone.utc)
    last = _MT_CACHE.get("at")
    if last and (now - last).total_seconds() < 30:
        return bool(_MT_CACHE.get("ok"))
    mt = MikroTik()
    if not mt.is_configured():
        _MT_CACHE.update({"at": now, "ok": False, "count": None})
        return False
    try:
        entries = mt.get_address_list(address_list_name())
        _MT_CACHE.update({"at": now, "ok": True, "count": len(entries)})
        return True
    except Exception:  # noqa: BLE001
        _MT_CACHE.update({"at": now, "ok": False, "count": None})
        return False


def _cached_mt_count() -> int | None:
    _mt_quick_ok()
    val = _MT_CACHE.get("count")
    return val if isinstance(val, int) else None


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8090, debug=False)
