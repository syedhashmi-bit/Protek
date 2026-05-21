"""
notifications.py — Discord / Telegram / SMTP fan-out, lifted in shape from
pipsqueeze and adapted for CrowdSec ban events.

Event types Protek emits:
    new_ban             one or more new decisions hit the local mirror
    sync_threshold      a reconcile cycle added more than N entries
    sync_error          a reconcile cycle reported errors
    lapi_down           the LAPI poll failed
    mt_down             the MikroTik adapter reported unreachable
    login_failure       a failed login attempt
    login_locked        an IP got rate-limit-locked
    hourly_digest       summary roll-up
    daily_digest        summary roll-up

Per-event channel toggles live in the `notifications` table — one row per
channel × event pair. Channel credentials live in env (DISCORD_WEBHOOK,
TELEGRAM_BOT_TOKEN/CHAT_ID, SMTP_*) and never leave the box.

All network sends are wrapped in try/except — a notification failure must
never crash the reconcile thread.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import socket
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

import requests

from db import get_conn, get_setting

log = logging.getLogger("protek.notify")

EVENTS = [
    "new_ban",
    "sync_threshold",
    "sync_error",
    "lapi_down",
    "mt_down",
    "login_failure",
    "login_locked",
    "hourly_digest",
    "daily_digest",
]


# ── env helpers ─────────────────────────────────────────────────────────────

def _envstr(name: str, default: str = "") -> str:
    raw = os.environ.get(name, default) or ""
    return raw.split("#", 1)[0].strip()


def _envint(name: str, default: int) -> int:
    v = _envstr(name, "")
    try:
        return int(v) if v else default
    except ValueError:
        return default


# ── credential storage (settings table first, .env as boot fallback) ────────
#
# Schema drives the /notifications credentials UI. `secret=True` fields are
# only ever returned masked to the UI and only saved when the operator
# submits a non-empty replacement (blank = keep current). Non-secret fields
# accept blank as a real clear.

CREDENTIAL_SCHEMA: dict[str, list[dict[str, Any]]] = {
    "discord": [
        {"field": "webhook", "env": "DISCORD_WEBHOOK", "secret": True,
         "label": "Webhook URL",
         "placeholder": "https://discord.com/api/webhooks/..."},
    ],
    "telegram": [
        {"field": "bot_token", "env": "TELEGRAM_BOT_TOKEN", "secret": True,
         "label": "Bot token", "placeholder": "123456:ABCdef..."},
        {"field": "chat_id", "env": "TELEGRAM_CHAT_ID", "secret": False,
         "label": "Chat ID", "placeholder": "-1001234567890 or @yourchannel"},
    ],
    "email": [
        {"field": "smtp_host", "env": "SMTP_HOST", "secret": False,
         "label": "SMTP host", "placeholder": "smtp.example.com"},
        {"field": "smtp_port", "env": "SMTP_PORT", "secret": False,
         "label": "SMTP port", "placeholder": "587 (STARTTLS) or 465 (SSL)"},
        {"field": "smtp_user", "env": "SMTP_USERNAME", "secret": False,
         "label": "SMTP username", "placeholder": "user@example.com"},
        {"field": "smtp_password", "env": "SMTP_PASSWORD", "secret": True,
         "label": "SMTP password", "placeholder": ""},
        {"field": "smtp_from", "env": "SMTP_FROM", "secret": False,
         "label": "From address", "placeholder": "alerts@example.com"},
        {"field": "smtp_to", "env": "SMTP_TO", "secret": False,
         "label": "To address", "placeholder": "ops@example.com"},
    ],
}


def _cred_key(channel: str, field: str) -> str:
    return f"notify.cred.{channel}.{field}"


def get_credential(channel: str, field: str) -> str:
    """Settings table first, .env as boot fallback. Returns plaintext —
    callers MUST NOT echo back to the UI for secrets (use mask_credential)."""
    spec = _spec(channel, field)
    if spec is None:
        return ""
    v = get_setting(_cred_key(channel, field))
    if v is not None and v != "":
        return v
    return _envstr(spec["env"], "")


def set_credential(channel: str, field: str, value: str) -> None:
    """Persist a credential override. Empty value clears the override (falls
    back to .env on next read). Caller is responsible for the secret-vs-clear
    semantics — this function just writes what it's given."""
    from db import set_setting
    spec = _spec(channel, field)
    if spec is None:
        return
    set_setting(_cred_key(channel, field), value or "")


def mask_credential(channel: str, field: str) -> str:
    """UI-safe display string for a credential.
    - Secrets: '•••• xxxx' showing last 4 chars (or '(unset)').
    - Non-secrets: the full value (the operator just typed it; not really secret)."""
    spec = _spec(channel, field)
    v = get_credential(channel, field)
    if not v:
        return "(unset)"
    if spec and spec.get("secret"):
        return "•••• " + (v[-4:] if len(v) >= 4 else "••")
    return v


def _spec(channel: str, field: str) -> dict[str, Any] | None:
    for f in CREDENTIAL_SCHEMA.get(channel, []):
        if f["field"] == field:
            return f
    return None


# ── per-event toggle storage (settings table, keyed channel.event) ──────────
# Default is OFF except for sync_error, lapi_down, mt_down, login_locked.
DEFAULTS = {
    "new_ban": False,
    "sync_threshold": True,
    "sync_error": True,
    "lapi_down": True,
    "mt_down": True,
    "login_failure": False,
    "login_locked": True,
    "hourly_digest": False,
    "daily_digest": True,
}


def is_event_enabled(channel: str, event: str) -> bool:
    key = f"notify.{channel}.{event}"
    v = get_setting(key)
    if v is None:
        return DEFAULTS.get(event, False)
    return v in ("1", "true", "yes")


def set_event_enabled(channel: str, event: str, on: bool) -> None:
    from db import set_setting
    set_setting(f"notify.{channel}.{event}", "1" if on else "0")


def get_threshold(event: str, default: int) -> int:
    v = get_setting(f"notify.threshold.{event}")
    try:
        return int(v) if v else default
    except (ValueError, TypeError):
        return default


# ── channel sends ───────────────────────────────────────────────────────────

def _send_discord(message: str, subject: str | None = None) -> tuple[bool, str]:
    url = get_credential("discord", "webhook")
    if not url:
        return False, "Discord webhook not set"
    # Basic SSRF guard — must be discord.com or discordapp.com host
    if not url.startswith(("https://discord.com/", "https://discordapp.com/",
                            "https://ptb.discord.com/", "https://canary.discord.com/")):
        return False, "invalid Discord webhook host"
    body = message if not subject else f"**[Protek] {subject}**\n{message}"
    try:
        r = requests.post(url, json={"content": body[:1900]}, timeout=8)
        if r.status_code in (200, 204):
            return True, ""
        return False, f"discord {r.status_code}: {r.text[:200]}"
    except Exception as e:  # noqa: BLE001
        return False, f"discord error: {e}"


def _send_telegram(message: str, subject: str | None = None) -> tuple[bool, str]:
    token = get_credential("telegram", "bot_token")
    chat_id = get_credential("telegram", "chat_id")
    if not token or not chat_id:
        return False, "Telegram bot_token / chat_id not set"
    text = message if not subject else f"<b>[Protek] {subject}</b>\n{message}"
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text[:3800], "parse_mode": "HTML"},
            timeout=8,
        )
        j = r.json() if r.content else {}
        if r.status_code == 200 and j.get("ok"):
            return True, ""
        return False, f"telegram {r.status_code}: {j.get('description', r.text[:200])}"
    except Exception as e:  # noqa: BLE001
        return False, f"telegram error: {e}"


def _send_email(message: str, subject: str | None = None) -> tuple[bool, str]:
    host = get_credential("email", "smtp_host")
    if not host:
        return False, "SMTP host not set"
    if _smtp_host_is_internal(host):
        return False, "SMTP host rejected as internal/private network"
    try:
        port = int(get_credential("email", "smtp_port") or "587")
    except ValueError:
        port = 587
    user = get_credential("email", "smtp_user")
    pw = get_credential("email", "smtp_password")
    sender = get_credential("email", "smtp_from") or user
    to_addr = get_credential("email", "smtp_to") or sender
    if not (user and sender and to_addr):
        return False, "SMTP credentials incomplete"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Protek] {subject or 'notification'}"
    msg["From"] = sender
    msg["To"] = to_addr
    msg.attach(MIMEText(message, "plain"))
    try:
        if port == 465:
            s = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            s = smtplib.SMTP(host, port, timeout=10)
            s.ehlo()
            s.starttls()
            s.ehlo()
        if user and pw:
            s.login(user, pw)
        s.sendmail(sender, [to_addr], msg.as_string())
        s.quit()
        return True, ""
    except Exception as e:  # noqa: BLE001
        return False, f"smtp error: {e}"


def _smtp_host_is_internal(host: str) -> bool:
    """Best-effort SSRF guard — reject hosts that resolve to private networks."""
    import ipaddress
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError):
            continue
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
            return True
    return False


CHANNELS = {
    "discord": _send_discord,
    "telegram": _send_telegram,
    "email": _send_email,
}


def channel_configured(channel: str) -> bool:
    """Whether the channel has the credentials it needs to send at all.
    Reads from settings first (UI-editable) then .env (boot fallback)."""
    if channel == "discord":
        return bool(get_credential("discord", "webhook"))
    if channel == "telegram":
        return bool(get_credential("telegram", "bot_token")) and bool(get_credential("telegram", "chat_id"))
    if channel == "email":
        return (bool(get_credential("email", "smtp_host"))
                and bool(get_credential("email", "smtp_user"))
                and bool(get_credential("email", "smtp_from")))
    return False


# ── dispatch ────────────────────────────────────────────────────────────────

def send(event: str, message: str, subject: str | None = None) -> list[dict[str, Any]]:
    """Fan out to every configured + enabled channel for this event.

    Returns a list of {channel, ok, error} dicts for each attempt.
    """
    results: list[dict[str, Any]] = []
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    suffix = f"\n— {timestamp}"
    for ch, fn in CHANNELS.items():
        if not channel_configured(ch):
            continue
        if not is_event_enabled(ch, event):
            continue
        ok, err = fn(message + suffix, subject=subject or event)
        results.append({"channel": ch, "ok": ok, "error": err})
        if not ok:
            log.warning("notify %s/%s failed: %s", ch, event, err)
    return results


def test_channel(channel: str) -> dict[str, Any]:
    """Send a one-off test message via a specific channel (ignores toggles)."""
    fn = CHANNELS.get(channel)
    if not fn:
        return {"channel": channel, "ok": False, "error": "unknown channel"}
    if not channel_configured(channel):
        return {"channel": channel, "ok": False, "error": "channel not configured"}
    ok, err = fn(f"Test notification from Protek ({channel}). If you see this, it's working.", subject="test")
    return {"channel": channel, "ok": ok, "error": err}
