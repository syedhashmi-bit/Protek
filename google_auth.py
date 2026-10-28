"""
google_auth.py — "Sign in with Google", the same model as Othoni and RiMM.

Standard OIDC authorization-code flow against Google, on the Authlib client
that oidc.py already depends on:

  GET /auth/google           → Google's account chooser, carrying a random
                               `state` (kept in the signed session cookie, so
                               it is bound to this browser), a `nonce` (bound
                               into the ID token) and a PKCE S256 challenge
  GET /auth/google/callback  → code swapped for an ID token server-to-server;
                               Authlib checks its signature against Google's
                               published keys, its audience, expiry and nonce,
                               and we check the issuer and `email_verified`

Who gets in is env-only — an allowlist of Google account emails per role:

  GOOGLE_ADMIN_EMAILS     comma-separated → admin
  GOOGLE_OPERATOR_EMAILS  comma-separated → operator
  GOOGLE_VIEWER_EMAILS    comma-separated → viewer

Any other account, even a valid, verified Google login, is turned away. An
email listed under two roles gets the higher one. The allowlist is re-read on
every request (app._revalidate_session), so dropping an email and restarting
signs that person out on their next click — a demotion likewise lands at once.

TOTP is skipped for Google users: 2-Step Verification on the Google account
is the second factor, as in the sibling apps. Break-glass: the env-anchored
admin's password + TOTP at /login keeps working whatever Google's state.

Unset GOOGLE_CLIENT_ID and the button disappears; the routes send people
back to /login with a "not configured" message.
"""

from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("protek.google_auth")

DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
# Google documents both forms for the ID token's `iss`.
ISSUERS = ["https://accounts.google.com", "accounts.google.com"]

ROLE_ENV = (
    ("admin", "GOOGLE_ADMIN_EMAILS"),
    ("operator", "GOOGLE_OPERATOR_EMAILS"),
    ("viewer", "GOOGLE_VIEWER_EMAILS"),
)

# /login?error=<code> → what the login page says. Only these codes are ever
# rendered, so the query string can't inject text into the page.
ERROR_MESSAGES = {
    "not_configured": "Google sign-in isn't set up on this Protek.",
    "cancelled": "Google sign-in was cancelled.",
    "expired": "That sign-in took too long or started in another tab. Try again.",
    "unverified": "That Google account's email isn't verified.",
    "not_allowed": "That Google account isn't allowed to sign in to Protek.",
    "disabled": "Your Protek account is disabled.",
    "failed": "Google sign-in failed. Try again.",
}


class GoogleSignInError(Exception):
    """A failed sign-in. `code` is a key of ERROR_MESSAGES; `email` is set
    once Google has told us who it was, for the audit trail."""

    def __init__(self, code: str, detail: str = "", email: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.email = email


def _envstr(name: str) -> str:
    return (os.environ.get(name, "") or "").split("#", 1)[0].strip()


def _emails(name: str) -> list[str]:
    return [e.strip().lower() for e in _envstr(name).split(",") if e.strip()]


def config() -> dict[str, Any]:
    return {
        "client_id": _envstr("GOOGLE_CLIENT_ID"),
        # Secrets are taken verbatim — a generated secret may contain '#'.
        "client_secret": (os.environ.get("GOOGLE_CLIENT_SECRET") or "").strip(),
        "emails": {role: _emails(env) for role, env in ROLE_ENV},
    }


def is_configured() -> bool:
    """True iff sign-in can actually work: a client, its secret, and at least
    one allowed email. The login page shows the Google button only then."""
    c = config()
    return bool(c["client_id"] and c["client_secret"]
                and any(c["emails"].values()))


def config_problems() -> list[str]:
    """What's wrong with a half-filled config. Nothing set at all is not a
    problem — Google sign-in is optional — so that returns []."""
    c = config()
    any_emails = any(c["emails"].values())
    if not (c["client_id"] or c["client_secret"] or any_emails):
        return []
    problems = []
    if not c["client_id"]:
        problems.append("GOOGLE_CLIENT_ID is unset")
    if not c["client_secret"]:
        problems.append("GOOGLE_CLIENT_SECRET is unset")
    if not any_emails:
        problems.append("GOOGLE_ADMIN_EMAILS / GOOGLE_OPERATOR_EMAILS / "
                        "GOOGLE_VIEWER_EMAILS are all empty, so nobody could sign in")
    return problems


def role_for(email: str | None) -> str | None:
    """'admin' | 'operator' | 'viewer' for an allowlisted email, else None.
    ROLE_ENV is ordered highest first, so the higher role wins."""
    if not email or not isinstance(email, str):
        return None
    e = email.strip().lower()
    emails = config()["emails"]
    for role, _env in ROLE_ENV:
        if e in emails[role]:
            return role
    return None


def status() -> dict[str, Any]:
    """Read-only view for /admin/sso. Never includes the client secret."""
    c = config()
    return {
        "configured": is_configured(),
        "problems": config_problems(),
        "client_id": c["client_id"] or "(unset)",
        "secret_set": bool(c["client_secret"]),
        "emails": c["emails"],
    }


def init_oauth(app):
    """Register the Google client on an Authlib registry. None when Google
    sign-in isn't configured (or Authlib is missing), and the routes then
    bounce to /login?error=not_configured.

    Discovery is lazy — Authlib fetches Google's metadata on the first
    sign-in, so a network blip at boot doesn't disable the button."""
    problems = config_problems()
    if problems:
        log.warning("Google sign-in disabled: %s", "; ".join(problems))
    if not is_configured():
        return None
    try:
        from authlib.integrations.flask_client import OAuth
    except ImportError:
        log.warning("authlib not installed, so Google sign-in is disabled")
        return None
    c = config()
    oauth = OAuth(app)
    oauth.register(
        name="google",
        client_id=c["client_id"],
        client_secret=c["client_secret"],
        server_metadata_url=DISCOVERY_URL,
        client_kwargs={"scope": "openid email", "code_challenge_method": "S256"},
    )
    return oauth.google


def begin(client, redirect_uri: str):
    """The redirect to Google. Always shows the account chooser, so someone
    who picked the wrong account (and got "not allowed") can pick another."""
    return client.authorize_redirect(redirect_uri, prompt="select_account")


def complete(client, args) -> dict[str, str]:
    """Callback half: code → verified identity → role.

    `args` is the callback's query string. Returns {"email", "role", "sub"};
    raises GoogleSignInError whose `code` the caller turns into a
    /login?error= redirect."""
    from authlib.integrations.base_client import (MismatchingStateError,
                                                  OAuthError)

    if args.get("error"):
        # access_denied is the user backing out of Google's consent screen.
        if args.get("error") == "access_denied":
            raise GoogleSignInError("cancelled", "user cancelled at Google")
        raise GoogleSignInError("failed", f"Google returned {args.get('error')}")

    try:
        token = client.authorize_access_token(
            claims_options={"iss": {"essential": True, "values": ISSUERS}},
        )
    except MismatchingStateError as e:
        raise GoogleSignInError("expired", "state missing or mismatched") from e
    except OAuthError as e:
        raise GoogleSignInError("failed", f"token exchange failed: {e}") from e
    except Exception as e:  # noqa: BLE001 — ID-token validation, network, JWKS
        raise GoogleSignInError("failed", f"ID token rejected: {e}") from e

    claims = token.get("userinfo") or {}
    if not claims:
        # No id_token in the response — Authlib only verifies one when present.
        raise GoogleSignInError("failed", "Google returned no ID token")

    email = claims.get("email")
    email = email.strip().lower() if isinstance(email, str) else ""
    # Google sends a real boolean; anything else is not "verified".
    if not email or claims.get("email_verified") is not True:
        raise GoogleSignInError("unverified", "email missing or unverified", email)
    role = role_for(email)
    if not role:
        raise GoogleSignInError("not_allowed", f"{email} is not on the allowlist", email)
    return {"email": email, "role": role, "sub": str(claims.get("sub") or "")}
