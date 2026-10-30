"""Google sign-in — allowlist mapping and the full browser round trip.

The round trip runs through the real routes and Authlib's real ID-token
checks (signature, audience, issuer, expiry, nonce). Only Google itself is
faked: its discovery document and keys are pre-loaded into the client, and
the server-to-server code exchange returns an ID token signed with a test
RSA key. Nothing here touches the network.
"""
from __future__ import annotations

import base64
import hashlib
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

import google_auth

CLIENT_ID = "test-client.apps.googleusercontent.com"
KID = "test-kid"
IP = "127.0.0.1"
_DROP = object()


def _clear_google_env(monkeypatch):
    for env in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET",
                *(env for _role, env in google_auth.ROLE_ENV)):
        monkeypatch.delenv(env, raising=False)


# ── allowlist + config ────────────────────────────────────────────────────


def test_role_for_is_case_insensitive_and_highest_wins(monkeypatch):
    _clear_google_env(monkeypatch)
    monkeypatch.setenv("GOOGLE_ADMIN_EMAILS", " Boss@Example.com , both@example.com")
    monkeypatch.setenv("GOOGLE_OPERATOR_EMAILS", "op@example.com,both@example.com")
    monkeypatch.setenv("GOOGLE_VIEWER_EMAILS", "view@example.com  # inline comment")
    assert google_auth.role_for("boss@example.com") == "admin"
    assert google_auth.role_for("BOSS@EXAMPLE.COM") == "admin"
    assert google_auth.role_for("op@example.com") == "operator"
    assert google_auth.role_for("both@example.com") == "admin"
    assert google_auth.role_for("view@example.com") == "viewer"
    assert google_auth.role_for("stranger@example.com") is None
    assert google_auth.role_for("") is None
    assert google_auth.role_for(None) is None


def test_unset_config_is_not_a_problem(monkeypatch):
    _clear_google_env(monkeypatch)
    assert google_auth.config_problems() == []
    assert google_auth.is_configured() is False


def test_half_filled_config_is_reported_and_stays_off(monkeypatch):
    _clear_google_env(monkeypatch)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", CLIENT_ID)
    problems = google_auth.config_problems()
    assert any("GOOGLE_CLIENT_SECRET" in p for p in problems)
    assert any("nobody could sign in" in p for p in problems)
    assert google_auth.is_configured() is False

    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "s3cret")
    monkeypatch.setenv("GOOGLE_VIEWER_EMAILS", "v@example.com")
    assert google_auth.config_problems() == []
    assert google_auth.is_configured() is True


def test_status_never_carries_the_secret(monkeypatch):
    _clear_google_env(monkeypatch)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "do-not-leak")
    monkeypatch.setenv("GOOGLE_ADMIN_EMAILS", "a@example.com")
    s = google_auth.status()
    assert s["secret_set"] is True
    assert "do-not-leak" not in repr(s)


# ── fake Google + fixture ─────────────────────────────────────────────────


class FakeGoogle:
    """Plays Google's side: records what /auth/google sent, then answers the
    code exchange with an ID token built from `email` + `overrides`."""

    def __init__(self, key):
        self.key = key
        self.sign_with = key
        self.email = ""
        self.overrides: dict = {}
        self.auth_params: dict = {}
        self.exchange_kwargs: dict = {}

    def fetch_access_token(self, **kwargs):
        self.exchange_kwargs = kwargs
        now = int(time.time())
        claims = {
            "iss": "https://accounts.google.com",
            "aud": CLIENT_ID,
            "sub": "109876543210",
            "email": self.email,
            "email_verified": True,
            "nonce": self.auth_params.get("nonce"),
            "iat": now,
            "exp": now + 3600,
        }
        claims.update(self.overrides)
        claims = {k: v for k, v in claims.items() if v is not _DROP}
        id_token = jwt.encode({"alg": "RS256", "kid": KID}, claims, self.sign_with)
        return {"access_token": "ya29.test", "token_type": "Bearer",
                "expires_in": 3599, "id_token": id_token}


@pytest.fixture
def g(monkeypatch):
    import app as app_mod
    import auth

    _clear_google_env(monkeypatch)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("GOOGLE_ADMIN_EMAILS", "Admin@Example.com")
    monkeypatch.setenv("GOOGLE_VIEWER_EMAILS", "viewer@example.com")

    client = google_auth.init_oauth(app_mod.app)
    assert client is not None
    key = RSAKey.generate_key(2048, parameters={"kid": KID})
    # Pre-loaded discovery document + keys, so Authlib never fetches them.
    client.server_metadata.update({
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "id_token_signing_alg_values_supported": ["RS256"],
        "jwks": {"keys": [key.as_dict(private=False)]},
        "_loaded_at": time.time(),
    })
    fake = FakeGoogle(key)
    monkeypatch.setattr(client, "fetch_access_token", fake.fetch_access_token)
    monkeypatch.setattr(app_mod, "_google", client)
    app_mod.app.config["TESTING"] = True
    auth.clear_failures(IP)
    yield SimpleNamespace(app=app_mod, auth=auth, http=app_mod.app.test_client(), fake=fake)
    auth.clear_failures(IP)


def _start(g, path="/auth/google"):
    r = g.http.get(path)
    assert r.status_code == 302, r.status_code
    loc = urlparse(r.location)
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == "https://accounts.google.com/o/oauth2/v2/auth"
    g.fake.auth_params = {k: v[0] for k, v in parse_qs(loc.query).items()}
    return g.fake.auth_params


def _sign_in(g, email, start_path="/auth/google", overrides=None):
    params = _start(g, start_path)
    g.fake.email = email
    g.fake.overrides = overrides or {}
    return g.http.get(f"/auth/google/callback?code=4/test-code&state={params['state']}")


def _session(g):
    with g.http.session_transaction() as s:
        return dict(s)


def _attempts(ip=IP):
    from db import get_conn
    conn = get_conn()
    try:
        row = conn.execute("SELECT attempts FROM login_attempts WHERE ip = ?", (ip,)).fetchone()
    finally:
        conn.close()
    return row["attempts"] if row else 0


def _last_audit():
    from db import get_conn
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT username, success, reason FROM login_audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    return dict(row)


# ── the round trip ────────────────────────────────────────────────────────


def test_start_sends_state_nonce_pkce_and_account_chooser(g):
    p = _start(g)
    assert p["client_id"] == CLIENT_ID
    assert p["response_type"] == "code"
    assert set(p["scope"].split()) == {"openid", "email"}
    assert p["redirect_uri"].endswith("/auth/google/callback")
    assert p["prompt"] == "select_account"
    assert p["code_challenge_method"] == "S256"
    assert p["state"] and p["nonce"] and p["code_challenge"]


def test_allowlisted_admin_signs_in(g):
    r = _sign_in(g, "admin@example.com")
    assert r.status_code == 302
    assert urlparse(r.location).path == "/"
    s = _session(g)
    assert s["logged_in"] is True
    assert s["username"] == "admin@example.com"
    assert s["role"] == "admin"
    assert s["auth_source"] == "google"
    assert _last_audit() == {"username": "admin@example.com", "success": 1, "reason": "google"}
    # PKCE: the code exchange carried the verifier behind the challenge.
    verifier = g.fake.exchange_kwargs["code_verifier"]
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == g.fake.auth_params["code_challenge"]
    assert g.fake.exchange_kwargs["redirect_uri"] == g.fake.auth_params["redirect_uri"]
    # And the session actually opens an admin page.
    assert g.http.get("/admin/sso").status_code == 200


def test_viewer_gets_viewer_role(g):
    _sign_in(g, "viewer@example.com")
    assert _session(g)["role"] == "viewer"


def test_next_survives_the_round_trip_but_not_offsite(g):
    r = _sign_in(g, "admin@example.com", start_path="/auth/google?next=/decisions")
    assert r.location.endswith("/decisions")
    g.http.get("/logout")
    r = _sign_in(g, "admin@example.com", start_path="/auth/google?next=https://evil.example/")
    assert "evil.example" not in r.location
    assert urlparse(r.location).path == "/"


def test_account_not_on_the_allowlist_is_refused(g):
    r = _sign_in(g, "stranger@gmail.com")
    assert r.status_code == 302
    assert r.location.endswith("/login?error=not_allowed")
    assert not _session(g).get("logged_in")
    assert _attempts() == 1  # counts toward the lockout
    assert _last_audit() == {"username": "stranger@gmail.com", "success": 0,
                             "reason": "google: not_allowed"}


@pytest.mark.parametrize("overrides", [
    {"email_verified": False},
    {"email_verified": _DROP},
    {"email_verified": "true"},  # only a real boolean counts
    {"email": _DROP},
])
def test_unverified_or_missing_email_is_refused(g, overrides):
    r = _sign_in(g, "admin@example.com", overrides=overrides)
    assert r.location.endswith("/login?error=unverified")
    assert not _session(g).get("logged_in")


@pytest.mark.parametrize("overrides", [
    {"nonce": "not-the-nonce-we-sent"},
    {"aud": "someone-elses-client.apps.googleusercontent.com"},
    # azp matching ours used to let Authlib skip the audience entirely: it only
    # checks aud when claims_options names it.
    {"aud": "someone-elses-client.apps.googleusercontent.com", "azp": CLIENT_ID},
    {"iss": "https://evil.example"},
    {"exp": int(time.time()) - 3600},
])
def test_id_token_that_fails_verification_is_refused(g, overrides):
    r = _sign_in(g, "admin@example.com", overrides=overrides)
    assert r.location.endswith("/login?error=failed")
    assert not _session(g).get("logged_in")
    assert _attempts() == 0  # a broken round trip isn't a guess


def test_id_token_signed_by_another_key_is_refused(g):
    g.fake.sign_with = RSAKey.generate_key(2048, parameters={"kid": KID})
    r = _sign_in(g, "admin@example.com")
    assert r.location.endswith("/login?error=failed")
    assert not _session(g).get("logged_in")


def test_short_form_issuer_is_accepted(g):
    _sign_in(g, "admin@example.com", overrides={"iss": "accounts.google.com"})
    assert _session(g)["logged_in"] is True


def test_callback_with_a_foreign_state_is_refused(g):
    _start(g)
    g.fake.email = "admin@example.com"
    r = g.http.get("/auth/google/callback?code=4/test-code&state=forged")
    assert r.location.endswith("/login?error=expired")
    assert not _session(g).get("logged_in")
    assert g.fake.exchange_kwargs == {}  # never reached Google's token endpoint


def test_cancel_at_google_does_not_count_as_a_failure(g):
    params = _start(g)
    r = g.http.get(f"/auth/google/callback?error=access_denied&state={params['state']}")
    assert r.location.endswith("/login?error=cancelled")
    assert _attempts() == 0


def test_disabled_user_is_refused(g):
    _sign_in(g, "viewer@example.com")
    uid = _session(g)["user_id"]
    g.http.get("/logout")
    g.auth.set_user_disabled(uid, True)
    try:
        r = _sign_in(g, "viewer@example.com")
        assert r.location.endswith("/login?error=disabled")
        assert not _session(g).get("logged_in")
    finally:
        g.auth.set_user_disabled(uid, False)


def test_locked_ip_is_not_sent_to_google(g):
    for _ in range(g.auth._max_attempts()):
        g.auth.record_failure(IP)
    r = g.http.get("/auth/google")
    assert urlparse(r.location).path == "/login"


# ── the allowlist stays authoritative for live sessions ───────────────────


def test_removing_an_email_signs_that_session_out(g, monkeypatch):
    _sign_in(g, "admin@example.com")
    assert g.http.get("/admin/sso").status_code == 200
    monkeypatch.setenv("GOOGLE_ADMIN_EMAILS", "someone-else@example.com")
    r = g.http.get("/admin/sso")
    assert urlparse(r.location).path == "/login"
    assert not _session(g).get("logged_in")


def test_moving_an_email_to_a_lower_list_demotes_the_session(g, monkeypatch):
    _sign_in(g, "admin@example.com")
    monkeypatch.setenv("GOOGLE_ADMIN_EMAILS", "")
    monkeypatch.setenv("GOOGLE_VIEWER_EMAILS", "admin@example.com")
    r = g.http.get("/admin/sso")
    assert r.status_code == 403
    assert _session(g)["role"] == "viewer"


# ── login page ────────────────────────────────────────────────────────────


def test_login_page_shows_the_google_button_when_configured(g):
    body = g.http.get("/login?next=/alerts").get_data(as_text=True)
    assert "Sign in with Google" in body
    assert "/auth/google?next=/alerts" in body
    # The password form is still there, folded away as break-glass.
    assert '<details class="alt-login">' in body
    assert 'name="totp"' in body


def test_login_page_renders_only_known_error_codes(g):
    body = g.http.get("/login?error=not_allowed").get_data(as_text=True)
    assert "isn&#39;t allowed to sign in to Protek" in body
    body = g.http.get("/login?error=%3Cscript%3Ealert(1)%3C/script%3E").get_data(as_text=True)
    assert "alert(1)" not in body


def test_unconfigured_google_hides_the_button_and_bounces(monkeypatch):
    import app as app_mod
    monkeypatch.setattr(app_mod, "_google", None)
    app_mod.app.config["TESTING"] = True
    http = app_mod.app.test_client()
    body = http.get("/login").get_data(as_text=True)
    assert "Sign in with Google" not in body
    assert "<details" not in body
    r = http.get("/auth/google")
    assert r.location.endswith("/login?error=not_configured")
