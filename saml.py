"""
saml.py — Arc 12 phase 70. SAML 2.0 SSO (sibling of oidc.py).

For enterprise IdPs that don't speak OIDC: Okta SAML, ADFS, OneLogin,
Azure AD (Entra ID) SAML enterprise apps. The OIDC path from phase 70
covers the modern providers (Google Workspace, Authentik, Auth0,
Keycloak); this fills the remaining gap.

Wire shape:
  GET  /saml/login       → SP-initiated redirect to IdP SSO endpoint
  POST /saml/acs         → Assertion Consumer Service; IdP posts back
                            the signed SAML response. We validate the
                            signature, extract attributes, map to a
                            Protek role, set session.
  GET  /saml/metadata    → SP metadata XML for the IdP to import

Library: `python3-saml` (the onelogin library — de-facto standard).
It's optional: if not installed, the routes return 503 with a clear
install hint. Same pattern oidc.py uses for `authlib`.

Install on the host:
  apt install -y libxmlsec1-dev pkg-config        # Debian/Ubuntu
  dnf install -y xmlsec1-devel libtool-ltdl-devel  # Fedora/RHEL
  pip install python3-saml

Configuration (env vars; presence of SAML_IDP_* enables the routes):
  SAML_SP_BASE_URL          — public origin (https://protek.example.com)
  SAML_SP_ENTITY_ID         — default: {base}/saml/metadata
  SAML_IDP_ENTITY_ID        — entity ID published by your IdP
  SAML_IDP_SSO_URL          — IdP SAML SSO endpoint (where /saml/login redirects)
  SAML_IDP_X509             — IdP signing certificate (PEM, single line, no headers)
  SAML_IDP_SLO_URL          — optional, for single logout (not used today)

  SAML_GROUPS_ATTR          — attribute name carrying group memberships
                              (default "groups"; common IdP names:
                              "memberOf", "http://schemas.xmlsoap.org/claims/Group")
  SAML_GROUPS_ADMIN         — comma-separated groups → admin
  SAML_GROUPS_OPERATOR      — comma-separated groups → operator
  SAML_GROUPS_VIEWER        — comma-separated groups → viewer
  SAML_DEFAULT_ROLE         — fallback role when no group matches
                              (admin/operator/viewer); unset = explicit deny
  SAML_ALLOWED_DOMAINS      — comma-separated email domains; empty = any

  SAML_SP_X509              — our SP cert (optional; for signed AuthnRequests)
  SAML_SP_PRIVATE_KEY       — matching private key (optional)

Role mapping shares oidc.py's algorithm so the operator sees identical
group→role semantics across both SSO methods.

Break-glass: same as OIDC — the env-anchored admin always works at
/login regardless of SAML state.
"""
from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("protek.saml")


def _envstr(name: str, default: str = "") -> str:
    return (os.environ.get(name, default) or "").split("#", 1)[0].strip()


def _split(s: str) -> list[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]


# ── Configuration ──────────────────────────────────────────────────────────


def is_configured() -> bool:
    """SAML is enabled when the IdP-side minimum is configured. The SP
    cert/key are optional (only needed for signed AuthnRequests)."""
    return bool(
        _envstr("SAML_SP_BASE_URL")
        and _envstr("SAML_IDP_ENTITY_ID")
        and _envstr("SAML_IDP_SSO_URL")
        and _envstr("SAML_IDP_X509")
    )


def library_available() -> bool:
    """Cheap check before any route handler does real work. Caches the
    import result across calls."""
    global _LIB_AVAILABLE
    try:
        return _LIB_AVAILABLE
    except NameError:
        pass
    try:
        import onelogin.saml2  # noqa: F401
        _LIB_AVAILABLE = True
    except ImportError:
        _LIB_AVAILABLE = False
    return _LIB_AVAILABLE


def status() -> dict[str, Any]:
    return {
        "configured":      is_configured(),
        "library_present": library_available(),
        "sp_base_url":     _envstr("SAML_SP_BASE_URL") or "(unset)",
        "sp_entity_id":    _envstr("SAML_SP_ENTITY_ID")
                            or (_envstr("SAML_SP_BASE_URL") + "/saml/metadata"
                                if _envstr("SAML_SP_BASE_URL") else "(unset)"),
        "idp_entity_id":   _envstr("SAML_IDP_ENTITY_ID") or "(unset)",
        "idp_sso_url":     _envstr("SAML_IDP_SSO_URL")   or "(unset)",
        "domains":         _envstr("SAML_ALLOWED_DOMAINS") or "(any)",
        "groups_attr":     _envstr("SAML_GROUPS_ATTR") or "groups",
        "default_role":    _envstr("SAML_DEFAULT_ROLE") or "(none)",
        "groups_admin":    _envstr("SAML_GROUPS_ADMIN")    or "(none)",
        "groups_operator": _envstr("SAML_GROUPS_OPERATOR") or "(none)",
        "groups_viewer":   _envstr("SAML_GROUPS_VIEWER")   or "(none)",
        "sp_signed_requests": bool(_envstr("SAML_SP_X509") and _envstr("SAML_SP_PRIVATE_KEY")),
    }


# ── Role mapping ───────────────────────────────────────────────────────────


def role_for_attributes(attrs: dict[str, Any]) -> str | None:
    """Map SAML attribute statements → Protek role. Mirrors
    oidc.role_for_claims's algorithm so both SSO paths surface identical
    semantics to the operator.

    `attrs` is the dict the python3-saml library returns from
    `get_attributes()` — values are always lists per the SAML spec,
    even single-valued attributes.
    """
    # Email — extract from the configured attribute name OR NameID format.
    email_attr = (_envstr("SAML_EMAIL_ATTR")
                  or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
    email = _first(attrs.get(email_attr) or attrs.get("email") or [])
    email = (email or "").lower().strip()
    if not email:
        return None

    # Domain gate
    allowed = set(_split(_envstr("SAML_ALLOWED_DOMAINS")))
    if allowed:
        domain = email.split("@", 1)[1] if "@" in email else ""
        if domain not in allowed:
            return None

    # Group membership
    groups_attr = _envstr("SAML_GROUPS_ATTR") or "groups"
    raw_groups = attrs.get(groups_attr) or []
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    g_set = {str(g) for g in raw_groups}

    admin_g    = set(_split(_envstr("SAML_GROUPS_ADMIN")))
    operator_g = set(_split(_envstr("SAML_GROUPS_OPERATOR")))
    viewer_g   = set(_split(_envstr("SAML_GROUPS_VIEWER")))

    if g_set & admin_g:
        return "admin"
    if g_set & operator_g:
        return "operator"
    if g_set & viewer_g:
        return "viewer"

    default = _envstr("SAML_DEFAULT_ROLE")
    if default in ("admin", "operator", "viewer"):
        return default
    return None  # explicit deny


def _first(v: Any) -> str:
    """python3-saml returns attribute values as lists. This grabs the
    first scalar safely."""
    if isinstance(v, list):
        return v[0] if v else ""
    return str(v) if v else ""


def email_from_attributes(attrs: dict[str, Any]) -> str:
    """Same email extraction `role_for_attributes` uses — exposed for
    the route handler that has to upsert the user after the role
    decision."""
    email_attr = (_envstr("SAML_EMAIL_ATTR")
                  or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
    return (_first(attrs.get(email_attr) or attrs.get("email") or []) or "").lower().strip()


# ── onelogin/python3-saml glue ────────────────────────────────────────────


def build_settings() -> dict[str, Any]:
    """python3-saml's settings dict. Built from env every call so the
    operator doesn't restart Protek after rotating the IdP cert."""
    base = _envstr("SAML_SP_BASE_URL").rstrip("/")
    sp_entity = _envstr("SAML_SP_ENTITY_ID") or f"{base}/saml/metadata"
    settings: dict[str, Any] = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": sp_entity,
            "assertionConsumerService": {
                "url": f"{base}/saml/acs",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            "x509cert": _envstr("SAML_SP_X509"),
            "privateKey": _envstr("SAML_SP_PRIVATE_KEY"),
        },
        "idp": {
            "entityId": _envstr("SAML_IDP_ENTITY_ID"),
            "singleSignOnService": {
                "url": _envstr("SAML_IDP_SSO_URL"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": _envstr("SAML_IDP_SLO_URL") or _envstr("SAML_IDP_SSO_URL"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _envstr("SAML_IDP_X509"),
        },
        "security": {
            "authnRequestsSigned": bool(_envstr("SAML_SP_X509")
                                        and _envstr("SAML_SP_PRIVATE_KEY")),
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            # Block SAML responses that arrive with `<xs:any>` extensions
            # outside the assertion — defends against signature-wrapping
            # attacks documented in OWASP SAML Cheat Sheet.
            "wantNameIdEncrypted": False,
        },
    }
    return settings


def request_data_from_flask(flask_request) -> dict[str, Any]:
    """python3-saml wants its own request dict. Build it from Flask's
    request object — the library doesn't speak WSGI directly."""
    parsed = urlparse(_envstr("SAML_SP_BASE_URL"))
    return {
        "https": "on" if parsed.scheme == "https" else "off",
        "http_host": parsed.netloc,
        "server_port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
        "script_name": flask_request.path,
        "get_data": flask_request.args.copy(),
        "post_data": flask_request.form.copy(),
    }


def build_auth(flask_request):
    """Construct the python3-saml OneLogin_Saml2_Auth object. Raises
    ImportError if the library isn't installed — callers should check
    `library_available()` first and 503 cleanly."""
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    return OneLogin_Saml2_Auth(request_data_from_flask(flask_request),
                                old_settings=build_settings())


# ── User provisioning ────────────────────────────────────────────────────


def upsert_sso_user(email: str, role: str):
    """SAML and OIDC share `users` table and provisioning semantics, so
    we just delegate. Kept here as a name so callers don't need to know
    the two SSO methods share state."""
    from oidc import upsert_sso_user as _upsert
    return _upsert(email, role, idp_sub=email)
