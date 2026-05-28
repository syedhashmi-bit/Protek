"""Arc 12 phase 70 — SAML role mapping tests.

Library-independent: the role mapping logic + attribute extraction +
settings construction don't need python3-saml to be installed. Only
the actual /saml/login | /saml/acs | /saml/metadata routes need the
library, and those are guarded behind `library_available()` 503s.
"""
from __future__ import annotations

import pytest


# ── role mapping ──────────────────────────────────────────────────────────


def _setenv(monkeypatch, **env):
    """Helper: clear all SAML_* env then set the ones the test cares about."""
    import os
    for k in list(os.environ):
        if k.startswith("SAML_"):
            monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_role_for_attributes_admin_match(monkeypatch):
    _setenv(monkeypatch,
            SAML_GROUPS_ATTR="memberOf",
            SAML_GROUPS_ADMIN="protek-admins,sec-team",
            SAML_GROUPS_OPERATOR="protek-ops",
            SAML_GROUPS_VIEWER="protek-viewers")
    import saml
    email_attr = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/"
                   "emailaddress")
    attrs = {email_attr: ["admin@example.com"],
             "memberOf": ["protek-admins", "all-staff"]}
    assert saml.role_for_attributes(attrs) == "admin"


def test_role_for_attributes_operator_match(monkeypatch):
    _setenv(monkeypatch,
            SAML_GROUPS_ATTR="memberOf",
            SAML_GROUPS_ADMIN="protek-admins",
            SAML_GROUPS_OPERATOR="protek-ops,site-reliability")
    import saml
    attrs = {"email": ["op@example.com"], "memberOf": ["site-reliability"]}
    assert saml.role_for_attributes(attrs) == "operator"


def test_role_for_attributes_admin_wins_over_operator(monkeypatch):
    """Highest-precedence wins — admin beats operator beats viewer."""
    _setenv(monkeypatch,
            SAML_GROUPS_ATTR="groups",
            SAML_GROUPS_ADMIN="all-staff",
            SAML_GROUPS_OPERATOR="all-staff")
    import saml
    attrs = {"email": ["x@example.com"], "groups": ["all-staff"]}
    assert saml.role_for_attributes(attrs) == "admin"


def test_role_for_attributes_no_match_returns_none(monkeypatch):
    _setenv(monkeypatch,
            SAML_GROUPS_ATTR="memberOf",
            SAML_GROUPS_ADMIN="protek-admins")
    import saml
    attrs = {"email": ["nobody@example.com"], "memberOf": ["randos"]}
    assert saml.role_for_attributes(attrs) is None


def test_default_role_when_no_group_matches(monkeypatch):
    _setenv(monkeypatch,
            SAML_GROUPS_ATTR="groups",
            SAML_GROUPS_ADMIN="admins",
            SAML_DEFAULT_ROLE="viewer")
    import saml
    attrs = {"email": ["x@example.com"], "groups": ["randos"]}
    assert saml.role_for_attributes(attrs) == "viewer"


def test_domain_gate_blocks_non_allowed(monkeypatch):
    _setenv(monkeypatch,
            SAML_GROUPS_ATTR="groups",
            SAML_GROUPS_ADMIN="admins",
            SAML_ALLOWED_DOMAINS="example.com,trusted.org",
            SAML_DEFAULT_ROLE="viewer")
    import saml
    attrs_ok = {"email": ["x@example.com"], "groups": ["admins"]}
    attrs_blocked = {"email": ["evil@elsewhere.com"], "groups": ["admins"]}
    assert saml.role_for_attributes(attrs_ok) == "admin"
    assert saml.role_for_attributes(attrs_blocked) is None


def test_missing_email_returns_none(monkeypatch):
    _setenv(monkeypatch, SAML_GROUPS_ADMIN="admins")
    import saml
    assert saml.role_for_attributes({"groups": ["admins"]}) is None


def test_role_lookup_handles_scalar_groups(monkeypatch):
    """Some IdPs send a single group as a string, not a list. The
    library normalises but our role mapper accepts both shapes."""
    _setenv(monkeypatch,
            SAML_GROUPS_ATTR="memberOf",
            SAML_GROUPS_ADMIN="solo-admin")
    import saml
    attrs = {"email": ["x@example.com"], "memberOf": "solo-admin"}
    assert saml.role_for_attributes(attrs) == "admin"


def test_first_helper_handles_list_str_empty():
    import saml
    assert saml._first(["a", "b"]) == "a"
    assert saml._first([]) == ""
    assert saml._first("a") == "a"
    assert saml._first(None) == ""
    assert saml._first(123) == "123"


def test_email_extraction_picks_configured_attr(monkeypatch):
    _setenv(monkeypatch,
            SAML_EMAIL_ATTR="user.email")
    import saml
    assert saml.email_from_attributes({"user.email": ["A@B.com"]}) == "a@b.com"


def test_email_extraction_falls_back_to_email_key(monkeypatch):
    _setenv(monkeypatch)  # no SAML_EMAIL_ATTR set
    import saml
    attrs = {"email": ["alice@example.com"]}
    assert saml.email_from_attributes(attrs) == "alice@example.com"


# ── configuration / status ─────────────────────────────────────────────────


def test_is_configured_requires_all_idp_values(monkeypatch):
    _setenv(monkeypatch,
            SAML_SP_BASE_URL="https://protek.example.com",
            SAML_IDP_ENTITY_ID="https://idp.example.com",
            SAML_IDP_SSO_URL="https://idp.example.com/saml/sso")
    import saml
    # X509 missing → not configured
    assert saml.is_configured() is False

    monkeypatch.setenv("SAML_IDP_X509", "MIIDpDCCAoy...")
    assert saml.is_configured() is True


def test_is_configured_blank_when_nothing_set(monkeypatch):
    _setenv(monkeypatch)
    import saml
    assert saml.is_configured() is False


def test_status_reports_configured_flag(monkeypatch):
    _setenv(monkeypatch,
            SAML_SP_BASE_URL="https://protek.example.com",
            SAML_IDP_ENTITY_ID="https://idp.example.com",
            SAML_IDP_SSO_URL="https://idp.example.com/saml/sso",
            SAML_IDP_X509="MIIDpDCCAoy...",
            SAML_GROUPS_ADMIN="protek-admins")
    import saml
    s = saml.status()
    assert s["configured"] is True
    assert s["sp_entity_id"].startswith("https://protek.example.com")
    assert s["idp_entity_id"] == "https://idp.example.com"
    assert s["groups_admin"] == "protek-admins"


# ── settings dict shape (verifies python3-saml-compatible structure) ──────


def test_build_settings_emits_required_shape(monkeypatch):
    _setenv(monkeypatch,
            SAML_SP_BASE_URL="https://protek.example.com",
            SAML_IDP_ENTITY_ID="https://idp.example.com",
            SAML_IDP_SSO_URL="https://idp.example.com/saml/sso",
            SAML_IDP_X509="MIIDpDCCAoy...")
    import saml
    s = saml.build_settings()

    # The OneLogin SAML library expects these exact keys.
    assert s["strict"] is True
    assert s["sp"]["entityId"] == "https://protek.example.com/saml/metadata"
    assert s["sp"]["assertionConsumerService"]["url"] == \
           "https://protek.example.com/saml/acs"
    assert s["sp"]["assertionConsumerService"]["binding"] == \
           "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    assert s["idp"]["entityId"] == "https://idp.example.com"
    assert s["idp"]["singleSignOnService"]["url"] == \
           "https://idp.example.com/saml/sso"
    assert s["idp"]["x509cert"] == "MIIDpDCCAoy..."
    assert s["security"]["wantAssertionsSigned"] is True
    # SP isn't signing AuthnRequests without an SP cert
    assert s["security"]["authnRequestsSigned"] is False


def test_build_settings_signs_when_sp_keypair_present(monkeypatch):
    _setenv(monkeypatch,
            SAML_SP_BASE_URL="https://protek.example.com",
            SAML_IDP_ENTITY_ID="https://idp.example.com",
            SAML_IDP_SSO_URL="https://idp.example.com/saml/sso",
            SAML_IDP_X509="MIIDpDCCAoy...",
            SAML_SP_X509="MIIDpDCCAoy_SP...",
            SAML_SP_PRIVATE_KEY="MIIEvQIBA...")
    import saml
    s = saml.build_settings()
    assert s["security"]["authnRequestsSigned"] is True


def test_custom_sp_entity_id_overrides_default(monkeypatch):
    _setenv(monkeypatch,
            SAML_SP_BASE_URL="https://protek.example.com",
            SAML_SP_ENTITY_ID="protek-sp",
            SAML_IDP_ENTITY_ID="https://idp.example.com",
            SAML_IDP_SSO_URL="https://idp.example.com/saml/sso",
            SAML_IDP_X509="x")
    import saml
    s = saml.build_settings()
    assert s["sp"]["entityId"] == "protek-sp"
