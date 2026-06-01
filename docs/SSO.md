# SSO — OIDC + SAML

Phase 70 spans both protocols. Pick whichever your IdP speaks more
naturally; you can also enable both side-by-side. The break-glass
admin from `.env` (`APP_USERNAME` / `APP_PASSWORD_HASH` / `TOTP_SECRET`)
always works at `/login` regardless of SSO state.

## OIDC — modern providers

Verified against Google Workspace, Authentik, Auth0, Keycloak. See
the comment block at the top of `oidc.py` for env vars.

Login URL: `/sso/login` → callback at `/sso/callback`.

## SAML — enterprise IdPs

Filed at `/saml/login` / `/saml/acs` / `/saml/metadata`. Useful for
Okta SAML, ADFS, OneLogin, Azure AD Entra ID enterprise apps.

### Install the SAML library

SAML support is optional — when `python3-saml` isn't installed the
three SAML routes return 503 with this hint. Install:

```bash
# Debian/Ubuntu
sudo apt install -y libxmlsec1-dev pkg-config
sudo -u protek /var/www/Protek/venv/bin/pip install python3-saml

# Fedora/RHEL
sudo dnf install -y xmlsec1-devel libtool-ltdl-devel
sudo -u protek /var/www/Protek/venv/bin/pip install python3-saml

# Verify
python3 -c "import onelogin.saml2; print(onelogin.saml2.__version__)"
```

Restart Protek after install.

### Configure (env vars)

Minimum:

```bash
# Public origin Protek serves on
SAML_SP_BASE_URL=https://protek.example.com

# IdP-side values (from your IdP's metadata XML)
SAML_IDP_ENTITY_ID=https://idp.example.com/saml/metadata
SAML_IDP_SSO_URL=https://idp.example.com/saml/sso
SAML_IDP_X509=MIIDpDCCAoygAwIBAgIG...    # single line, no BEGIN/END

# Role mapping — same shape as the OIDC env vars
SAML_GROUPS_ATTR=memberOf                  # default: groups
SAML_GROUPS_ADMIN=protek-admins
SAML_GROUPS_OPERATOR=protek-operators
SAML_GROUPS_VIEWER=protek-viewers
SAML_DEFAULT_ROLE=                          # unset = deny if no group match
SAML_ALLOWED_DOMAINS=example.com            # empty = any

# Optional — sign AuthnRequests with our own cert
SAML_SP_X509=MIIDpDCCAoy...
SAML_SP_PRIVATE_KEY=MIIEvQIBA...
```

### IdP setup

1. In Protek, hit `https://protek.example.com/saml/metadata` — copy the
   XML.
2. In your IdP admin console, create a new SAML application:
   - **Entity ID**: `https://protek.example.com/saml/metadata`
   - **ACS URL**: `https://protek.example.com/saml/acs`
   - **NameID format**: emailAddress
   - **Signed assertions**: yes
   - **Signed responses**: optional
3. Map the IdP's user attribute that carries email → SAML
   `emailaddress` (or set `SAML_EMAIL_ATTR` to whatever name your IdP
   uses). Map groups → the attribute named in `SAML_GROUPS_ATTR`.
4. Copy the IdP's signing certificate (X.509 PEM, base64 body only —
   no `-----BEGIN/END` lines) into `SAML_IDP_X509`.
5. Restart Protek.

### Test

Browse to `https://protek.example.com/saml/login`. On success: you
should land on the dashboard with `session.auth_source == "saml"`.
On failure: the login page surfaces the validation error verbatim,
and the cause is also in `journalctl -u protek` + the audit log.

### Failure shapes you might hit

| Symptom | Likely cause |
|---------|--------------|
| `python3-saml not installed` 503 | Install the library + restart |
| `metadata validation: [...]` 500 on `/saml/metadata` | Your SP_BASE_URL probably has no scheme or trailing-slash issues |
| `SAML validation: invalid_response` | IdP signing cert mismatch — re-copy `SAML_IDP_X509` |
| `SAML validation: invalid_audience` | IdP's "Audience" / "Entity ID" doesn't match `SAML_SP_ENTITY_ID` |
| `SAML validation: response_no_signed` | IdP isn't signing assertions — flip on assertion-signing in the IdP admin |
| Login succeeds but role denied | Group attribute name mismatch — check `SAML_GROUPS_ATTR` vs what IdP sends. The audit log shows the raw attribute set. |

### Group attribute name quirks

Common IdP-side defaults:
- **Okta**: `groups` (custom claim) or you must add a Group Attribute Statement
- **ADFS**: `http://schemas.xmlsoap.org/claims/Group`
- **Entra ID**: `http://schemas.microsoft.com/ws/2008/06/identity/claims/role`
- **Authentik (SAML)**: `groups`

Set `SAML_GROUPS_ATTR` to whatever your IdP actually sends.

## /admin/sso

Both OIDC and SAML config status are visible at `/admin/sso` (admin-only).
The page shows what's configured, what's missing, and a test button for
OIDC. SAML's test path is harder to automate without a real IdP click-through,
so the SAML row links to `/saml/metadata` so the operator can verify the
SP metadata XML is being served correctly.
