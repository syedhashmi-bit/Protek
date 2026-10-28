# SSO — OIDC + SAML

Phase 70 spans both protocols. Pick whichever your IdP speaks more
naturally; you can also enable both side-by-side. The break-glass
admin from `.env` (`APP_USERNAME` / `APP_PASSWORD_HASH` / `TOTP_SECRET`)
always works at `/login` regardless of SSO state.

## Google sign-in

The same model as Othoni and RiMM: a **Sign in with Google** button on
`/login`, and an email allowlist in `.env` that decides who gets in and
with which role. Use this for Google rather than the generic OIDC
client below. Google sends no groups claim, so OIDC could only gate it
by domain, and the domain for a personal account is `gmail.com`.

### Set up

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
   go to **APIs & Services → Credentials → Create credentials → OAuth
   client ID**, type **Web application**. If you already have a project
   for Othoni or RiMM, add a new client there. If the consent screen is
   in *Testing*, add yourself as a test user.
2. Add this **Authorized redirect URI** (`/admin/sso` shows the exact
   value for your host):

   ```
   https://<your-protek-host>/auth/google/callback
   ```

3. Put the client and the allowlist in `.env`:

   ```bash
   GOOGLE_CLIENT_ID=<id>.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=<secret>
   GOOGLE_ADMIN_EMAILS=you@example.com       # comma-separated
   GOOGLE_OPERATOR_EMAILS=                   # optional
   GOOGLE_VIEWER_EMAILS=                     # optional, read-only
   ```

4. `systemctl restart protek`. The button appears once the client ID,
   the secret and at least one email are set. A half-filled config logs
   a warning at boot and shows on `/admin/sso`, and the button stays off.

### How it works

- `/auth/google` sends the browser to Google's account chooser with a
  random `state` (held in the signed session cookie, so it is bound to
  this browser), a `nonce` and a PKCE S256 challenge.
- `/auth/google/callback` swaps the code for an ID token server-to-server.
  Authlib checks its signature against Google's published keys, plus its
  audience, expiry and nonce. Protek then checks the issuer and requires
  `email_verified`.
- The verified email must be on one of the three lists. An email on two
  lists gets the higher role. Anyone else is sent back to `/login` with
  "That Google account isn't allowed". That counts toward the IP lockout
  like a bad password and lands in the login audit as `google: not_allowed`.
- The first sign-in creates a `users` row keyed by email, with an unusable
  password. For Google users the **role comes from `.env`**, not
  `/admin/users`. The allowlist is re-checked on every request, so
  removing an email (or moving it to a lower list) and restarting takes
  effect on that person's next click. To block someone without
  restarting, disable them in `/admin/users`.
- There is no TOTP prompt. 2-Step Verification on the Google account is
  the second factor, as in Othoni and RiMM, so turn it on.
- The IP allowlist and the login lockout apply to Google sign-in too.
- **Break-glass:** with Google configured, `/login` folds the password +
  TOTP form under "Use a password and 2FA code instead". It keeps working
  whatever Google's state.

## OIDC — modern providers

Verified against Google Workspace, Authentik, Auth0, Keycloak. See
the comment block at the top of `oidc.py` for env vars. For Google,
use the Google sign-in section above instead.

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

Google sign-in, OIDC and SAML config status are visible at `/admin/sso`
(admin-only). The Google panel shows the redirect URI to register and
the allowlist per role.
The page shows what's configured, what's missing, and a test button for
OIDC. SAML's test path is harder to automate without a real IdP click-through,
so the SAML row links to `/saml/metadata` so the operator can verify the
SP metadata XML is being served correctly.
