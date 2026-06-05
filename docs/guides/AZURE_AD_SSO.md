# Single Sign-On with Microsoft Entra ID (Azure AD)

Capybara_AI's OIDC works with any standards-compliant provider; Entra ID is
OIDC-compliant. This guide covers the exact app-registration steps.

## 1. App registration

Azure Portal → **Microsoft Entra ID** → **App registrations** → **New registration**:

- **Name:** `Capybara_AI`
- **Supported account types:** *Accounts in this organizational directory only*
  (single tenant) for a company deployment.
- **Redirect URI:** platform **Web**, value
  `https://<your-app-host>/api/auth/sso/callback`
  (must match `OIDC_REDIRECT_URI` exactly).

Record the **Application (client) ID** and **Directory (tenant) ID**.

## 2. Client secret

App → **Certificates & secrets** → **New client secret**. Copy the **Value**
immediately (shown once). This is your `clientSecret`.

## 3. API permissions

App → **API permissions** → **Add a permission** → **Microsoft Graph** →
**Delegated permissions**: `openid`, `profile`, `email`. Grant admin consent.
No application (app-only) permissions are required.

## 4. Issuer / endpoints

The OIDC **issuer** for Entra ID v2.0 is:

```
https://login.microsoftonline.com/<tenant-id>/v2.0
```

Discovery document (auto-used by Capybara_AI):
`https://login.microsoftonline.com/<tenant-id>/v2.0/.well-known/openid-configuration`

## 5. Configure Capybara_AI

Either via the **Admin Console** (`/admin/sso`) or the API:

```http
POST /api/admin/sso/config
{
  "issuer":       "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "clientId":     "<application-client-id>",
  "clientSecret": "<client-secret-value>",
  "redirectUri":  "https://<your-app-host>/api/auth/sso/callback",
  "domainHint":   "yourcompany.com",
  "autoProvision": true,
  "defaultRole":  "member"
}
```

Test the connection with `POST /api/admin/sso/config/test` (validates issuer
discovery). The client secret is stored **AES-256-GCM encrypted** per tenant.

### Value → field mapping

| Azure value | Capybara_AI field / env |
|---|---|
| Application (client) ID | `clientId` |
| Client secret value | `clientSecret` (stored encrypted) |
| `…/<tenant-id>/v2.0` | `issuer` |
| Redirect URI | `redirectUri` / `OIDC_REDIRECT_URI` |
| Primary email domain | `domainHint` (for `/api/auth/sso/login?domain=`) |

## 6. Login flow

Users start at `GET /api/auth/sso/login?domain=yourcompany.com`. Capybara_AI
looks up the org by domain, runs the PKCE authorization-code flow, verifies the
ID token (issuer/audience/expiry/nonce + JWKS signature), and **auto-provisions**
a `member` account on first login. Disable SSO any time via
`DELETE /api/admin/sso/config` or by setting `active: false`.
