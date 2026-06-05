# SCIM Provisioning with Okta

Capybara_AI implements SCIM 2.0 (RFC 7643/7644) so your IdP can provision,
update, and deactivate users automatically. This guide wires up **Okta**.

## What Capybara_AI exposes

| Item | Value |
| --- | --- |
| SCIM base URL | `https://<your-host>/scim/v2` |
| Auth | HTTP header `Authorization: Bearer <token>` |
| Supported resources | `Users`, `Groups`, `ServiceProviderConfig` |
| Unique identifier | `userName` (the user's email) |
| Deactivation | `active: false` (PATCH) and `DELETE` both **soft-deactivate** — users are never hard-deleted |

> Roles map to groups: `owner`, `admin`, `member`, `viewer`. Adding a user to a
> role group via SCIM PATCH sets their membership role.

## 1. Generate a SCIM token (Capybara_AI)

As an org **admin**, request a bearer token. It is shown **once** — store it in
Okta immediately.

```bash
curl -X POST https://<your-host>/api/admin/scim/token \
  -H "Authorization: Bearer <your-admin-session-or-api-key>"
# → { "token": "scim_...", "tokenPrefix": "scim_xxxx" }
```

To rotate, revoke the current token and generate a new one:

```bash
curl -X DELETE https://<your-host>/api/admin/scim/token -H "Authorization: Bearer <admin>"
```

## 2. Create the SCIM app in Okta

1. **Admin → Applications → Browse App Catalog → Create App Integration**
   (or use a generic *SCIM 2.0 Test App (Header Auth)*).
2. In **Provisioning → Integration**:
   - **SCIM connector base URL:** `https://<your-host>/scim/v2`
   - **Unique identifier field for users:** `userName`
   - **Supported provisioning actions:** Push New Users, Push Profile Updates,
     Push Groups, Deactivate Users.
   - **Authentication Mode:** *HTTP Header* →
     `Authorization: Bearer scim_...` (the token from step 1).
3. Click **Test Connector Configuration** — Okta calls
   `GET /scim/v2/ServiceProviderConfig` (public) and a token-authenticated probe.

## 3. Enable provisioning

Under **Provisioning → To App**, enable:

- **Create Users**
- **Update User Attributes**
- **Deactivate Users**

Map at minimum `userName → email`. Then **assign** people/groups to the app;
Okta pushes them to Capybara_AI.

## 4. Verify

```bash
curl https://<your-host>/scim/v2/Users \
  -H "Authorization: Bearer scim_..." -H "Accept: application/scim+json"
```

You should see the assigned users scoped to your organization only. A
deactivation in Okta sets `active: false` in Capybara_AI and revokes the user's
sessions.

## Security notes

- The token is org-scoped and resolved via a `SECURITY DEFINER` lookup before any
  tenant context exists; a token for org A can never read or write org B.
- Tokens are stored **hashed** (SHA-256); only the prefix is retained for display.
- All SCIM mutations are written to the tamper-evident audit log.
- Serve SCIM only over TLS. Treat the bearer token as a high-value secret.
