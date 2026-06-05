# SCIM Provisioning with Microsoft Entra ID (Azure AD)

Capybara_AI implements SCIM 2.0 (RFC 7643/7644) for automatic user
provisioning. This guide wires up **Microsoft Entra ID** (formerly Azure AD).

## What Capybara_AI exposes

| Item | Value |
| --- | --- |
| Tenant URL | `https://<your-host>/scim/v2` |
| Secret Token | a Capybara_AI SCIM bearer token (`scim_...`) |
| Supported resources | `Users`, `Groups`, `ServiceProviderConfig` |
| Matching attribute | `userName` ↔ `emails[type eq "work"].value` |
| Deactivation | `active: false` (PATCH) / `DELETE` → **soft-deactivate** (never hard-deleted) |

## 1. Generate a SCIM token (Capybara_AI)

As an org **admin**:

```bash
curl -X POST https://<your-host>/api/admin/scim/token \
  -H "Authorization: Bearer <your-admin-session-or-api-key>"
# → { "token": "scim_...", "tokenPrefix": "scim_xxxx" }   (shown once)
```

## 2. Configure provisioning in Entra ID

1. **Entra admin center → Enterprise applications → New application →
   Create your own application** (non-gallery).
2. Open the app → **Provisioning → Get started** → set **Provisioning Mode** to
   **Automatic**.
3. Under **Admin Credentials**:
   - **Tenant URL:** `https://<your-host>/scim/v2`
   - **Secret Token:** the `scim_...` token from step 1.
   - Click **Test Connection**. Entra calls `ServiceProviderConfig` and a
     token-authenticated probe; both must succeed.
4. **Save**.

## 3. Attribute mappings

In **Provisioning → Mappings → Provision Microsoft Entra ID Users**, keep the
defaults and ensure:

- `userPrincipalName` or `mail` → **`userName`** (Capybara_AI matches on email).
- `Switch([IsSoftDeleted], …)` → **`active`** (controls activation/deactivation).

Remove unsupported complex attributes if Entra reports schema errors; Capybara_AI
needs only `userName` and `active`.

## 4. Assign and start

1. **Users and groups → Add user/group** to scope who gets provisioned.
2. Back in **Provisioning**, set **Scope** to *Sync only assigned users and
   groups* and **turn Provisioning On**.
3. Use **Provision on demand** to test a single user immediately.

## 5. Verify

```bash
curl https://<your-host>/scim/v2/Users \
  -H "Authorization: Bearer scim_..." -H "Accept: application/scim+json"
```

Assigned users appear, scoped to your organization. Removing a user's assignment
(or soft-deleting them in Entra) deactivates them in Capybara_AI and revokes
their sessions.

## Security notes

- Tokens are **org-scoped**: resolution happens via a `SECURITY DEFINER` lookup
  before tenant context is established, so a token can only ever touch its own
  organization's data.
- Tokens are stored **hashed** (SHA-256); rotate by `DELETE`-ing then
  re-creating the token.
- All SCIM mutations are recorded in the tamper-evident audit log.
- Serve SCIM only over TLS; protect the secret token like any credential.
