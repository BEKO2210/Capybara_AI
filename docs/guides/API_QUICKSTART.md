# API Quickstart

Integrate Capybara_AI into your CRM/ERP/custom apps via the REST API and
outbound webhooks.

## 1. Create an API key

In the Admin Console (`/admin/api-keys`) or via the API (admin+):

```http
POST /api/admin/api-keys
{ "name": "crm-integration", "scopes": ["chat:read", "documents:read"] }
```

The response contains the **full key once** — store it securely; only a SHA-256
hash is kept server-side:

```json
{ "id": "…", "key": "capy_XXXXXXXXXXXXXXXXXXXXXXXX", "prefix": "capy_XXX" }
```

Available scopes: `chat:read`, `chat:write`, `documents:read`,
`documents:write`, `admin:read`. Keys may carry an `expiresAt` and can be
revoked (`DELETE /api/admin/api-keys/:id`).

## 2. Authenticate

Send the key as a Bearer token:

```bash
curl -H "Authorization: Bearer capy_XXXXXXXXXXXXXXXXXXXXXXXX" \
     https://<host>/api/v1/me
```

- Missing/expired/revoked key → `401`.
- Key without the required scope → `403`.
- Rate limiting is **per key** (default 100 req/min; stricter than sessions).
- Every API-key request is recorded in the tamper-evident audit log.

## 3. First query (RAG)

```bash
curl -X POST https://<host>/api/chat/rag \
  -H "Authorization: Bearer capy_…" -H "Content-Type: application/json" \
  -d '{"message":"Was steht im Vertrag zur Kündigungsfrist?"}'
```

Responses are streamed via SSE and carry an `ai_meta` envelope
(`ai_generated: true`, model/provider, sources, KI-Inventar link, compliance) —
see the EU AI Act transparency model in `AI_SECURITY_MODEL.md`.

## 4. Webhooks

Subscribe to events to receive push notifications:

```http
POST /api/admin/webhooks
{ "url": "https://your-app/hooks/capybara",
  "secret": "a-long-random-shared-secret",
  "events": ["document.uploaded", "chat.completed", "oversight.decided"] }
```

Each delivery is signed (`X-Capybara-Signature: sha256=…`) and retried up to 3
times with backoff before dead-lettering. **Verify the signature** on receipt —
see [`WEBHOOK_SECURITY.md`](./WEBHOOK_SECURITY.md). Inspect delivery attempts via
`GET /api/admin/webhooks/:id/deliveries`.

## 5. OpenAPI

When `ENABLE_API_DOCS=true`, an OpenAPI 3.1 spec + Swagger UI are served at
`/api/docs` (JSON at `/api/docs/json`). Disabled by default (off in production
unless explicitly enabled).
