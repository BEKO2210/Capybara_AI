# Enterprise Readiness

An honest assessment for a CTO/security reviewer evaluating Capybara_AI for
self-hosted, multi-tenant production use. It states what is **implemented and
tested today**, and what is deferred to P1/P2. No capability is claimed as
"done" unless code and tests back it.

## Maturity at a glance

| Capability | Status | Evidence |
|---|---|---|
| Multi-tenant data model | ✅ Implemented | `src/db/schema/`, `organizations`/`memberships` |
| Tenant isolation (app + Postgres RLS) | ✅ Implemented + tested | `src/tenancy/`, `tests/db/rls.test.ts` |
| Fail-closed config / secret strength | ✅ Implemented + tested | `src/config/`, `tests/config/` |
| Local password auth (Argon2id) | ✅ Implemented + tested | `src/auth/`, `tests/auth/` |
| Opaque, revocable sessions (hash-at-rest) | ✅ Implemented + tested | `src/auth/session.ts` |
| RBAC (4 roles, least privilege) | ✅ Implemented + tested | `src/rbac/`, `tests/rbac/` |
| Security headers / CORS / CSRF / rate limit | ✅ Implemented + tested | `src/http/`, `tests/http/` |
| Audit log + tamper-evident security log | ✅ Implemented + tested | `src/audit/`, `tests/audit/` |
| LLM provider abstraction (server-only) | ✅ Implemented + tested | `src/ai/providers/`, `tests/ai/provider.test.ts` |
| AI tool sandbox (allowlist/scopes/approval) | ✅ Implemented + tested | `src/ai/tools/`, `tests/ai/sandbox.test.ts` |
| SSRF egress guard | ✅ Implemented + tested | `src/net/ssrfGuard.ts`, `tests/ai/ssrf.test.ts` |
| Non-root hardened container + healthcheck | ✅ Implemented | `docker/Dockerfile`, `docker/docker-compose*.yml` |
| CI: typecheck/build/test | ✅ Implemented | `.github/workflows/ci.yml` |
| Supply chain: lockfile/audit/SBOM/OSV/gitleaks | ✅ Implemented | `.github/workflows/security.yml` |
| OIDC SSO (PKCE) | ✅ Implemented + tested | `src/auth/oidc.provider.ts`, `tests/auth/oidc.test.ts` |
| SAML SSO | ⚠️ Stub (interface) | `src/auth/saml.provider.ts` (full impl P2) |
| MFA / TOTP + backup codes | ✅ Implemented + tested | `src/auth/mfa.ts`, `tests/auth/mfa.test.ts` |
| Streaming (SSE) LLM responses | ✅ Implemented + tested | `src/http/aiStream.ts`, `tests/ai/streaming.test.ts` |
| Document intelligence / RAG (pgvector) | ✅ Implemented + tested | `src/documents/`, `src/ai/embeddings/`, `tests/documents/` |
| Classification-aware ACL retrieval (app + RLS) | ✅ Implemented + tested | `src/documents/search.ts`, `src/db/sql/0004_documents.sql` |
| Document encryption at rest (per-tenant AES-256-GCM) | ✅ Implemented + tested | `src/documents/storage.ts`, `src/lib/crypto.ts` |
| GDPR erasure workflow (documents/chunks/messages) | ✅ Implemented + tested | `src/documents/erasure.ts`, `tests/documents/lifecycle.test.ts` |
| EU AI Act KI-Inventar (Art. 4) + PDF export | ✅ Implemented + tested | `src/compliance/inventory.ts`, `tests/compliance/` |
| Human oversight enforcement (Art. 14) | ✅ Implemented + tested | `src/compliance/oversight.ts`, sandbox integration |
| Transparency envelope (Art. 50) | ✅ Implemented + tested | `src/http/aiResponseEnvelope.ts` |
| Compliance report PDF (regulator-ready) | ✅ Implemented + tested | `src/compliance/report.ts`, `src/compliance/pdf.ts` |
| Admin console REST (users/stats/export) | ✅ Implemented + tested | `src/admin/`, `src/http/routes/admin.ts`, `tests/admin/` |
| Billing-ready metering (append-only) | ✅ Implemented + tested | `src/admin/metering.ts` |
| SSO production (per-tenant OIDC + auto-provision) | ✅ Implemented + tested | `src/admin/sso.ts`, `tests/admin/sso.test.ts` |
| API keys (scoped, per-key rate limit, audited) | ✅ Implemented + tested | `src/integrations/apiKeys.ts`, `src/http/apiKeyAuth.ts` |
| Outbound webhooks (HMAC, retries, dead-letter) | ✅ Implemented + tested | `src/integrations/webhooks.ts`, `tests/integrations/` |
| OpenAPI 3.1 spec (opt-in) | ✅ Implemented | `@fastify/swagger` at `/api/docs` (ENABLE_API_DOCS) |
| Admin console UI (htmx, no CDN, no build) | ✅ Implemented + tested | `src/http/admin-ui.ts`, `src/admin/views/`, `tests/http/admin-ui.test.ts` |
| SCIM provisioning | ❌ P2 | — |
| Cloud providers (OpenAI-compat, Anthropic) | ✅ Implemented + tested | `src/ai/providers/`, `tests/ai/cloud-providers.test.ts` |
| Encryption at rest (field-level, AES-256-GCM) | 🟡 Secrets (e.g. TOTP) | `src/lib/crypto.ts`; broader field-level + KMS is P2 |
| Per-token fine-grained scopes / API keys | ❌ P1/P2 | — |
| Security-event off-box anchoring | ❌ P1 | chain is local today |
| Admin console / SCIM provisioning | ❌ P2 | — |
| Process/microVM isolation for tools | ❌ P2 | capability-scoped in-process today |

## What "done" means here

All 62 tests run against a real PostgreSQL 16 (Testcontainers) and assert both
success and failure paths. Production startup is fail-closed. There is no mock
data on production code paths — demo/fixtures live only under `tests/`.

## Honest gaps & how to compensate today

1. **No SSO/MFA yet.** Mitigation: strong Argon2id local auth + the
   `AuthProvider` seam means OIDC/SAML drop in without changing call sites.
   For now, front the app with an SSO-capable reverse proxy if required.
2. **In-process tool sandbox.** Tools are trusted code constrained by capability
   scopes; this is not a substitute for kernel isolation. Do not register tools
   that execute untrusted code until the P2 microVM/worker isolation lands.
3. **Audit chain is local.** A DB superuser could rewrite and recompute it.
   Until off-box anchoring (P1), restrict superuser access and ship logs to an
   append-only sink.
4. **No field-level encryption.** Use encrypted storage/volumes and a managed
   Postgres with encryption at rest; secrets stay in a secret manager.
5. **DoS protections are per-instance.** Add a WAF/edge rate limiting for
   internet-facing deployments.

## Roadmap

- **P1 (delivered):** OIDC (PKCE) + MFA/TOTP; SSE streaming; cloud providers
  (OpenAI-compatible + Anthropic); AES-256-GCM secrets at rest.
- **Phase A (delivered):** Document Intelligence / RAG (pgvector, ACL search,
  GDPR erasure).
- **Phase B (delivered):** EU AI Act compliance — KI-Inventar (Art. 4), human
  oversight (Art. 14), transparency envelope (Art. 50), compliance report PDF.
- **Phase C (delivered):** Enterprise integrations — admin console (REST + htmx
  UI), billing-ready metering, GDPR data export, production SSO/OIDC with
  auto-provisioning, scoped API keys, signed outbound webhooks, OpenAPI.
- **P2 (next):** full SAML; microVM/worker isolation for tools; field-level
  encryption + KMS; SCIM provisioning; BSI-C5 readiness; admin console depth.
- **P1 (remaining):** scoped API tokens; security-event anchoring/log shipping;
  approval UI + notifications.
- **P2:** full SAML; microVM/worker isolation for dangerous tools; broader
  field-level encryption + KMS; GDPR erasure workflows; admin console + SCIM;
  anomaly detection.

## Compliance posture

Aligned with OWASP ASVS 5.0 (see
[`docs/security/ASVS_MAPPING.md`](./docs/security/ASVS_MAPPING.md)), OWASP Top 10
for LLM 2025 (see
[`docs/security/LLM_TOP_10_MAPPING.md`](./docs/security/LLM_TOP_10_MAPPING.md)),
NIST SSDF practices (lockfile, SBOM, scanning, reproducible builds), and
GDPR privacy-by-design (see [`PRIVACY_AND_GDPR.md`](./PRIVACY_AND_GDPR.md)).
