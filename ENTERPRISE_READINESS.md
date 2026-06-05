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
| SCIM 2.0 provisioning (RFC 7643/7644) | ✅ Implemented + tested | `src/integrations/scim.ts`, `tests/integrations/scim.test.ts` |
| Cloud providers (OpenAI-compat, Anthropic) | ✅ Implemented + tested | `src/ai/providers/`, `tests/ai/cloud-providers.test.ts` |
| Field-level encryption + key rotation (envelope) | ✅ Implemented + tested | `src/admin/encryption.ts`, `tests/admin/encryption.test.ts` |
| Layered rate limiting + storage quota | ✅ Implemented + tested | `src/http/rateLimits.ts`, `src/admin/storageQuota.ts`, `tests/admin/storageQuota.test.ts` |
| Brute-force lockout + admin unlock | ✅ Implemented + tested | `src/auth/abuseGuard.ts`, `tests/auth/abuseGuard.test.ts` |
| Backup/restore + disaster recovery runbook | ✅ Implemented | `scripts/backup.sh`, `scripts/restore.sh`, `docs/DISASTER_RECOVERY.md` |
| Deep health check (db/vector/backup/version) | ✅ Implemented + tested | `src/http/health.ts`, `tests/http/health.test.ts` |
| Per-token fine-grained scopes / API keys | ✅ Implemented + tested | `src/integrations/apiKeys.ts`, `src/http/apiKeyAuth.ts` |
| Security-event off-box anchoring | ❌ P3 | chain is local today; verify via `npm run verify:chain` |
| Process/microVM isolation for tools | ❌ P3 | capability-scoped in-process today |
| KMS-backed master key | 🟡 Env-supplied KEK | `MASTER_KEK`; external KMS integration is future work |

## What "done" means here

The full suite runs against a real PostgreSQL 16 (Testcontainers) and asserts
both success and failure paths. Production startup is fail-closed. There is no
mock data on production code paths — demo/fixtures live only under `tests/`.

## Honest gaps & how to compensate today

1. **In-process tool sandbox.** Tools are trusted code constrained by capability
   scopes; this is not a substitute for kernel isolation. Do not register tools
   that execute untrusted code until microVM/worker isolation lands (P3).
2. **Audit chain is local.** A DB superuser could rewrite and recompute it.
   Until off-box anchoring (P3), restrict superuser access, ship logs to an
   append-only sink, and run `npm run verify:chain` regularly (and post-restore).
3. **Master key is env-supplied.** Field-level encryption uses an envelope
   scheme (`MASTER_KEK` wraps per-org DEKs) with rotation, but the KEK comes from
   the environment. Source it from a secret manager; native KMS is future work.
4. **DoS protections are per-instance.** Layered rate limiting, per-org storage
   quota, and brute-force lockout are in-process; for internet-facing
   deployments add a WAF/edge rate limiting and sticky routing for stream caps.
5. **SAML is a stub.** OIDC SSO is delivered; full SAML is deferred (P3). Front
   with an SSO-capable reverse proxy if SAML is mandatory today.

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
- **Phase D / P2 (delivered):** SCIM 2.0 provisioning; field-level encryption +
  envelope key rotation; layered rate limiting, storage quota & brute-force
  lockout; backup/restore + disaster-recovery runbook; deep `/healthz`.
- **P3 (next):** full SAML; microVM/worker isolation for dangerous tools;
  security-event off-box anchoring/log shipping; KMS-backed master key;
  BSI-C5 readiness; approval UI + notifications; anomaly detection.

## Compliance posture

Aligned with OWASP ASVS 5.0 (see
[`docs/security/ASVS_MAPPING.md`](./docs/security/ASVS_MAPPING.md)), OWASP Top 10
for LLM 2025 (see
[`docs/security/LLM_TOP_10_MAPPING.md`](./docs/security/LLM_TOP_10_MAPPING.md)),
NIST SSDF practices (lockfile, SBOM, scanning, reproducible builds), and
GDPR privacy-by-design (see [`PRIVACY_AND_GDPR.md`](./PRIVACY_AND_GDPR.md)).
