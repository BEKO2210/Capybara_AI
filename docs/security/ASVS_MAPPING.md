# OWASP ASVS 5.0.0 Mapping

Maps OWASP Application Security Verification Standard 5.0.0 chapters to the
Capybara_AI implementation. Status legend: ✅ implemented & tested ·
🟡 partial / by-configuration · ⛔ not yet (roadmap). Evidence cites the
implementing module and, where applicable, the test.

| ASVS 5.0 chapter | Control intent | Status | Evidence |
|---|---|---|---|
| **V1 Encoding & Sanitization** | Output handled safely; untrusted data marked | ✅/🟡 | CSP blocks inline script (`src/http/security.ts`); LLM/tool content wrapped as untrusted (`src/ai/prompt/untrustedContext.ts`). API is JSON; no server-side HTML templating. |
| **V2 Validation & Business Logic** | Validate all input against a positive schema | ✅ | Zod schemas for env (`src/config/env.schema.ts`), provider config (`registry.ts`), and tool args (validated in `src/ai/tools/sandbox.ts`); invalid args ⇒ denied. `tests/ai/sandbox.test.ts` |
| **V3 Web Frontend Security** | CSP, anti-clickjacking, CSRF, secure cookies | ✅ | helmet CSP (`frame-ancestors 'none'`, no inline), `@fastify/csrf-protection`, `httpOnly`/`Secure`/`SameSite` cookies. `tests/http/security.test.ts` |
| **V4 API & Web Service** | Rate limiting, method/CORS control, safe errors | ✅ | `@fastify/rate-limit`, strict `@fastify/cors` (no wildcard in prod), fail-closed error handler (`src/http/errors.ts`). `tests/http/security.test.ts` |
| **V5 File Handling** | Path traversal, upload validation, AV scanning | ✅ | Tool fs realpath+allowlist (`src/ai/tools/scopes/fs.scope.ts`). Document uploads: MIME allowlist, size cap, optional fail-closed ClamAV scan, encrypted-at-rest storage under random UUID names (`src/documents/`, `src/http/routes/documents.ts`). `tests/http/documents-http.test.ts`, `tests/documents/rag-pipeline.test.ts` |
| **V6 Authentication** | Strong hashing, fail-closed, anti-enumeration | ✅ | Argon2id (`src/auth/password.ts`); dummy-verify on unknown user; production requires strong secrets (`src/config/`). `tests/auth/auth.test.ts`, `tests/config/failClosed.test.ts` |
| **V7 Session Management** | Opaque, revocable, server-side sessions | ✅ | Random opaque token; only SHA-256 stored; re-validated each request; revocation + expiry honored (`src/auth/session.ts`). `tests/auth/auth.test.ts` |
| **V8 Authorization** | Least privilege; enforced server-side; multi-tenant + data-classification isolation | ✅ | RBAC matrix + guards (`src/rbac/`); Postgres RLS under NOBYPASSRLS role + `withTenant` (`src/tenancy/`, `src/db/sql/0001_rls_and_grants.sql`). Document classification clearance enforced at app layer AND RLS (`src/db/sql/0004_documents.sql`). `tests/rbac/`, `tests/db/rls.test.ts`, `tests/documents/rag-pipeline.test.ts` |
| **V9 Self-contained Tokens** | JWT pitfalls avoided | ✅ | P0 uses opaque DB-backed sessions (no JWT), eliminating self-contained-token risks; a signed-token path would reuse the validated `SESSION_SECRET`. |
| **V10 OAuth & OIDC** | Federated auth done correctly | ✅/🟡 | OIDC authorization-code flow with **PKCE** (no implicit), state+nonce, JWKS signature verification + issuer/audience/expiry checks with clock-skew tolerance (`src/auth/oidc.provider.ts`, `tests/auth/oidc.test.ts`). SAML is a typed stub (P2). |
| **V11 Cryptography** | Modern algorithms; strong secrets; no weak defaults | ✅ | Argon2id; SHA-256 for token/at-rest hashing & audit chain (`src/lib/hash.ts`); secret-strength validation rejects weak/placeholder values (`src/config/secrets.ts`). `tests/config/failClosed.test.ts` |
| **V12 Secure Communication** | TLS enforced | 🟡 | DB TLS required in prod (`sslmode=require`, `src/config/config.ts`); app TLS terminated at the operator's reverse proxy (`DEPLOYMENT_SECURITY.md`); HSTS set in prod (`src/http/security.ts`). |
| **V13 Configuration** | Fail-closed, secrets management, hardened defaults | ✅ | Fail-closed `loadConfig`; secrets only via env (`process.env` confined to `src/config`); non-root, minimal, healthchecked container (`docker/`). `tests/config/failClosed.test.ts` |
| **Logging & error handling** (cross-cutting) | Tamper-evident security logging; no sensitive data in logs | ✅ | Hash-chained `security_events` (append-only, `src/audit/`); Pino redaction of auth/cookie headers (`src/server.ts`). `tests/audit/chain.test.ts` |
| **SSRF defense** (API/comms) | Block internal/metadata targets | ✅ | Server-only LLM endpoints + `src/net/ssrfGuard.ts`. `tests/ai/provider.test.ts`, `tests/ai/ssrf.test.ts` |

## Enterprise integrations (Phase C)

- **API keys** (`src/integrations/apiKeys.ts`, `src/http/apiKeyAuth.ts`): random
  keys, only SHA-256 hashes stored, explicit scopes, expiry/revocation, **per-key
  rate limiting**, and every request audited. (ASVS V6/V7/V8.)
- **Outbound webhooks** (`src/integrations/webhooks.ts`): HMAC-SHA256 signed
  payloads, retries + dead-letter, encrypted secrets at rest, delivery log.
- **Admin console** REST + htmx UI (`src/http/routes/admin.ts`, `admin-ui.ts`):
  admin+ gated, CSRF-protected forms, **no external CDN** (bundled htmx), stats
  contain aggregates only (no PII).
- **GDPR data export** (`src/admin/export.ts`): encrypted ZIP, 1-hour signed
  download token, artifact deleted after download. (Art. 20.)
- **Production SSO/OIDC** (`src/admin/sso.ts`): per-tenant config (client secret
  AES-256-GCM encrypted), discovery validation, auto-provisioning. (ASVS V10.)
- **Metering** (`src/admin/metering.ts`): append-only (INSERT/SELECT grants only).
- **OpenAPI** served only when `ENABLE_API_DOCS=true` (off by default).

## Governance (EU AI Act, beyond ASVS)

- **KI-Inventar (Art. 4):** org-scoped AI usage registry, auto-populated, PDF
  export (`src/compliance/inventory.ts`, `src/compliance/pdf.ts`).
- **Human oversight (Art. 14):** DB-backed, forward-only, audited approval for
  HIGH/CRITICAL tools (`src/compliance/oversight.ts`).
- **Transparency (Art. 50):** `ai_meta` envelope on every AI response
  (`src/http/aiResponseEnvelope.ts`).
- **Compliance report:** regulator-/works-council-ready German PDF
  (`src/compliance/report.ts`). Endpoints are RBAC-gated (admin/owner). Tests in
  `tests/compliance/`.

## Delivered in P1

- **V10 OIDC** (PKCE) and **MFA/TOTP** with backup codes (`src/auth/oidc.provider.ts`,
  `src/auth/mfa.ts`); TOTP secrets encrypted at rest via AES-256-GCM (`src/lib/crypto.ts`).
- Streaming (SSE) responses and cloud providers (OpenAI-compatible, Anthropic).

## Delivered in Phase D / P2 (production hardening)

- **V2/V4 Account lockout:** brute-force lockout with a sliding failure window
  and exponential backoff; admin unlock endpoint; events recorded in the
  tamper-evident log (`src/auth/abuseGuard.ts`, `tests/auth/abuseGuard.test.ts`).
- **V6 Cryptography at rest:** field-level encryption via envelope scheme — a
  master KEK wraps per-org DEKs — with **key rotation** that re-encrypts chunk
  and message ciphertext and retains retired key versions
  (`src/admin/encryption.ts`, `tests/admin/encryption.test.ts`).
- **V11 Business-logic / anti-automation:** layered rate limiting per
  IP/account/LLM/upload, in-process per-org concurrent-stream cap, and per-org
  storage quota (413 + quota headers) (`src/http/rateLimits.ts`,
  `src/admin/storageQuota.ts`).
- **V12 Provisioning:** SCIM 2.0 (RFC 7643/7644) user/group provisioning with
  org-scoped bearer tokens (`src/integrations/scim.ts`, guides under
  `docs/guides/SCIM_*.md`).
- **Operational resilience:** backup/restore scripts, disaster-recovery runbook,
  and a deep `/healthz` (db/vectorSearch/backup/version → 200/503)
  (`scripts/`, `docs/DISASTER_RECOVERY.md`, `src/http/health.ts`).

## Delivered post-1.0 (review hardening)

- **V7 Logging integrity:** off-box **Ed25519 audit anchoring** — signed
  checkpoints over the chain head make a DB-superuser rewrite detectable with a
  public key held off the database (`src/audit/anchor.ts`,
  `tests/audit/anchor.test.ts`; `npm run audit:anchor` / `verify:chain`).
- **V6 Key management:** pluggable **key source** — at-rest keys can be projected
  from a KMS / secret-manager sidecar as files (`KEY_SOURCE=file`), fail-closed
  on unreadable files (`src/config/keySource.ts`, `tests/config/keySource.test.ts`).
- **V11 Anti-automation at scale:** shared rate-limit store seam
  (`buildServer({ rateLimitRedis })`) for one global budget across replicas.

## Delivered in P3

- **V2 Authentication:** **SAML 2.0** SP (SP-initiated POST binding) with signed
  assertions verified via `@node-saml/node-saml`; signature/audience/expiry
  enforced, fail-closed (`src/auth/saml.provider.ts`, `tests/auth/saml.test.ts`).
- **V6 Key management:** native KMS key source `KEY_SOURCE=command` (Vault / AWS
  KMS CLI), fail-closed on non-zero exit (`src/config/keySource.ts`).
- **V10/V1 Malicious code isolation:** tools marked `requiresIsolation` are
  denied unless an external `IsolationRunner` is wired — untrusted code never
  runs in-process (`src/ai/tools/sandbox.ts`).
- **V7 / DER.1 Attack detection:** anomaly detection over the audit stream raises
  tamper-evident `security.anomaly` events with notifications
  (`src/security/anomaly.ts`).
- **V14 Governance:** BSI IT-Grundschutz readiness mapping
  (`docs/security/BSI_GRUNDSCHUTZ_MAPPING.md`).

## Notable not-yet (tracked in ENTERPRISE_READINESS / RISK_REGISTER)

- Bundled **microVM/gVisor tool runner** (fail-closed isolation seam is in place) — P4.
- Native in-process **KMS decrypt client** (env/file/command sources available) — P4.
- SAML **`InResponseTo` replay cache** (signature/audience/expiry enforced today) — P4.
