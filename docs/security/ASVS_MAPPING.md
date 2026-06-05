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

## Delivered in P1

- **V10 OIDC** (PKCE) and **MFA/TOTP** with backup codes (`src/auth/oidc.provider.ts`,
  `src/auth/mfa.ts`); TOTP secrets encrypted at rest via AES-256-GCM (`src/lib/crypto.ts`).
- Streaming (SSE) responses and cloud providers (OpenAI-compatible, Anthropic).

## Notable not-yet (tracked in ENTERPRISE_READINESS / RISK_REGISTER)

- Full **SAML** (typed stub only) — P2.
- Broad field-level encryption at rest / KMS — P2 (TOTP secrets already encrypted).
- Process/microVM isolation for tool execution — P2.
