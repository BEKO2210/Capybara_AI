# Capybara_AI

Enterprise, security-first, self-hostable AI system. Built secure-by-default
from the first commit: multi-tenant, zero-trust, fail-closed.

> **Status: P0 secure foundation (in progress).** The core security pillars are
> implemented and tested. Packaging (Docker hardening, CI/supply-chain) and the
> full security-document suite are still pending. See [Scope](#scope) below.

## Scope

Eight foundation pillars, each with passing integration tests proving they
**work and fail correctly** (62 tests total):

1. **Fail-closed configuration** (`src/config/`) — production refuses to start
   when required secrets are missing, weak, placeholder, or when CORS is
   wildcarded / cookies are insecure / the DB URL lacks TLS. Dev uses
   clearly-ephemeral generated secrets — no insecure defaults.
2. **Database + PostgreSQL Row-Level Security** (`src/db/`, `src/tenancy/`) —
   tenant isolation at the **database** layer. The app connects as a restricted
   `capybara_app` role (non-superuser, **NOBYPASSRLS**); RLS keys off a
   per-transaction `app.current_org` GUC set via `withTenant()`. Deny-by-default
   when no tenant context is set.
3. **Auth abstraction** (`src/auth/`) — Argon2id hashing, an OIDC/SAML-ready
   `AuthProvider` interface, a local dev provider, and opaque server-side
   sessions storing **only the SHA-256 hash** of the token.
4. **RBAC** (`src/rbac/`) — least-privilege `owner/admin/member/viewer`
   capability matrix; fail-closed Fastify guards (401/403).
5. **HTTP security middleware** (`src/http/`, `src/server.ts`) — helmet CSP,
   strict CORS (no wildcard), CSRF on state-changing routes, rate limiting,
   fail-closed error handler that never leaks internals.
6. **Audit + tamper-evident security log** (`src/audit/`) — queryable audit
   trail plus a hash-chained, append-only security-event log (UPDATE/DELETE
   revoked from the app role) with an offline chain verifier.
7. **LLM provider abstraction** (`src/ai/providers/`) — server-only endpoints;
   callers select a provider by id and **cannot** supply a base URL (closes the
   SSRF-via-base_url gap). OpenAI-compatible adapter (Ollama/vLLM).
8. **AI tool sandbox** (`src/ai/tools/`, `src/net/ssrfGuard.ts`) — allowlist-only
   registry; default-empty fs/network/shell capability scopes; per-tool
   timeouts; **human approval required for dangerous actions**; output
   redaction; untrusted-context wrapping for prompt-injection defense.

**Packaging & docs (P0 complete):**
- **Docker** — multi-stage, non-root (uid 10001), healthchecked image
  (`docker/Dockerfile`); dev + prod compose with no default credentials,
  loopback binds, `read_only`/`cap_drop`/`no-new-privileges` (`docker/`).
- **CI** — `.github/workflows/ci.yml` (typecheck + build + real Testcontainers
  tests) and `security.yml` (npm audit, OSV, gitleaks, CycloneDX SBOM; weekly).
- **Security docs** — `SECURITY.md`, `SECURITY_ARCHITECTURE.md`,
  `THREAT_MODEL.md`, `ENTERPRISE_READINESS.md`, `PRIVACY_AND_GDPR.md`,
  `AI_SECURITY_MODEL.md`, `SUPPLY_CHAIN_SECURITY.md`, `DEPLOYMENT_SECURITY.md`,
  `INCIDENT_RESPONSE.md`, and `docs/security/{ASVS_MAPPING,LLM_TOP_10_MAPPING,RISK_REGISTER}.md`.

**P1 (delivered):** OIDC SSO (PKCE) + SAML stub (`src/auth/oidc.provider.ts`,
`src/auth/saml.provider.ts`); MFA/TOTP with backup codes (`src/auth/mfa.ts`);
SSE streaming (`src/http/aiStream.ts`); cloud providers — OpenAI-compatible +
Anthropic (`src/ai/providers/`); AES-256-GCM secrets at rest (`src/lib/crypto.ts`).

**Deferred to P1-remaining/P2:** full SAML, scoped API tokens, off-box audit
anchoring, broader field-level encryption/KMS, and process/microVM isolation for
tools. See [`ENTERPRISE_READINESS.md`](./ENTERPRISE_READINESS.md).

## Tech stack

Node.js 22 · TypeScript (strict, ESM) · Fastify (P0) · Drizzle ORM ·
PostgreSQL 16 (RLS) · Zod · Argon2id · Vitest + Testcontainers · Apache-2.0.

## Running the tests

Tests spin up a real PostgreSQL 16 via **Testcontainers**, so a working Docker
daemon is required.

```bash
npm install
npm run typecheck
npm test
```

Expected: 9 test files, 62 tests passing.

## Configuration

All environment variables are documented in [`.env.example`](./.env.example).
In `production`, `loadConfig()` aggregates every problem and exits rather than
starting with an insecure default (fail-closed).

## Security model (so far)

- **Least privilege at the DB:** migrations run as a privileged role; the app
  runs as `capybara_app` which cannot bypass RLS.
- **Defense in depth for tenancy:** application-layer scoping (`withTenant`)
  **and** database-layer RLS — both must be bypassed to cross a tenant boundary.
- **Fail-closed everywhere:** invalid config aborts startup; unknown tenant
  context returns zero rows; auth failures and tampered sessions return `null`,
  never an exception mistaken for success.
- **No secrets in code or VCS:** secrets come from the environment; `.env` is
  gitignored; `.env.example` ships only rejected placeholders.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).
