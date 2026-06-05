# Capybara_AI

Enterprise, security-first, self-hostable AI system. Built secure-by-default
from the first commit: multi-tenant, zero-trust, fail-closed.

> **Status: foundation slice.** This commit delivers a reviewable *thin vertical
> slice* of the secure foundation — not the full product. See
> [Scope](#scope-of-this-slice) below.

## Scope of this slice

Three foundation pillars, each with a passing integration test that proves it
**works and fails correctly**:

1. **Fail-closed configuration** (`src/config/`) — the app refuses to start in
   production when required secrets are missing, weak, placeholder, or when CORS
   is wildcarded / cookies are insecure / the DB URL lacks TLS. Development uses
   clearly-ephemeral generated secrets so local work needs no insecure defaults.
2. **Database + PostgreSQL Row-Level Security** (`src/db/`, `src/tenancy/`) —
   tenant isolation enforced at the **database** layer. The app connects as a
   restricted `capybara_app` role (non-superuser, **NOBYPASSRLS**). RLS policies
   key off a per-transaction `app.current_org` GUC set via `withTenant()`. A
   forgotten `WHERE` cannot leak across tenants; deny-by-default when no tenant
   context is set.
3. **Auth abstraction** (`src/auth/`) — Argon2id password hashing, an
   OIDC/SAML-ready `AuthProvider` interface, a local dev provider, and opaque
   server-side sessions that store **only the SHA-256 hash** of the token.

Deferred to the full P0 build (not in this slice): RBAC guards, HTTP security
middleware (helmet/CSRF/CORS/rate-limit), audit + tamper-evident logging, the AI
provider + tool sandbox, Docker hardening, CI, and the security document suite.

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

Expected: 3 test files, 20 tests passing (config / RLS isolation / auth).

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
