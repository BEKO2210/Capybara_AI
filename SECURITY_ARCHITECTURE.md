# Security Architecture

Capybara_AI is a multi-tenant, self-hostable AI system designed secure-by-default:
least privilege, defense in depth, fail-closed, and zero-trust between tenants.
This document describes the implemented architecture (not aspirations — see
[`ENTERPRISE_READINESS.md`](./ENTERPRISE_READINESS.md) for the honest gap list).

Stack: Node.js 22 · TypeScript (strict, ESM) · Fastify 5 · Drizzle ORM ·
PostgreSQL 16 (Row-Level Security) · Zod · Argon2id · Pino.

## The eight pillars

| # | Pillar | Module(s) | Core guarantee |
|---|---|---|---|
| 1 | Fail-closed config | `src/config/` | Prod refuses to start on missing/weak/placeholder secrets, wildcard CORS, non-TLS DB, insecure cookies. |
| 2 | Tenant isolation | `src/db/`, `src/tenancy/` | App runs as a **non-superuser, NOBYPASSRLS** role; Postgres RLS keys off a per-tx `app.current_org`. |
| 3 | Authentication | `src/auth/` | Argon2id hashing; opaque sessions stored only as SHA-256; OIDC/SAML-ready provider interface. |
| 4 | RBAC | `src/rbac/` | Least-privilege `owner/admin/member/viewer`; fail-closed guards. |
| 5 | HTTP hardening | `src/http/`, `src/server.ts` | helmet CSP/HSTS, strict CORS, CSRF, rate limit, leak-free errors, log redaction. |
| 6 | Audit + tamper-evidence | `src/audit/` | Hash-chained, append-only security log; UPDATE/DELETE revoked from app role. |
| 7 | LLM provider abstraction | `src/ai/providers/` | Server-only endpoints; callers cannot supply a base URL (no SSRF). |
| 8 | AI tool sandbox | `src/ai/tools/`, `src/net/ssrfGuard.ts` | Allowlist-only; default-empty fs/net/shell scopes; timeouts; human approval; redaction. |

## Defense-in-depth (request → data)

```
                         Internet / clients
                                │  (TLS terminated at reverse proxy — operator)
                                ▼
   ┌─────────────────────────── Fastify app (non-root container, uid 10001) ───────────────────────────┐
   │                                                                                                    │
   │  [helmet CSP/HSTS] → [CORS allowlist] → [rate limit] → [CSRF on mutations] → [Zod validation]      │  Pillar 5
   │                                                                                                    │
   │  ── Auth: validate opaque session (SHA-256 lookup) → load membership ──────────────────────────►  │  Pillar 3
   │       │  fail-closed: no/invalid/expired/revoked session ⇒ 401                                     │
   │       ▼                                                                                            │
   │  ── AuthContext { userId, orgId, role } (server-derived, never from client) ───────────────────►   │
   │       │                                                                                            │
   │       ▼                                                                                            │
   │  ── RBAC guard: requirePermission / requireRole ⇒ 403 if lacking ─────────────────────────────►   │  Pillar 4
   │       │                                                                                            │
   │       ▼                                                                                            │
   │  ── withTenant(orgId): open tx + SET LOCAL app.current_org ───────────────────────────────────►   │  Pillar 2
   │       │                                                                                            │
   │  ── AI calls ─► provider registry (server-only endpoint) ─► tool sandbox (allowlist + scopes +    │  Pillars 7,8
   │       │          ▲ no caller base_url                       timeout + approval + SSRF guard)       │
   │       ▼                                                                                            │
   │  ── audit_log (who/what) + hash-chained security_events (tamper-evident) ─────────────────────►    │  Pillar 6
   └────────┬───────────────────────────────────────────────────────────────────────────────────────┘
            ▼
   ┌──────────────────────────── PostgreSQL 16 ────────────────────────────┐
   │  Connection as role `capybara_app`  (NOSUPERUSER, NOBYPASSRLS)         │  ← zero-trust backstop
   │  RLS USING (org_id = current_setting('app.current_org'))               │
   │  security_events: GRANT SELECT,INSERT only (UPDATE/DELETE revoked)     │
   │  Migrations run separately as the PRIVILEGED role.                      │
   └────────────────────────────────────────────────────────────────────────┘
```

Two independent isolation layers (app-layer `withTenant` scoping **and**
database RLS under a non-bypass role) must BOTH fail to cross a tenant boundary.
Likewise SSRF is closed twice: provider endpoints are server-config-only, and
tool egress passes through `src/net/ssrfGuard.ts` (DNS-resolved private/loopback/
metadata ranges blocked).

## Fail-closed defaults (selected)

- Missing/weak production secret ⇒ process exits before binding (`src/config/config.ts`).
- No tenant context set ⇒ RLS returns zero rows (deny-by-default).
- Unknown/unregistered tool ⇒ denied (`src/ai/tools/registry.ts`).
- Tool with no fs/network/shell scope ⇒ those capabilities throw.
- Dangerous tool without approval ⇒ `pending_approval`, handler never runs.
- 5xx errors ⇒ generic body, full detail only in server logs (`src/http/errors.ts`).

## What is enforced where

- **Identity vs. authorization:** `users` are global; authorization within a
  tenant comes from `memberships(org_id, user_id, role)` — never from the user
  row or a client header.
- **Secrets:** only via environment/secret manager; `.env` is gitignored; the
  image bakes in none. `process.env` reads are confined to `src/config`.
- **Tests:** every pillar has integration tests proving happy-path AND
  failure/boundary behavior (see each test file under `tests/`).
