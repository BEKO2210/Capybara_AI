# Threat Model

Scope: the Capybara_AI application as implemented in `src/`, its PostgreSQL
data store, and the AI provider/tool subsystem. Methodology: asset inventory →
trust boundaries → STRIDE per component → mitigations → residual risk. Tracked
risks are quantified in [`docs/security/RISK_REGISTER.md`](./docs/security/RISK_REGISTER.md).

## Assets

| Asset | Sensitivity | Where |
|---|---|---|
| User credentials (Argon2id hashes) | High | `users.password_hash` |
| Session tokens | High | client cookie (raw) / `sessions.token_hash` (SHA-256) |
| Tenant data + membership/roles | High | `organizations`, `memberships`, app tables (RLS) |
| Audit & security event log | High (integrity) | `audit_log`, `security_events` (hash-chained) |
| Application secrets | Critical | environment / secret manager only |
| LLM provider endpoints/keys | High | server config (`LLM_PROVIDERS`) |
| AI tool capabilities (fs/net/shell) | Critical | `src/ai/tools/` scopes |

## Trust boundaries

1. Internet ↔ reverse proxy (TLS termination — operator responsibility).
2. Reverse proxy ↔ app (Fastify, non-root container).
3. App ↔ PostgreSQL (app connects as restricted `capybara_app` role).
4. App ↔ LLM provider (server-configured endpoint; egress).
5. Model output / retrieved content ↔ app (treated as **untrusted data**).
6. Tenant A ↔ Tenant B (zero-trust; enforced at app + DB layers).

## Threat actors

- **Unauthenticated external attacker** — probes endpoints, injection, SSRF.
- **Authenticated low-privilege user / cross-tenant attacker** — tries to read
  or write another tenant's data, or escalate role.
- **Malicious / compromised tool input or prompt-injection** — content that
  tries to make the agent exfiltrate data or call dangerous tools.
- **Compromised application process** — attempts to tamper with the audit log
  or reach internal network services.
- **Supply-chain attacker** — malicious dependency or build tampering.

## STRIDE per component

### Auth & sessions (`src/auth/`)
- **Spoofing:** opaque random tokens; only SHA-256 stored; session re-validated
  against the user every request → revoked/deleted users rejected. Mitigates
  token forgery and orphaned sessions.
- **Tampering:** tokens are random, not client-derived; cookies `httpOnly`,
  `Secure` (forced in prod), `SameSite=Lax`.
- **Info disclosure:** raw token never persisted; password only as Argon2id;
  login failures return null with a dummy verify to flatten timing/enumeration.
- **Elevation:** authentication yields identity only; tenant role comes from
  `memberships`. Residual: MFA not yet implemented (P1).

### Tenancy (`src/db/`, `src/tenancy/`)
- **Tampering / Info disclosure (cross-tenant):** Postgres RLS under a
  NOBYPASSRLS role; `WITH CHECK` blocks cross-tenant writes; unset context →
  zero rows. App-layer `withTenant` is a second gate. Tested in
  `tests/db/rls.test.ts`.
- **Elevation:** the app role cannot disable RLS or bypass it; migrations use a
  separate privileged role.

### RBAC (`src/rbac/`)
- **Elevation:** capability matrix is least-privilege and additive; guards fail
  closed (401/403). Unknown role → no permissions. Tested in `tests/rbac/`.

### HTTP layer (`src/http/`, `src/server.ts`)
- **Tampering (CSRF):** `@fastify/csrf-protection` on state-changing routes.
- **Info disclosure (XSS/clickjacking):** helmet CSP (`frame-ancestors 'none'`,
  no inline script), `nosniff`, `no-referrer`; error handler never leaks
  internals; Pino redacts `authorization`/`cookie`/CSRF headers.
- **DoS:** per-IP + per-route rate limiting. Residual: no WAF/global quota (P1).
- **SSRF:** see provider/sandbox below.

### LLM provider (`src/ai/providers/`)
- **SSRF / tampering:** endpoints come only from server config; a caller cannot
  supply `base_url` (extra fields ignored). Tested in `tests/ai/provider.test.ts`.
- **Info disclosure:** provider keys live in server config, never returned to
  clients.

### AI tool sandbox (`src/ai/tools/`, `src/net/ssrfGuard.ts`)
- **Elevation / Tampering (capability escape):** allowlist-only registry;
  default-empty fs/network/shell scopes; fs paths realpath-checked against an
  allowlist (no `..`/symlink escape); shell denied by default and `execFile`
  argv-only (no shell injection); per-tool timeout.
- **SSRF:** tool egress blocks private/loopback/link-local/metadata ranges
  (incl. `169.254.169.254`) unless explicitly opted in.
- **Prompt injection (Repudiation/Tampering of intent):** retrieved/tool content
  wrapped as untrusted data (not instructions); system safety preamble; the
  server-side allowlist + approval are the real boundary, not the prompt.
- **No autonomous destruction:** dangerous tools require human approval keyed to
  the exact arguments. Tested in `tests/ai/sandbox.test.ts`.
  Residual: in-process tools are trusted code constrained by capabilities;
  untrusted/arbitrary code execution requires process/microVM isolation (P2).

### Audit & security log (`src/audit/`)
- **Repudiation / Tampering:** hash-chained `security_events`; `UPDATE`/`DELETE`
  revoked from the app role; `verifyChain()` detects any mutation. Tested in
  `tests/audit/chain.test.ts`. Residual: a DB superuser can still rewrite +
  recompute the chain — mitigate by shipping/anchoring hashes off-box (P1).

### Configuration & secrets (`src/config/`)
- **Info disclosure / misconfig:** fail-closed validation; secrets never logged
  (only variable + reason); `process.env` confined to `src/config`.

### Supply chain (build/deps)
- **Tampering:** committed lockfile, `npm ci --ignore-scripts`, `npm audit`,
  OSV scan, gitleaks, CycloneDX SBOM (see
  [`SUPPLY_CHAIN_SECURITY.md`](./SUPPLY_CHAIN_SECURITY.md)).

## Out of scope / assumptions

- TLS is terminated by an operator-managed reverse proxy.
- The PostgreSQL superuser and host are trusted; an attacker with superuser DB
  access or host root is outside the model (defended only by tamper-evidence).
- The configured LLM endpoint is operated by the deployer.
