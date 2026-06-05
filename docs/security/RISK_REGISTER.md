# Risk Register

Living record of security risks for Capybara_AI. Likelihood/Impact are
qualitative (Low/Med/High); residual risk is after the listed mitigations.
Owners are roles (fill with names per deployment). Review at least quarterly and
after any incident.

| ID | Risk | Likelihood | Impact | Mitigations (implemented) | Residual | Owner |
|---|---|---|---|---|---|---|
| R-01 | Cross-tenant data access | Med | High | Postgres RLS under NOBYPASSRLS role + app-layer `withTenant`; deny-by-default with no context; `WITH CHECK` blocks cross-tenant writes (`tests/db/rls.test.ts`) | Low | Eng lead |
| R-02 | Weak/leaked secrets in prod | Med | High | Fail-closed config rejects missing/weak/placeholder secrets, wildcard CORS, non-TLS DB (`src/config/`); secrets env-only; gitleaks in CI | Low | Security lead |
| R-03 | Credential stuffing / brute force | High | Med | Argon2id; rate limiting; security events on failures | Med — add account lockout/MFA (P1) | Security lead |
| R-04 | Session theft / fixation | Med | High | Opaque random tokens, only SHA-256 stored; `httpOnly`/`Secure`/`SameSite`; revocation + per-request re-validation | Low | Eng lead |
| R-05 | Privilege escalation (RBAC) | Med | High | Least-privilege matrix; fail-closed guards; role from `memberships`, never client input (`tests/rbac/`) | Low | Eng lead |
| R-06 | CSRF / XSS / clickjacking | Med | Med | CSRF tokens; helmet CSP (no inline, `frame-ancestors 'none'`); JSON API; nosniff (`tests/http/`) | Low | Eng lead |
| R-07 | SSRF via LLM endpoint or tool egress | Med | High | Server-only provider endpoints (no caller base_url); `ssrfGuard` blocks private/metadata ranges (`tests/ai/provider.test.ts`, `tests/ai/ssrf.test.ts`) | Low | Eng lead |
| R-08 | Prompt injection → unsafe action | High | High | Untrusted-context wrapping; server-side allowlist + capability scopes + human approval for dangerous tools | Low–Med (depends on registered tools) | AI/Eng lead |
| R-09 | Excessive agency / autonomous destruction | Med | High | Dangerous tools require approval keyed to exact args; no shell by default; timeouts (`tests/ai/sandbox.test.ts`) | Low | AI/Eng lead |
| R-10 | Tool capability escape (fs/shell) | Med | High | realpath+allowlist fs (no `..`/symlink); shell deny-by-default, `execFile` argv-only | Med — in-process, not kernel-isolated (P2) | AI/Eng lead |
| R-11 | Sensitive data sent to model/logs | Med | Med | Redaction before model calls and in records; Pino header redaction | Med — pattern-based, not exhaustive | AI/Eng lead |
| R-12 | Audit log tampering / repudiation | Low | High | Hash-chained append-only `security_events`; UPDATE/DELETE revoked from app role; `verifyChain()` (`tests/audit/`) | Med — DB superuser could rewrite + recompute; off-box anchoring is P1 | Security lead |
| R-13 | Vulnerable / malicious dependency | Med | High | Lockfile, `--ignore-scripts`, `npm audit`, OSV, SBOM, weekly scans | Low–Med | Security lead |
| R-14 | Insecure deployment / exposure | Med | High | Non-root container, loopback-by-default, no default creds, healthcheck, prod fail-closed; hardening checklist | Med — depends on operator (TLS proxy, DB encryption) | Ops owner |
| R-15 | Data subject rights / GDPR erasure gaps | Med | Med | Cascade delete of user data; data map + retention guidance | Med — first-class erasure workflow is P2; security log retention needs operator policy | DPO |
| R-16 | DoS / resource exhaustion | Med | Med | Per-route rate limits; per-tool + request timeouts | Med — no edge WAF/global quota (P1) | Ops owner |
| R-17 | Missing SSO/MFA for enterprise | High | Med | `AuthProvider` seam ready; can front with SSO proxy | Med until OIDC/SAML + MFA (P1) | Eng lead |

## Top residual risks to address next (P1)

1. **R-12** — anchor/ship the security-event chain off-box (signed checkpoints).
2. **R-03 / R-17** — account lockout, MFA, and OIDC/SAML.
3. **R-10** — process/microVM isolation before allowing untrusted-code tools (P2).

## Change log

- Initial register created alongside the P0 security foundation (config, RLS
  tenancy, auth, RBAC, HTTP hardening, audit chain, LLM provider, AI sandbox,
  Docker, CI, supply-chain scanning).
