# Security Policy

Capybara_AI is built secure-by-default. This document covers how to report a
vulnerability and which versions receive fixes. For the design rationale see
[`SECURITY_ARCHITECTURE.md`](./SECURITY_ARCHITECTURE.md) and
[`THREAT_MODEL.md`](./THREAT_MODEL.md).

## Reporting a vulnerability

**Do not open a public issue for security problems.**

- Preferred: open a [GitHub Security Advisory](https://docs.github.com/code-security/security-advisories)
  (private) on this repository.
- Or email the maintainers' security contact. _Self-hosters must set a real
  contact in their fork/deployment; the upstream placeholder is
  `security@REPLACE-ME.example`._

Please include: affected version/commit, a description, reproduction steps or a
proof-of-concept, and the impact you observed. We support coordinated
disclosure and will credit reporters who wish to be named.

### Response targets (best effort, pre-1.0)

| Stage | Target |
|---|---|
| Acknowledge report | 3 business days |
| Triage + severity (CVSS) | 7 business days |
| Fix or mitigation for High/Critical | 30 days |
| Public advisory | After a fix ships, coordinated with reporter |

## Supported versions

The project is pre-1.0. Only the latest `main` receives security fixes until a
tagged release line exists. Self-hosted deployments should track `main` or a
pinned commit and rebuild to pick up dependency and code fixes.

| Version | Supported |
|---|---|
| `main` (HEAD) | ✅ |
| older commits | ❌ rebase/rebuild |

## Scope

In scope: authentication/session handling, tenant isolation (app + Postgres
RLS), RBAC, input validation, the AI tool sandbox and approval flow, SSRF
controls, secret handling, and the security/audit logging in `src/`.

Out of scope: vulnerabilities that require a pre-existing superuser database
role, physical/host compromise, or third-party services you connect (e.g. your
own LLM endpoint or reverse proxy). See the threat model for trust boundaries.

## Hardening & operations

Operators should follow [`DEPLOYMENT_SECURITY.md`](./DEPLOYMENT_SECURITY.md) and
[`INCIDENT_RESPONSE.md`](./INCIDENT_RESPONSE.md). Production refuses to start
without strong secrets (fail-closed); never disable that check.
