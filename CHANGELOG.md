# Changelog

All notable changes to Capybara_AI are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — post-1.0 review hardening
- **Off-box audit anchoring** (Ed25519): signed checkpoints commit to the
  security-event chain head so a DB-superuser rewrite is detectable with a public
  key held off the database. New `npm run audit:anchor`; `npm run verify:chain`
  now also verifies anchors. Append-only `audit_anchors` table + optional
  `anchors.jsonl` off-box sink.
- **KMS / secret-manager key source** (`KEY_SOURCE=file`): at-rest keys can be
  projected from files mounted by a Vault/CSI/Docker-secret sidecar; fail-closed
  on unreadable files.
- **Shared rate-limit store seam** (`buildServer({ rateLimitRedis })`) for one
  global rate-limit budget across horizontally scaled replicas.
- **Internationalization**: full English README (`README.en.md`) with a language
  switcher.
- New guide: `docs/security/AUDIT_ANCHORING_AND_KMS.md`.

## [1.0.0] — 2026-06-05

First public release. A complete, security-first, self-hostable AI workspace
built secure-by-default from the first commit.

### Added

**Secure foundation (P0)**
- Fail-closed configuration: production refuses to start on missing/weak/
  placeholder secrets, wildcard CORS, insecure cookies, or a non-TLS DB URL.
- Multi-tenant PostgreSQL with Row-Level Security under a restricted
  `capybara_app` role (NOSUPERUSER, NOBYPASSRLS) and per-transaction tenant GUCs.
- Local Argon2id auth with opaque server-side sessions (only SHA-256 hashes
  stored, revocable, re-validated per request).
- RBAC capability matrix (`owner/admin/member/viewer`) with fail-closed guards.
- HTTP hardening: Helmet CSP/HSTS, strict CORS, CSRF, rate limiting, Zod
  validation, secret/PII-redacting structured logs, fail-closed error handler.
- Tamper-evident, hash-chained `security_events` with an offline verifier
  (`npm run verify:chain`); business `audit_log`.
- LLM provider abstraction with **server-only** endpoints (closes the
  `base_url`-SSRF class) and an SSRF-guarding egress dispatcher.
- AI tool sandbox skeleton: allowlist registry, capability scopes, timeouts,
  human approval, redaction, untrusted-context wrapping.
- Hardened Docker (non-root, `cap_drop ALL`, `no-new-privileges`, read-only FS),
  Compose stacks, CI (typecheck/build/test) + security workflow
  (npm audit, OSV, gitleaks, CycloneDX SBOM).

**Auth providers & streaming (P1)**
- OIDC SSO (PKCE auth-code flow), TOTP MFA with single-use backup codes,
  streaming completions, and cloud providers (OpenAI, Anthropic) behind the
  same provider interface.

**Document intelligence / RAG (Phase A)**
- pgvector semantic search, ingestion pipeline, classification-based ACL,
  optional ClamAV scanning, document lifecycle (versions, legal hold,
  retention), and GDPR-aware deletion.

**EU AI Act compliance (Phase B)**
- Transparency envelope on every AI response, auto-populated KI-Inventar
  (AI inventory), human-oversight workflow, and a compliance report.

**Enterprise integrations (Phase C)**
- Admin console (users, stats, metering, export), production SSO config,
  webhooks with signing + retries, scoped API keys, and an htmx admin frontend.

**Production hardening (Phase D / P2)**
- **SCIM 2.0** user/group provisioning (RFC 7643/7644) with per-org bearer tokens.
- **Field-level encryption** with envelope encryption (master KEK wraps per-org
  DEKs) and **key rotation** that re-encrypts chunks + messages and retains old
  key versions for auditability.
- **Layered rate limiting** (per IP/account/LLM/upload), per-org **storage
  quota** (413 + quota headers), and **brute-force lockout** with exponential
  backoff plus an admin unlock endpoint.
- **Backup/restore** scripts (`scripts/backup.sh`, `scripts/restore.sh`) with
  retention and optional GPG encryption, a Compose backup profile, and a
  **Disaster Recovery runbook**.
- Deep `/healthz` reporting status, database, vector search, last backup, and
  build version (200 when healthy, 503 when degraded/down).

### Security
- OWASP ASVS 5.0 and OWASP Top 10 for LLM/GenAI 2025 mappings to implementing
  modules and tests; GDPR/DSGVO data map; threat model; incident response and
  deployment-security runbooks.

[1.0.0]: https://github.com/BEKO2210/Capybara_AI/releases/tag/v1.0.0
