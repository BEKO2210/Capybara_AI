# BSI IT-Grundschutz — Readiness Mapping

A pragmatic mapping of relevant **BSI IT-Grundschutz** building blocks (Bausteine)
to Capybara_AI controls, for organizations pursuing IT-Grundschutz / BSI-C5
alignment. This is a *readiness aid*, not a certification; certification requires
an audited ISMS in your operating environment.

> Scope note: many requirements are **operational** (your processes, hosting,
> personnel). Capybara_AI provides the *product-side* controls; the operator
> supplies the surrounding ISMS, physical security, and procedures.

## APP.3.1 — Web Applications

| Requirement (sinngemäß) | Capybara_AI control |
| --- | --- |
| Authentication & session security | Argon2id, opaque server sessions (only SHA-256 stored, revocable), TOTP MFA, OIDC + **SAML 2.0** SSO |
| Access control / least privilege | RBAC (`owner/admin/member/viewer`), deny-by-default guards (401/403) |
| Input validation & output handling | Zod validation on every route; strict CSP (no inline), CSRF, security headers |
| Protection against injection/SSRF | Parameterized queries (Drizzle), server-only LLM endpoints + SSRF egress guard |
| Controlled errors | Fail-closed error handler; no stack/secret leakage in production |

## ORP.4 — Identity and Access Management

| Requirement | Control |
| --- | --- |
| Central identity / provisioning | **SCIM 2.0** (RFC 7643/7644), OIDC/SAML federation |
| Strong authentication | MFA (TOTP) + single-use backup codes |
| Lifecycle (joiner/mover/leaver) | Invite/role-change/deactivate flows; SCIM deprovisioning (soft-deactivate) |
| Brute-force protection | Account lockout with exponential backoff + admin unlock |

## CON.1 — Crypto Concept

| Requirement | Control |
| --- | --- |
| Encryption at rest | AES-256-GCM; per-tenant HKDF subkeys; envelope encryption (KEK→DEK) |
| Key management & rotation | Versioned per-org DEKs with rotation; **key source** from env / file / command (Vault, AWS KMS) — `docs/security/AUDIT_ANCHORING_AND_KMS.md` |
| Transport security | TLS enforced for DB in production; HSTS; secure cookies |

## OPS.1.1.5 — Logging  ·  DER.1 — Detecting Security Incidents

| Requirement | Control |
| --- | --- |
| Tamper-evident audit logging | Hash-chained `security_events` (append-only; UPDATE/DELETE revoked) |
| Log integrity beyond the host | **Off-box Ed25519 anchoring** — signed checkpoints verifiable with an off-box key |
| Attack detection | **Anomaly detection** over the audit stream (lockout/role-change/rotation bursts → `security.anomaly`) |
| Auditability of decisions | EU AI Act human-oversight decisions recorded in the tamper-evident log |

## OPS.1.2.4 — Backup  ·  DER.4 — Business Continuity

| Requirement | Control |
| --- | --- |
| Regular, restorable backups | `scripts/backup.sh` (retention, optional GPG) + Compose backup profile |
| Documented recovery | `docs/DISASTER_RECOVERY.md` runbook with RPO/RTO + verification checklist |
| Health/readiness | Deep `/healthz` (db / vector / backup / version → 200/503) |

## SYS.1.6 / APP.4.4 — Containerization

| Requirement | Control |
| --- | --- |
| Least-privilege containers | Non-root, `cap_drop ALL`, `no-new-privileges`, read-only FS |
| Network exposure minimization | App bound to loopback; Postgres not published; restricted DB role (NOBYPASSRLS) |
| Untrusted code isolation | Tools requiring isolation **fail closed** unless an external isolation runner (container/microVM) is wired |

## CON.2 — Data Protection (DSGVO interplay)

| Requirement | Control |
| --- | --- |
| Data minimization & purpose | `PRIVACY_AND_GDPR.md` data map; classification-based ACL |
| Right to erasure | Atomic GDPR erasure (documents/chunks/messages; log anonymization) |
| Transparency of AI processing | EU AI Act transparency envelope on every AI response; KI-Inventar |

## Supply chain (CON.8 — Software Development)

| Requirement | Control |
| --- | --- |
| Dependency & secret hygiene | `npm audit`, OSV scan, gitleaks, CycloneDX SBOM in CI |
| Reproducible, reviewed changes | Lockfile, strict typecheck, integration tests on real Postgres, PR-based workflow |

---

### Gaps / operator responsibilities

- **ISMS, risk treatment, personnel & physical security** are out of product scope.
- **Native in-process KMS client**, full **microVM tool isolation**, and a managed
  **SIEM integration** are roadmap (P3+); the seams (key-source command, isolation
  runner, anomaly events/notifications) are in place to integrate them.
