# Privacy & GDPR/DSGVO

Privacy-by-design and security-of-processing notes for operators deploying
Capybara_AI. This describes the data the software handles **as implemented**;
each self-hosted deployment is the **data controller** and must complete its own
records of processing, DPAs, and (where required) a DPIA.

## Data map (personal data)

| Data | Category | Stored where | Basis (typical) | Retention |
|---|---|---|---|---|
| Email address | Identifier (PII) | `users.email` | Contract / legitimate interest | Life of account |
| Password hash (Argon2id) | Credential | `users.password_hash` | Contract | Life of account |
| Session token hash + UA/IP metadata | Security | `sessions` | Legitimate interest (security) | Until expiry/revocation |
| Org membership & role | Account data | `memberships` | Contract | Life of membership |
| Audit entries (actor, action, target) | Security log | `audit_log` | Legal obligation / legitimate interest | Operator-defined |
| Security events (hash-chained) | Security log | `security_events` | Legitimate interest (integrity) | Operator-defined |
| Prompt/tool content | Varies (may contain PII) | transient; not persisted by P0 core | Depends on use | Not stored by core |

The P0 core does not persist chat/prompt content; if you add features that do,
extend this map and the retention policy accordingly.

## Privacy-by-design measures (implemented)

- **Data minimization:** the core schema stores only what authentication,
  tenancy, RBAC, and audit require. No analytics/tracking.
- **Pseudonymization at rest where feasible:** session tokens are stored only as
  SHA-256 hashes; passwords only as Argon2id hashes; user-agent is hashable.
- **Redaction before model calls/logs:** `src/ai/redaction/redactor.ts` masks
  emails, tokens, keys, JWTs, and PEM blocks before content reaches a model or
  is recorded in tool-invocation records. Pino redacts auth/cookie headers.
- **Purpose limitation for AI:** retrieved/tool content is treated as untrusted
  data; tools cannot exfiltrate via arbitrary network/fs without an allowlisted,
  approved scope (`src/ai/tools/`, `src/net/ssrfGuard.ts`).
- **Tenant isolation:** personal data is partitioned per organization and
  enforced by Postgres RLS (`src/tenancy/`, `tests/db/rls.test.ts`).
- **Security of processing (Art. 32):** encryption in transit (operator TLS),
  access control (RBAC), auditability (tamper-evident log), fail-closed config.

## Data-subject rights — how to service them today

- **Access / portability:** query the subject's `users` row and their
  `memberships`; export tenant rows scoped via `withTenant`.
- **Rectification:** update the `users`/membership records through authorized
  endpoints.
- **Erasure ("right to be forgotten"):** delete the `users` row;
  `ON DELETE CASCADE` removes `memberships` and `sessions`. **Caveat:** the
  tamper-evident `security_events` log is append-only by design — do not delete
  rows (it would break the chain). Records there should reference user **ids**,
  not raw PII; treat the security log retention separately and document the
  legitimate-interest basis. A first-class, audited erasure workflow is **P2**.
- **Restriction / objection:** set `users.status` to a non-`active` value to
  block authentication while preserving records.

## International transfers & sub-processors

Self-hosted: no data leaves your infrastructure by default. If you configure a
**cloud** LLM provider (not the default local Ollama/vLLM), prompt content is
transferred to that provider — add it as a sub-processor and ensure an adequate
transfer mechanism. The default posture (local models) keeps inference on-prem.

## Operator checklist

- [ ] Maintain a Record of Processing Activities (Art. 30).
- [ ] Set a real retention period for `audit_log`/`security_events`.
- [ ] Configure storage encryption at rest (DB/volumes) and TLS in transit.
- [ ] If using a cloud LLM, sign a DPA and document the transfer.
- [ ] Define a breach-notification process (see
      [`INCIDENT_RESPONSE.md`](./INCIDENT_RESPONSE.md); Art. 33/34: 72h).
- [ ] Run a DPIA if processing is high-risk for your use case.
