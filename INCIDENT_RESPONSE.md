# Incident Response

A practical runbook for security incidents in a Capybara_AI deployment. Adapt
the contacts and SLAs to your organization. Phases follow NIST SP 800-61
(prepare → detect → contain → eradicate → recover → post-incident).

## Contacts (template — fill in per deployment)

| Role | Name | Channel | Backup |
|---|---|---|---|
| Incident Commander | _TBD_ | _TBD_ | _TBD_ |
| Security lead | _TBD_ | _TBD_ | _TBD_ |
| Database/infra owner | _TBD_ | _TBD_ | _TBD_ |
| DPO / privacy (GDPR) | _TBD_ | _TBD_ | _TBD_ |
| Comms / legal | _TBD_ | _TBD_ | _TBD_ |

Security reports arrive per [`SECURITY.md`](./SECURITY.md).

## Detection sources

- **Tamper-evident security log** (`security_events`): auth failures, lockouts,
  CSRF/validation rejections, tenant-guard trips, tool denials, SSRF blocks,
  approval grants/denials. Run `verifyChain()` (`src/audit/verifyChain.ts`) to
  detect log tampering.
- **Audit log** (`audit_log`): sensitive business actions (role/membership
  changes, approvals).
- **Application logs** (Pino, secrets redacted) shipped to your aggregator.
- **CI security alerts**: `npm audit`, OSV, gitleaks, SBOM diffs.
- **Infra**: reverse proxy logs, DB logs, container health.

## Severity

| Sev | Examples | Initial response |
|---|---|---|
| SEV-1 | Cross-tenant data exposure, auth bypass, secret leak, RCE | Immediate; page IC |
| SEV-2 | Privilege escalation attempt, SSRF reaching internal svc, audit tampering | Same business day |
| SEV-3 | High-severity dependency CVE, repeated abuse/DoS | Next business day |

## Containment playbooks

**Compromised session / account**
- Revoke sessions: set `revoked_at` on the affected `sessions` rows (or all rows
  for the user). Validation rejects revoked tokens immediately.
- Disable the account: set `users.status` to non-`active` (blocks auth).

**Suspected cross-tenant access**
- Identify scope from `audit_log`/`security_events`.
- Verify RLS posture: app role must be `NOBYPASSRLS` and not superuser; confirm
  `withTenant` is used on the affected path.
- If a code path bypassed scoping, hotfix and redeploy; RLS should have blocked
  it at the DB — confirm whether the DB layer held.

**Leaked secret (cookie/session/DB/LLM key)**
- Rotate `COOKIE_SECRET`/`SESSION_SECRET` (invalidates cookie signatures),
  the `capybara_app` DB password (rerun migrate + update `DATABASE_URL`), and any
  LLM provider key. Redeploy. Rotate anything seen in logs/screenshots.

**Malicious tool / prompt-injection abuse**
- Inspect `ai_tool_invocations`/`security_events` for denied/pending actions.
- Tighten or remove the offending tool's scopes; revoke pending approvals.
- Confirm no dangerous tool ran without approval (it cannot, by design).

**Dependency CVE / supply-chain**
- Assess exploitability in our context; upgrade/patch; rebuild the image
  (no-cache); redeploy. See [`SUPPLY_CHAIN_SECURITY.md`](./SUPPLY_CHAIN_SECURITY.md).

## Eradication & recovery

- Apply the fix on a branch, get CI (typecheck/test/security) green, deploy.
- Restore data from backups if integrity was affected (see
  [`DEPLOYMENT_SECURITY.md`](./DEPLOYMENT_SECURITY.md)); after restore, run
  `verifyChain()` and smoke tests.
- Confirm the issue is resolved in production and monitoring is clean.

## GDPR breach notification

If personal data was exposed, the controller must assess notifying the
supervisory authority within **72 hours** (GDPR Art. 33) and affected data
subjects without undue delay if high risk (Art. 34). Coordinate with the DPO.
See [`PRIVACY_AND_GDPR.md`](./PRIVACY_AND_GDPR.md).

## Post-incident

- Write a blameless post-mortem: timeline, root cause, impact, what worked,
  what didn't.
- File follow-up issues; add a regression test for the root cause.
- Update this runbook, the [`RISK_REGISTER`](./docs/security/RISK_REGISTER.md),
  and detections so the same class of incident is caught earlier next time.
