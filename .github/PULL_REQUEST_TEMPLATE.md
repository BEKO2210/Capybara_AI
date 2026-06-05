## Summary

<!-- What does this PR change, and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Refactor / chore

## Security impact

<!-- REQUIRED. How does this change affect the security posture? Consider tenant
isolation, fail-closed defaults, authn/authz, secrets, data retention/GDPR, and
the audit trail. Write "none" only if you are certain there is no impact. -->

## Checklist

- [ ] `npm run typecheck` is clean
- [ ] `npm test` passes (added/updated tests, including failure paths)
- [ ] `npm audit` shows no new high/critical advisories
- [ ] New env vars documented in `.env.example` (no real secrets)
- [ ] New tenant tables have `org_id`, RLS, and least-privilege grants
- [ ] Relevant docs updated (security mappings, runbooks, guides)
- [ ] No secrets, mock data, or debug code in production paths

## How to test

<!-- Steps a reviewer can follow to verify the change. -->

## Related issues

<!-- e.g. Closes #123 -->
