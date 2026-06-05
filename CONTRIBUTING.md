# Contributing to Capybara_AI

Thanks for your interest in improving Capybara_AI! This project is
**security-first**: contributions are held to the same secure-by-default,
fail-closed bar as the rest of the codebase.

## Ground rules

- **No mock data in production paths.** Test fixtures live under `tests/` and are
  never imported by `src/`.
- **Every dangerous default fails closed.** If a feature can be misconfigured,
  it must refuse to run rather than run insecurely.
- **Document every new env var** in `.env.example` (with a rejected placeholder,
  never a real secret).
- **No secrets in code or VCS.** `.env` is gitignored; gitleaks runs in CI.
- **Tenant safety.** New tenant tables get `org_id NOT NULL`, RLS, and
  least-privilege grants. Cross-tenant access must be impossible at the DB layer.

## Development setup

```bash
npm install
npm run typecheck      # strict TypeScript, ESM — must be clean
npm test               # Vitest + Testcontainers (Docker required)
```

Tests spin up a real PostgreSQL (with pgvector) via Testcontainers, so Docker
must be available. If image pulls are rate-limited, build the local
`capy-pgvector:16` image and set `PGVECTOR_TEST_IMAGE=capy-pgvector:16`.

## Before you open a PR

1. `npm run typecheck` is clean.
2. `npm test` is green (add tests for new behavior — including the failure path).
3. `npm audit` shows no new high/critical advisories.
4. New env vars are in `.env.example`; new endpoints are documented.
5. Security-relevant changes update the relevant doc (`THREAT_MODEL.md`,
   `docs/security/ASVS_MAPPING.md`, etc.).

## Commit & PR conventions

- Write clear, imperative commit messages explaining the *why*.
- Keep PRs focused; describe the security impact explicitly in the PR template.
- Use a **regular merge** (not squash) unless a maintainer says otherwise.
- CI (typecheck/build/test) and the security workflow (audit/OSV/gitleaks/SBOM)
  must pass.

## Reporting security vulnerabilities

**Do not** open a public issue for security problems. Follow the private
disclosure process in [SECURITY.md](SECURITY.md).

## Code of conduct

Be respectful and constructive. We want Capybara_AI to be a welcoming project
for contributors of all backgrounds.

## License

By contributing, you agree that your contributions are licensed under the
project's [Apache-2.0](LICENSE) license.
