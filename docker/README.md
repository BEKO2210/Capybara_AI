# Capybara_AI — Docker

Hardened container images and Compose stacks for running Capybara_AI.

## Images

- **`docker/Dockerfile`** — multi-stage build, runs as a non-root user, drops
  all Linux capabilities, `no-new-privileges`, read-only root filesystem with a
  `tmpfs` for `/tmp`.

## Stacks

| File | Purpose |
| --- | --- |
| `docker-compose.yml` | Local/dev stack: Postgres + one-shot `migrate` + `app`. Loopback-only app port; Postgres not published; fail-closed on missing secrets. |
| `docker-compose.prod.yml` | Production overlay (TLS termination at your proxy, stricter envs). |

### Quickstart

```bash
cp ../.env.example .env           # fill in STRONG values
# Required: POSTGRES_PASSWORD, DB_APP_PASSWORD, COOKIE_SECRET, SESSION_SECRET
# Production also requires: ENCRYPTION_KEY, DOCUMENT_ENCRYPTION_KEY, MASTER_KEK
docker compose -f docker-compose.yml up --build
```

The app starts only after `migrate` completes (creates the restricted
`capybara_app` role + applies RLS migrations). The app connects as
`capybara_app` (NOSUPERUSER, NOBYPASSRLS) — a forgotten `WHERE` cannot leak
across tenants.

## Backups

The `backup` profile runs an on-demand database dump into the `capy-backups`
volume and prunes old artifacts:

```bash
docker compose -f docker-compose.yml --profile backup run --rm backup
```

For full backups (database **and** the encrypted document store), plus the
restore runbook, see [`../docs/DISASTER_RECOVERY.md`](../docs/DISASTER_RECOVERY.md)
and the host scripts `scripts/backup.sh` / `scripts/restore.sh`.

## Health

`GET /healthz` returns `200` with component health (`db`, `vectorSearch`,
`backup`) and the build version when healthy, and `503` when any critical
component is degraded or down — wire it to your load balancer's drain check.
`GET /readyz` is a minimal readiness probe.
