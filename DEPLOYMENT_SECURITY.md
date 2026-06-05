# Deployment Security

How to deploy Capybara_AI securely. The defaults are safe; production
**fails closed** if required secrets are missing/weak. Containers run non-root.

## Pre-flight hardening checklist

- [ ] `APP_ENV=production` set (enables fail-closed validation).
- [ ] Strong `COOKIE_SECRET` and `SESSION_SECRET` (≥32 bytes, generated, not
      placeholders). `node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`.
- [ ] `DATABASE_URL` for the **restricted** `capybara_app` role, with
      `sslmode=require` (TLS enforced in prod).
- [ ] `DATABASE_MIGRATION_URL` for the **privileged** migration role (used only
      by the one-shot migrate job, not the app).
- [ ] `CORS_ALLOWED_ORIGINS` set to explicit origins (no `*`).
- [ ] `APP_BASE_URL` set to the public URL.
- [ ] Secrets injected from a secret manager / orchestrator — never baked into
      the image or committed.
- [ ] TLS terminated at a reverse proxy in front of the app; app not exposed
      directly to the internet.
- [ ] DB encryption at rest enabled (managed Postgres or encrypted volume).
- [ ] Backups configured and tested (below).

Production refuses to start if any required secret is missing/weak, if CORS is
`*`, if `SECURE_COOKIES=false`, or if the DB URL lacks TLS
(`src/config/config.ts`). Do not work around these.

## Secrets

All configuration is environment-based; `process.env` is read only in
`src/config`. The image bakes in nothing. The app connects as `capybara_app`
(NOSUPERUSER, NOBYPASSRLS); migrations run separately as the privileged role.
The `capybara_app` password is provided via `DB_APP_PASSWORD` to the migrate
job and embedded in the app's `DATABASE_URL`.

## Containers (`docker/`)

- **Non-root:** image user uid 10001; override with the compose `user:`
  directive (PUID/PGID) if needed.
- **Minimal:** multi-stage build; runtime carries no build tools/source/tests.
- **Healthcheck:** `HEALTHCHECK` hits the unauthenticated `/healthz` (no detail
  leak) via Node's fetch.
- **No default credentials:** compose uses `${VAR:?}` for `POSTGRES_PASSWORD`,
  `DB_APP_PASSWORD`, `COOKIE_SECRET`, `SESSION_SECRET` — `up` fails if unset.
- **Loopback by default:** the app's host port binds to `127.0.0.1`; Postgres is
  not published to the host. Expose deliberately behind your proxy.
- **Runtime hardening:** `read_only: true`, `cap_drop: [ALL]`,
  `no-new-privileges:true`, tmpfs `/tmp`.

### Run

```bash
# Development
cp .env.example docker/.env   # fill strong values
docker compose -f docker/docker-compose.yml up --build

# Production (adds APP_ENV=production, TLS DB, resource limits)
docker compose -f docker/docker-compose.yml -f docker/docker-compose.prod.yml up -d
```

The one-shot `migrate` service creates the restricted role and applies SQL
migrations (tables + RLS) before the app starts (`depends_on … service_completed_successfully`).

## Network & TLS

- Terminate TLS at a reverse proxy (nginx/Caddy/Traefik); forward to the app.
- Set `trustProxy` is enabled in production (`src/server.ts`) so client IPs and
  rate limiting work behind the proxy — ensure the proxy sets correct
  `X-Forwarded-*` headers and is the only ingress.
- Keep the LLM endpoint (Ollama/vLLM) on a private network; the app reaches it
  via server config only.

## Document uploads & virus scanning (RAG)

- **Encryption at rest:** uploaded files and every text chunk are encrypted with
  AES-256-GCM under a per-tenant key derived (HKDF) from `DOCUMENT_ENCRYPTION_KEY`
  (a key distinct from `ENCRYPTION_KEY`; required and 32 bytes in production).
  Files are stored under `DOCUMENT_STORAGE_DIR/{org_id}/{uuid}.enc` — never under
  the original filename.
- **MIME allowlist:** only `pdf, docx, xlsx, txt, md, eml` are accepted; anything
  else is rejected (415). Uploads are size-capped by `MAX_UPLOAD_SIZE_MB` (413).
- **Virus scanning (ClamAV):** if `CLAMAV_SOCKET` is set, each upload is scanned
  via the ClamAV daemon (INSTREAM) **before** storage and rejected if infected;
  the scanner **fails closed** (a connection/protocol error rejects the upload).
  **If `CLAMAV_SOCKET` is unset, scanning is skipped** and a warning is logged —
  acceptable for trusted internal use, but **set it for any internet-facing or
  multi-tenant deployment.** Run `clamd` as a sidecar and mount its socket.
- **Classification & access:** documents carry a classification
  (PUBLIC/INTERNAL/CONFIDENTIAL/SECRET); retrieval is gated by the caller's
  clearance at both the application layer and Postgres RLS. Every access is
  recorded in an append-only `document_access_log` (queries stored only as a
  SHA-256 hash).

## Backups & restore

- **What to back up:** the PostgreSQL database (all tenant data, auth, audit).
- **How:** `pg_dump`/managed snapshots on a schedule; store encrypted off-box.
- **Restore drill (document & test):**
  1. Provision a fresh Postgres; restore the dump.
  2. Run the migrate job (idempotent) to ensure role/RLS exist.
  3. Start the app; verify `/healthz`/`/readyz` and run smoke tests.
  4. Run `verifyChain()` over `security_events` to confirm log integrity
     survived the restore.
- **RPO/RTO:** define per your SLA; test restores regularly (a backup is not
  real until a restore has succeeded).

## Post-deploy verification

- `GET /healthz` → `200 {"status":"ok"}`.
- Confirm security headers are present (CSP `frame-ancestors 'none'`, HSTS).
- Confirm cross-tenant access is blocked and the app role is NOBYPASSRLS.
- Review logs ship to your aggregator with secrets redacted.

See [`INCIDENT_RESPONSE.md`](./INCIDENT_RESPONSE.md) for handling problems.
