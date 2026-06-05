# syntax=docker/dockerfile:1
# Multi-stage build producing a minimal, non-root runtime image.
# No secrets are baked in: all configuration is supplied at runtime via env.
#
# We use Debian "slim" (glibc) rather than Alpine to avoid a musl-related npm
# crash; it remains a minimal base and the runtime stage carries no build tools.

# ---------- build stage ----------
FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV npm_config_audit=false \
    npm_config_fund=false \
    npm_config_update_notifier=false

# Install deps against the committed lockfile. --ignore-scripts avoids running
# arbitrary postinstall scripts; @node-rs/argon2 ships prebuilt binaries.
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
# Compile to dist/ and copy SQL migrations next to the compiled migrator
# (migrate.ts resolves ./sql relative to its own location), then drop dev deps.
RUN npm run build \
  && npm prune --omit=dev --ignore-scripts

# ---------- runtime stage ----------
FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production \
    APP_PORT=3000
WORKDIR /app

# Unprivileged, fixed uid 10001. PUID/PGID can be overridden via the compose
# `user:` directive (Docker-native; read-only-fs compatible; no /etc/passwd edits).
RUN groupadd -g 10001 app && useradd -u 10001 -g app -M -s /usr/sbin/nologin app

COPY --from=build --chown=app:app /app/node_modules ./node_modules
COPY --from=build --chown=app:app /app/dist ./dist
COPY --from=build --chown=app:app /app/package.json ./package.json

USER app
EXPOSE 3000

# Healthcheck hits the unauthenticated /healthz (leaks no detail). Uses Node's
# global fetch so no extra tooling is needed in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.APP_PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

CMD ["node", "dist/index.js"]
