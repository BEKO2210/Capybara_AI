import { z } from 'zod';

/**
 * Base shape of the process environment. This validates *types/format* only.
 * Production-specific "fail-closed" requirements (presence + secret strength)
 * are enforced in config.ts, because they depend on APP_ENV.
 *
 * Every variable here is documented in .env.example.
 */
export const envSchema = z.object({
  APP_ENV: z
    .enum(['development', 'test', 'production'])
    .default('development'),

  // Standard Node flag; informational only — APP_ENV is authoritative.
  NODE_ENV: z.string().optional(),

  APP_PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  APP_BIND: z.string().min(1).default('127.0.0.1'),

  // Public base URL (used later for cookie/CSRF/CORS reasoning).
  APP_BASE_URL: z.string().url().optional(),

  // Postgres DSN for the RESTRICTED application role (non-superuser, no BYPASSRLS).
  DATABASE_URL: z.string().min(1).optional(),
  // Separate DSN for the privileged migration role.
  DATABASE_MIGRATION_URL: z.string().min(1).optional(),

  COOKIE_SECRET: z.string().optional(),
  SESSION_SECRET: z.string().optional(),

  // Comma-separated origin allowlist. No "*" permitted in production.
  CORS_ALLOWED_ORIGINS: z.string().optional(),

  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace'])
    .default('info'),

  // Global rate-limit defaults (per IP+identity). Stricter limits are applied
  // per-route (e.g. auth, AI endpoints).
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),

  // LLM providers as a JSON array of {id,type,baseUrl,model,apiKey?}. Endpoints
  // are SERVER-ONLY: callers select a provider by id, never by URL.
  LLM_PROVIDERS: z.string().optional(),
  LLM_DEFAULT_PROVIDER: z.string().optional(),
  LLM_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(30_000),

  // 32-byte key (base64 or hex) for AES-256-GCM encryption at rest (e.g. TOTP
  // secrets). Required in production; ephemeral in dev if unset.
  ENCRYPTION_KEY: z.string().optional(),

  // OIDC (all-or-nothing). PKCE authorization-code flow; no implicit grant.
  OIDC_ISSUER: z.string().url().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_REDIRECT_URI: z.string().url().optional(),

  // Document intelligence (RAG). Separate key from ENCRYPTION_KEY; per-tenant
  // subkeys are derived from it via HKDF.
  DOCUMENT_ENCRYPTION_KEY: z.string().optional(),
  EMBEDDING_PROVIDER: z.enum(['local', 'openai']).default('local'),
  EMBEDDING_MODEL: z.string().default('nomic-embed-text'),
  OLLAMA_BASE_URL: z.string().url().optional(),
  OPENAI_EMBEDDING_MODEL: z.string().default('text-embedding-3-small'),
  OPENAI_EMBEDDING_BASE_URL: z.string().url().default('https://api.openai.com/v1'),
  OPENAI_API_KEY: z.string().optional(),
  MAX_UPLOAD_SIZE_MB: z.coerce.number().int().positive().default(50),
  // If set, uploaded files are scanned via this ClamAV unix socket before storage.
  CLAMAV_SOCKET: z.string().optional(),
  // Base directory for encrypted document storage.
  DOCUMENT_STORAGE_DIR: z.string().default('/data/documents'),
});

export type RawEnv = z.infer<typeof envSchema>;
