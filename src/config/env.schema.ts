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
});

export type RawEnv = z.infer<typeof envSchema>;
