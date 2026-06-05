import { randomBytes } from 'node:crypto';
import { envSchema, type RawEnv } from './env.schema.js';
import { assessSecret } from './secrets.js';

/**
 * Application configuration, derived once at startup from the environment.
 *
 * Design: fail-closed. In production the process MUST NOT start unless all
 * required secrets/values are present and strong. In development we fall back
 * to clearly-flagged ephemeral defaults so local work is frictionless without
 * ever shipping an insecure production default.
 */
export interface Config {
  readonly appEnv: 'development' | 'test' | 'production';
  readonly isProduction: boolean;
  readonly port: number;
  readonly bind: string;
  readonly baseUrl: string;
  readonly databaseUrl: string | undefined;
  readonly databaseMigrationUrl: string | undefined;
  readonly cookieSecret: string;
  readonly sessionSecret: string;
  readonly corsAllowedOrigins: readonly string[];
  readonly secureCookies: boolean;
  readonly logLevel: RawEnv['LOG_LEVEL'];
}

/** A single fail-closed configuration problem. Never contains secret values. */
export interface ConfigIssue {
  readonly variable: string;
  readonly reason: string;
}

/**
 * Thrown when configuration is invalid. Aggregates ALL problems so an operator
 * can fix them in one pass. The message intentionally omits secret values.
 */
export class ConfigError extends Error {
  readonly issues: readonly ConfigIssue[];
  constructor(issues: readonly ConfigIssue[]) {
    const summary = issues
      .map((i) => `  - ${i.variable}: ${i.reason}`)
      .join('\n');
    super(`Invalid configuration; refusing to start:\n${summary}`);
    this.name = 'ConfigError';
    this.issues = issues;
  }
}

/** Variables that are mandatory (and strength-checked) in production. */
const REQUIRED_IN_PRODUCTION = [
  'DATABASE_URL',
  'COOKIE_SECRET',
  'SESSION_SECRET',
  'CORS_ALLOWED_ORIGINS',
  'APP_BASE_URL',
] as const;

function parseOrigins(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * Load and validate configuration from a given environment (defaults to
 * process.env). Pure and side-effect free so it is trivially testable: callers
 * pass a synthetic env and assert on the thrown ConfigError.
 *
 * @throws {ConfigError} when configuration is invalid (fail-closed).
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  // 1. Shape/type validation via Zod.
  const parsed = envSchema.safeParse(env);
  if (!parsed.success) {
    const issues: ConfigIssue[] = parsed.error.issues.map((i) => ({
      variable: i.path.join('.') || '(root)',
      reason: i.message,
    }));
    throw new ConfigError(issues);
  }
  const e = parsed.data;
  const isProduction = e.APP_ENV === 'production';

  const issues: ConfigIssue[] = [];

  // 2. Production fail-closed presence checks.
  if (isProduction) {
    for (const key of REQUIRED_IN_PRODUCTION) {
      const value = env[key];
      if (value === undefined || value.trim().length === 0) {
        issues.push({ variable: key, reason: 'required in production but missing' });
      }
    }
  }

  // 3. Secret strength (production: hard fail; dev/test: ephemeral fallback).
  const cookieAssessment = assessSecret(e.COOKIE_SECRET);
  const sessionAssessment = assessSecret(e.SESSION_SECRET);

  let cookieSecret = e.COOKIE_SECRET;
  let sessionSecret = e.SESSION_SECRET;

  if (isProduction) {
    if (!cookieAssessment.ok) {
      issues.push({ variable: 'COOKIE_SECRET', reason: `weak secret (${cookieAssessment.reason})` });
    }
    if (!sessionAssessment.ok) {
      issues.push({ variable: 'SESSION_SECRET', reason: `weak secret (${sessionAssessment.reason})` });
    }
  } else {
    // Development/test: generate clearly-ephemeral strong secrets if absent or weak.
    if (!cookieAssessment.ok) cookieSecret = randomBytes(32).toString('base64url');
    if (!sessionAssessment.ok) sessionSecret = randomBytes(32).toString('base64url');
  }

  // 4. CORS hardening: no wildcard in production; must be non-empty.
  const origins = parseOrigins(e.CORS_ALLOWED_ORIGINS);
  if (isProduction) {
    if (origins.length === 0) {
      issues.push({ variable: 'CORS_ALLOWED_ORIGINS', reason: 'required in production but empty' });
    }
    if (origins.includes('*')) {
      issues.push({ variable: 'CORS_ALLOWED_ORIGINS', reason: 'wildcard "*" is not allowed in production' });
    }
  }

  // 5. Database credential hygiene in production.
  if (isProduction && e.DATABASE_URL) {
    if (/:\/\/[^:@/]+:(postgres|password|root|admin)@/i.test(e.DATABASE_URL)) {
      issues.push({ variable: 'DATABASE_URL', reason: 'uses a trivial/default password' });
    }
    if (!/sslmode=require|sslmode=verify/i.test(e.DATABASE_URL) && env['DB_ALLOW_INSECURE'] !== 'true') {
      issues.push({ variable: 'DATABASE_URL', reason: 'TLS not enforced (set sslmode=require)' });
    }
    if (env['DB_ALLOW_INSECURE'] === 'true') {
      issues.push({ variable: 'DB_ALLOW_INSECURE', reason: 'must not be enabled in production' });
    }
  }

  // 6. SECURE_COOKIES cannot be disabled in production.
  if (isProduction && env['SECURE_COOKIES'] === 'false') {
    issues.push({ variable: 'SECURE_COOKIES', reason: 'must be true in production' });
  }

  if (issues.length > 0) {
    throw new ConfigError(issues);
  }

  // cookieSecret/sessionSecret are guaranteed defined here: prod failures above
  // would have thrown; non-prod assigns ephemeral fallbacks.
  const config: Config = {
    appEnv: e.APP_ENV,
    isProduction,
    port: e.APP_PORT,
    bind: e.APP_BIND,
    baseUrl: e.APP_BASE_URL ?? `http://${e.APP_BIND}:${e.APP_PORT}`,
    databaseUrl: e.DATABASE_URL,
    databaseMigrationUrl: e.DATABASE_MIGRATION_URL,
    cookieSecret: cookieSecret as string,
    sessionSecret: sessionSecret as string,
    corsAllowedOrigins: isProduction ? origins : origins.length > 0 ? origins : ['http://localhost:3000'],
    secureCookies: isProduction ? true : env['SECURE_COOKIES'] !== 'false',
    logLevel: e.LOG_LEVEL,
  };

  return Object.freeze(config);
}
