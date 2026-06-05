import { randomBytes } from 'node:crypto';
import { envSchema, type RawEnv } from './env.schema.js';
import { assessSecret } from './secrets.js';
import { llmProvidersSchema, type LlmProviderConfig } from '../ai/providers/registry.js';

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
  readonly rateLimit: { readonly max: number; readonly windowMs: number };
  /** Layered, identity-scoped limits + per-org storage quota + login lockout. */
  readonly limits: {
    readonly llmHourly: number;
    readonly uploadsHourly: number;
    readonly streamsPerOrg: number;
    readonly storageQuotaBytes: number;
    readonly login: {
      readonly maxFailures: number;
      readonly windowMs: number;
      readonly lockBaseMs: number;
      readonly lockMaxMs: number;
    };
  };
  readonly llm: {
    readonly providers: readonly LlmProviderConfig[];
    readonly defaultProvider: string | undefined;
    readonly requestTimeoutMs: number;
  };
  /** 32-byte key for AES-256-GCM encryption at rest. */
  readonly encryptionKey: Buffer;
  /** Master KEK for envelope encryption + key rotation. */
  readonly masterKek: Buffer;
  /** OIDC settings, present only when all four OIDC_* vars are configured. */
  readonly oidc:
    | {
        readonly issuer: string;
        readonly clientId: string;
        readonly clientSecret: string;
        readonly redirectUri: string;
      }
    | undefined;
  /** Master key for document/chunk encryption (per-tenant subkeys derived via HKDF). */
  readonly documentEncryptionKey: Buffer;
  readonly embeddings: {
    readonly provider: 'local' | 'openai';
    readonly model: string;
    readonly ollamaBaseUrl: string | undefined;
    readonly openaiModel: string;
    readonly openaiBaseUrl: string;
    readonly openaiApiKey: string | undefined;
  };
  readonly maxUploadBytes: number;
  readonly clamavSocket: string | undefined;
  readonly documentStorageDir: string;
  readonly enableApiDocs: boolean;
  readonly webhook: { readonly timeoutMs: number; readonly maxRetries: number };
}

/** Parse a 32-byte key from base64 or hex; null if neither yields 32 bytes. */
function parseEncryptionKey(raw: string | undefined): Buffer | null {
  if (!raw) return null;
  for (const enc of ['base64', 'hex'] as const) {
    try {
      const b = Buffer.from(raw, enc);
      if (b.length === 32) return b;
    } catch {
      // try next encoding
    }
  }
  return null;
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

  // 7. LLM providers — server-only endpoint definitions (fail-closed parse).
  let llmProviders: LlmProviderConfig[] = [];
  if (e.LLM_PROVIDERS) {
    try {
      const parsed = llmProvidersSchema.safeParse(JSON.parse(e.LLM_PROVIDERS));
      if (!parsed.success) {
        issues.push({ variable: 'LLM_PROVIDERS', reason: 'invalid provider definition(s)' });
      } else {
        llmProviders = parsed.data;
      }
    } catch {
      issues.push({ variable: 'LLM_PROVIDERS', reason: 'must be valid JSON' });
    }
  }
  if (e.LLM_DEFAULT_PROVIDER && !llmProviders.some((p) => p.id === e.LLM_DEFAULT_PROVIDER)) {
    issues.push({ variable: 'LLM_DEFAULT_PROVIDER', reason: 'does not match any configured provider id' });
  }

  // 8. Encryption key (AES-256-GCM). Required+valid in prod; ephemeral in dev.
  let encryptionKey = parseEncryptionKey(e.ENCRYPTION_KEY);
  if (isProduction) {
    if (!encryptionKey) {
      issues.push({
        variable: 'ENCRYPTION_KEY',
        reason: e.ENCRYPTION_KEY ? 'must be 32 bytes (base64 or hex)' : 'required in production but missing',
      });
    }
  } else if (!encryptionKey) {
    encryptionKey = randomBytes(32); // ephemeral dev key
  }

  // 8b. Master KEK (envelope encryption / key rotation).
  let masterKek = parseEncryptionKey(e.MASTER_KEK);
  if (isProduction) {
    if (!masterKek) {
      issues.push({ variable: 'MASTER_KEK', reason: e.MASTER_KEK ? 'must be 32 bytes (hex or base64)' : 'required in production but missing' });
    }
  } else if (!masterKek) {
    masterKek = randomBytes(32); // ephemeral dev key
  }

  // 9. OIDC — all-or-nothing.
  const oidcParts = [e.OIDC_ISSUER, e.OIDC_CLIENT_ID, e.OIDC_CLIENT_SECRET, e.OIDC_REDIRECT_URI];
  const oidcCount = oidcParts.filter((v) => v && v.length > 0).length;
  let oidc: Config['oidc'];
  if (oidcCount > 0 && oidcCount < 4) {
    issues.push({
      variable: 'OIDC_*',
      reason: 'OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI must all be set together',
    });
  } else if (oidcCount === 4) {
    oidc = {
      issuer: e.OIDC_ISSUER as string,
      clientId: e.OIDC_CLIENT_ID as string,
      clientSecret: e.OIDC_CLIENT_SECRET as string,
      redirectUri: e.OIDC_REDIRECT_URI as string,
    };
  }

  // 10. Document encryption key + embedding provider requirements.
  let documentEncryptionKey = parseEncryptionKey(e.DOCUMENT_ENCRYPTION_KEY);
  if (isProduction) {
    if (!documentEncryptionKey) {
      issues.push({
        variable: 'DOCUMENT_ENCRYPTION_KEY',
        reason: e.DOCUMENT_ENCRYPTION_KEY ? 'must be 32 bytes (hex or base64)' : 'required in production but missing',
      });
    }
    if (e.EMBEDDING_PROVIDER === 'local' && !e.OLLAMA_BASE_URL) {
      issues.push({ variable: 'OLLAMA_BASE_URL', reason: 'required in production when EMBEDDING_PROVIDER=local' });
    }
    if (e.EMBEDDING_PROVIDER === 'openai' && !e.OPENAI_API_KEY) {
      issues.push({ variable: 'OPENAI_API_KEY', reason: 'required in production when EMBEDDING_PROVIDER=openai' });
    }
  } else if (!documentEncryptionKey) {
    documentEncryptionKey = randomBytes(32); // ephemeral dev key
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
    rateLimit: { max: e.RATE_LIMIT_MAX, windowMs: e.RATE_LIMIT_WINDOW_MS },
    limits: {
      llmHourly: e.RATE_LIMIT_LLM_HOURLY,
      uploadsHourly: e.RATE_LIMIT_UPLOADS_HOURLY,
      streamsPerOrg: e.RATE_LIMIT_STREAMS_PER_ORG,
      storageQuotaBytes: e.STORAGE_QUOTA_MB_PER_ORG * 1024 * 1024,
      login: {
        maxFailures: e.LOGIN_MAX_FAILURES,
        windowMs: e.LOGIN_FAILURE_WINDOW_MS,
        lockBaseMs: e.LOGIN_LOCK_BASE_MS,
        lockMaxMs: e.LOGIN_LOCK_MAX_MS,
      },
    },
    llm: {
      providers: llmProviders,
      defaultProvider: e.LLM_DEFAULT_PROVIDER,
      requestTimeoutMs: e.LLM_REQUEST_TIMEOUT_MS,
    },
    encryptionKey: encryptionKey as Buffer,
    masterKek: masterKek as Buffer,
    oidc,
    documentEncryptionKey: documentEncryptionKey as Buffer,
    embeddings: {
      provider: e.EMBEDDING_PROVIDER,
      model: e.EMBEDDING_MODEL,
      ollamaBaseUrl: e.OLLAMA_BASE_URL,
      openaiModel: e.OPENAI_EMBEDDING_MODEL,
      openaiBaseUrl: e.OPENAI_EMBEDDING_BASE_URL,
      openaiApiKey: e.OPENAI_API_KEY,
    },
    maxUploadBytes: e.MAX_UPLOAD_SIZE_MB * 1024 * 1024,
    clamavSocket: e.CLAMAV_SOCKET,
    documentStorageDir: e.DOCUMENT_STORAGE_DIR,
    // API docs are off by default; opt-in. Forced off is the safe default, but
    // we allow it in any env when explicitly enabled.
    enableApiDocs: e.ENABLE_API_DOCS === 'true',
    webhook: { timeoutMs: e.WEBHOOK_TIMEOUT_MS, maxRetries: e.WEBHOOK_MAX_RETRIES },
  };

  return Object.freeze(config);
}
