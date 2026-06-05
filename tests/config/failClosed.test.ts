import { describe, it, expect } from 'vitest';
import { loadConfig, ConfigError, type ConfigIssue } from '../../src/config/index.js';

// Strong, denylist-safe secrets for the "production succeeds" path.
const STRONG_COOKIE = 'Zk7Q2pXwL4mN8vR1tB6yH3sC0gJ-aE_uIoPqW5n';
const STRONG_SESSION = 'Hb9Fz2Lm6Qx4Rv8Tn1Yc3Sd0Gj7Aw5Pk-Ue_IoLr';

// 32 bytes, base64 — valid AES-256 key for the ENCRYPTION_KEY requirement.
const STRONG_ENC_KEY = Buffer.alloc(32, 7).toString('base64');

function prodEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    APP_ENV: 'production',
    DATABASE_URL: 'postgresql://capyapp:Hb9Fz2Lm6Qx4Rv8@db.internal:5432/capy?sslmode=require',
    COOKIE_SECRET: STRONG_COOKIE,
    SESSION_SECRET: STRONG_SESSION,
    CORS_ALLOWED_ORIGINS: 'https://app.acme-corp.io',
    APP_BASE_URL: 'https://app.acme-corp.io',
    ENCRYPTION_KEY: STRONG_ENC_KEY,
    ...overrides,
  };
}

function issuesOf(env: NodeJS.ProcessEnv): ConfigIssue[] {
  try {
    loadConfig(env);
    return [];
  } catch (e) {
    if (e instanceof ConfigError) return [...e.issues];
    throw e;
  }
}

describe('config — fail-closed startup validation', () => {
  it('starts in development with safe ephemeral defaults (no prod secrets required)', () => {
    const cfg = loadConfig({ APP_ENV: 'development' });
    expect(cfg.isProduction).toBe(false);
    // Ephemeral secrets are generated and strong (>= 32 chars).
    expect(cfg.cookieSecret.length).toBeGreaterThanOrEqual(32);
    expect(cfg.sessionSecret.length).toBeGreaterThanOrEqual(32);
    expect(cfg.cookieSecret).not.toBe(cfg.sessionSecret);
  });

  it('REFUSES to start in production when required secrets are missing', () => {
    const issues = issuesOf({ APP_ENV: 'production' });
    const vars = issues.map((i) => i.variable);
    expect(vars).toEqual(
      expect.arrayContaining([
        'DATABASE_URL',
        'COOKIE_SECRET',
        'SESSION_SECRET',
        'CORS_ALLOWED_ORIGINS',
        'APP_BASE_URL',
      ]),
    );
  });

  it('REFUSES a weak/placeholder secret in production', () => {
    const issues = issuesOf(
      prodEnv({ COOKIE_SECRET: 'changeme-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c' }),
    );
    const cookieIssue = issues.find((i) => i.variable === 'COOKIE_SECRET');
    expect(cookieIssue).toBeDefined();
    expect(cookieIssue?.reason).toMatch(/placeholder/);
  });

  it('REFUSES a too-short secret in production', () => {
    const issues = issuesOf(prodEnv({ SESSION_SECRET: 'short' }));
    expect(issues.some((i) => i.variable === 'SESSION_SECRET' && /too_short/.test(i.reason))).toBe(true);
  });

  it('REFUSES a wildcard CORS origin in production', () => {
    const issues = issuesOf(prodEnv({ CORS_ALLOWED_ORIGINS: '*' }));
    expect(issues.some((i) => i.variable === 'CORS_ALLOWED_ORIGINS' && /wildcard/.test(i.reason))).toBe(true);
  });

  it('REFUSES SECURE_COOKIES=false in production', () => {
    const issues = issuesOf(prodEnv({ SECURE_COOKIES: 'false' }));
    expect(issues.some((i) => i.variable === 'SECURE_COOKIES')).toBe(true);
  });

  it('REFUSES a database URL without TLS in production', () => {
    const issues = issuesOf(
      prodEnv({ DATABASE_URL: 'postgresql://capyapp:Hb9Fz2Lm6Qx4Rv8@db.internal:5432/capy' }),
    );
    expect(issues.some((i) => i.variable === 'DATABASE_URL' && /TLS/.test(i.reason))).toBe(true);
  });

  it('REFUSES a missing or wrong-length ENCRYPTION_KEY in production', () => {
    const missing = issuesOf(prodEnv({ ENCRYPTION_KEY: undefined }));
    expect(missing.some((i) => i.variable === 'ENCRYPTION_KEY')).toBe(true);
    const tooShort = issuesOf(prodEnv({ ENCRYPTION_KEY: Buffer.alloc(16, 1).toString('base64') }));
    expect(tooShort.some((i) => i.variable === 'ENCRYPTION_KEY' && /32 bytes/.test(i.reason))).toBe(true);
  });

  it('starts in production when all secrets are present and strong', () => {
    const cfg = loadConfig(prodEnv());
    expect(cfg.isProduction).toBe(true);
    expect(cfg.secureCookies).toBe(true);
    expect(cfg.corsAllowedOrigins).toEqual(['https://app.acme-corp.io']);
    expect(cfg.cookieSecret).toBe(STRONG_COOKIE);
  });
});
