import { describe, it, expect } from 'vitest';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveKeyMaterial } from '../../src/config/keySource.js';
import { loadConfig, ConfigError } from '../../src/config/index.js';

const STRONG_COOKIE = 'Zk7Q2pXwL4mN8vR1tB6yH3sC0gJ-aE_uIoPqW5n';
const STRONG_SESSION = 'Hb9Fz2Lm6Qx4Rv8Tn1Yc3Sd0Gj7Aw5Pk-Ue_IoLr';

function prodBase(): NodeJS.ProcessEnv {
  return {
    APP_ENV: 'production',
    DATABASE_URL: 'postgresql://capyapp:Hb9Fz2Lm6Qx4Rv8@db.internal:5432/capy?sslmode=require',
    COOKIE_SECRET: STRONG_COOKIE,
    SESSION_SECRET: STRONG_SESSION,
    CORS_ALLOWED_ORIGINS: 'https://app.acme-corp.io',
    APP_BASE_URL: 'https://app.acme-corp.io',
    OLLAMA_BASE_URL: 'http://ollama.internal:11434',
  };
}

describe('key source — env vs file (KMS/secret-manager pattern)', () => {
  it('reads keys from the environment by default', () => {
    const km = resolveKeyMaterial({ ENCRYPTION_KEY: 'abc', MASTER_KEK: 'def', DOCUMENT_ENCRYPTION_KEY: 'ghi' });
    expect(km).toEqual({ encryptionKey: 'abc', masterKek: 'def', documentEncryptionKey: 'ghi' });
  });

  it('reads keys from files when KEY_SOURCE=file (trailing newline trimmed)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'capy-keys-'));
    const enc = join(dir, 'enc'), doc = join(dir, 'doc'), kek = join(dir, 'kek');
    writeFileSync(enc, 'AAAA\n');
    writeFileSync(doc, 'BBBB');
    writeFileSync(kek, 'CCCC\n');
    const km = resolveKeyMaterial({ KEY_SOURCE: 'file', ENCRYPTION_KEY_FILE: enc, DOCUMENT_ENCRYPTION_KEY_FILE: doc, MASTER_KEK_FILE: kek });
    expect(km).toEqual({ encryptionKey: 'AAAA', documentEncryptionKey: 'BBBB', masterKek: 'CCCC' });
  });

  it('reads keys from a command when KEY_SOURCE=command (native KMS path)', () => {
    const km = resolveKeyMaterial({
      KEY_SOURCE: 'command',
      MASTER_KEK_COMMAND: 'printf deadbeef',
      ENCRYPTION_KEY_COMMAND: 'echo cafe',
    });
    expect(km.masterKek).toBe('deadbeef');
    expect(km.encryptionKey).toBe('cafe');
  });

  it('fails closed when a key command exits non-zero', () => {
    expect(() => resolveKeyMaterial({ KEY_SOURCE: 'command', MASTER_KEK_COMMAND: 'exit 3' })).toThrow();
  });

  it('loadConfig starts in production with keys sourced from files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'capy-keys-'));
    const enc = join(dir, 'enc'), doc = join(dir, 'doc'), kek = join(dir, 'kek');
    writeFileSync(enc, Buffer.alloc(32, 1).toString('hex') + '\n');
    writeFileSync(doc, Buffer.alloc(32, 2).toString('hex'));
    writeFileSync(kek, Buffer.alloc(32, 3).toString('hex'));
    const cfg = loadConfig({
      ...prodBase(),
      KEY_SOURCE: 'file',
      ENCRYPTION_KEY_FILE: enc,
      DOCUMENT_ENCRYPTION_KEY_FILE: doc,
      MASTER_KEK_FILE: kek,
    });
    expect(cfg.isProduction).toBe(true);
    expect(cfg.encryptionKey.length).toBe(32);
    expect(cfg.masterKek.equals(Buffer.alloc(32, 3))).toBe(true);
  });

  it('fails closed when a configured key file cannot be read', () => {
    let err: unknown;
    try {
      loadConfig({ ...prodBase(), KEY_SOURCE: 'file', MASTER_KEK_FILE: '/nonexistent/master.key' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConfigError);
    const issues = (err as ConfigError).issues.map((i) => i.variable);
    expect(issues).toContain('KEY_SOURCE');
  });
});
