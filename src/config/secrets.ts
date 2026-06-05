/**
 * Secret-strength validation.
 *
 * Security posture: fail-closed. A secret that is missing, too short, a known
 * placeholder, or low-entropy is REJECTED. We never log or echo the secret
 * value itself — only a machine-readable reason code.
 */

/** Minimum acceptable length for a high-entropy secret (characters). */
export const MIN_SECRET_LENGTH = 32;

/** Minimum number of distinct characters (cheap low-entropy heuristic). */
export const MIN_DISTINCT_CHARS = 8;

/**
 * Values (or fragments) that must never be accepted as a production secret.
 * These cover common scaffolding defaults and anything shipped in
 * `.env.example`. Matching is case-insensitive and substring-based.
 */
export const PLACEHOLDER_DENYLIST: readonly string[] = [
  'change_me',
  'changeme',
  'change-me',
  'placeholder',
  'example',
  'default',
  'secret',
  'password',
  'pass123',
  'test',
  'dev',
  'demo',
  'localhost',
  'todo',
  'xxxxx',
  '00000000',
  '12345678',
  'replace',
  'capybara', // app name must not be (part of) a secret
];

export type SecretRejectionReason =
  | 'missing'
  | 'too_short'
  | 'placeholder'
  | 'low_entropy';

export interface SecretAssessment {
  ok: boolean;
  reason?: SecretRejectionReason;
}

function distinctCharCount(value: string): number {
  return new Set(value).size;
}

/**
 * Assess a candidate secret. Returns a structured result; callers decide how
 * to surface it. Never returns the secret value.
 */
export function assessSecret(value: string | undefined): SecretAssessment {
  if (value === undefined || value.length === 0) {
    return { ok: false, reason: 'missing' };
  }
  if (value.length < MIN_SECRET_LENGTH) {
    return { ok: false, reason: 'too_short' };
  }
  const lowered = value.toLowerCase();
  for (const bad of PLACEHOLDER_DENYLIST) {
    if (lowered.includes(bad)) {
      return { ok: false, reason: 'placeholder' };
    }
  }
  if (distinctCharCount(value) < MIN_DISTINCT_CHARS) {
    return { ok: false, reason: 'low_entropy' };
  }
  return { ok: true };
}

/** Convenience boolean form. */
export function isStrongSecret(value: string | undefined): boolean {
  return assessSecret(value).ok;
}
