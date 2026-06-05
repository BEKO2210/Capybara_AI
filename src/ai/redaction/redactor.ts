/**
 * Sensitive-data redaction. Applied to content/arguments BEFORE they are sent
 * to a model or persisted in invocation records, so secrets and PII are not
 * leaked to the LLM, logs, or audit storage.
 *
 * This is pattern-based and intentionally conservative (false positives are
 * preferable to leaks). It is not a substitute for not handling secrets at all.
 */

export const REDACTED = '[REDACTED]';

interface RedactionPattern {
  name: string;
  re: RegExp;
}

const PATTERNS: RedactionPattern[] = [
  // JWTs (header.payload.signature)
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g },
  // PEM private key blocks
  { name: 'pem', re: /-----BEGIN [^-]+-----[\s\S]+?-----END [^-]+-----/g },
  // Bearer tokens
  { name: 'bearer', re: /Bearer\s+[A-Za-z0-9._-]{8,}/gi },
  // Common API-key shapes (sk-..., AKIA..., long key/secret/token values)
  { name: 'aws_akid', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'api_key', re: /\b(?:sk|pk|api[_-]?key|secret|token)[-_]?[A-Za-z0-9]{16,}\b/gi },
  // Email addresses (PII)
  { name: 'email', re: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g },
];

export function redactString(input: string): string {
  let out = input;
  for (const { re } of PATTERNS) {
    out = out.replace(re, REDACTED);
  }
  return out;
}

/** Deep-redact a value, returning a structurally-equal copy with masks applied. */
export function redact(value: unknown): unknown {
  if (typeof value === 'string') return redactString(value);
  if (Array.isArray(value)) return value.map(redact);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redact(v);
    }
    return out;
  }
  return value;
}
