import { createHash } from 'node:crypto';
import type { FastifyRequest } from 'fastify';

/**
 * Layered rate limiting. The global per-IP / per-API-key budget lives in
 * `http/security.ts`; these helpers add stricter, identity-scoped limits to
 * expensive routes (LLM calls, uploads) plus an in-process concurrency cap on
 * streaming responses per organization.
 *
 * Each factory returns a `@fastify/rate-limit` per-route config object suitable
 * for `{ config: { rateLimit: ... } }` on a route definition.
 */

export interface LayeredLimits {
  /** Max LLM/completion requests per account per hour. */
  readonly llmHourly: number;
  /** Max document uploads per organization per hour. */
  readonly uploadsHourly: number;
  /** Max concurrent streaming responses per organization. */
  readonly streamsPerOrg: number;
  /** Per-organization storage quota in bytes. */
  readonly storageQuotaBytes: number;
}

const HOUR_MS = 60 * 60_000;

/** Stable per-account bucket key (org+user when authenticated, else IP). */
function accountKey(req: FastifyRequest): string {
  const a = req.authContext;
  if (a) return `acct:${a.orgId}:${a.userId}`;
  const apiKey = req.apiKey;
  if (apiKey) return `apikey:${apiKey.orgId}:${createHash('sha256').update(apiKey.keyId).digest('hex')}`;
  return `ip:${req.ip}`;
}

/** Per-organization bucket key (falls back to IP when no tenant context). */
function orgKey(req: FastifyRequest): string {
  const a = req.authContext;
  if (a) return `org:${a.orgId}`;
  const apiKey = req.apiKey;
  if (apiKey) return `org:${apiKey.orgId}`;
  return `ip:${req.ip}`;
}

export interface RouteRateLimit {
  readonly max: number;
  readonly timeWindow: number;
  readonly keyGenerator: (req: FastifyRequest) => string;
}

/** Per-account hourly limit for LLM/completion endpoints. */
export function llmRateLimit(limits: LayeredLimits): RouteRateLimit {
  return { max: limits.llmHourly, timeWindow: HOUR_MS, keyGenerator: accountKey };
}

/** Per-organization hourly limit for document uploads. */
export function uploadRateLimit(limits: LayeredLimits): RouteRateLimit {
  return { max: limits.uploadsHourly, timeWindow: HOUR_MS, keyGenerator: orgKey };
}

/**
 * In-process concurrency limiter for streaming responses, scoped per org.
 * `acquire` returns a release function or throws {@link StreamLimitError} when
 * the org is at its cap. Single-instance by design; horizontal deployments
 * should pair this with sticky routing or a shared store.
 */
export class StreamLimitError extends Error {
  constructor(readonly orgId: string, readonly limit: number) {
    super('too many concurrent streams');
    this.name = 'StreamLimitError';
  }
}

export class StreamConcurrencyLimiter {
  private readonly active = new Map<string, number>();

  constructor(private readonly maxPerOrg: number) {}

  acquire(orgId: string): () => void {
    const current = this.active.get(orgId) ?? 0;
    if (current >= this.maxPerOrg) throw new StreamLimitError(orgId, this.maxPerOrg);
    this.active.set(orgId, current + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const n = (this.active.get(orgId) ?? 1) - 1;
      if (n <= 0) this.active.delete(orgId);
      else this.active.set(orgId, n);
    };
  }

  /** Current active stream count for an org (for tests / introspection). */
  count(orgId: string): number {
    return this.active.get(orgId) ?? 0;
  }
}
