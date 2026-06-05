import { describe, it, expect } from 'vitest';
import { StreamConcurrencyLimiter, StreamLimitError, llmRateLimit, uploadRateLimit, type LayeredLimits } from '../../src/http/rateLimits.js';

const LIMITS: LayeredLimits = { llmHourly: 50, uploadsHourly: 20, streamsPerOrg: 2, storageQuotaBytes: 500 * 1024 * 1024 };

describe('rate limits — per-route configs', () => {
  it('builds an hourly per-account LLM limit', () => {
    const rl = llmRateLimit(LIMITS);
    expect(rl.max).toBe(50);
    expect(rl.timeWindow).toBe(3_600_000);
  });

  it('builds an hourly per-org upload limit', () => {
    const rl = uploadRateLimit(LIMITS);
    expect(rl.max).toBe(20);
    expect(rl.timeWindow).toBe(3_600_000);
  });
});

describe('rate limits — stream concurrency per org', () => {
  it('allows up to the cap, then rejects, and releases free slots', () => {
    const limiter = new StreamConcurrencyLimiter(2);
    const r1 = limiter.acquire('org-a');
    const r2 = limiter.acquire('org-a');
    expect(limiter.count('org-a')).toBe(2);
    expect(() => limiter.acquire('org-a')).toThrow(StreamLimitError);

    r1();
    expect(limiter.count('org-a')).toBe(1);
    const r3 = limiter.acquire('org-a'); // slot freed
    expect(limiter.count('org-a')).toBe(2);

    // Releasing is idempotent.
    r2();
    r2();
    r3();
    expect(limiter.count('org-a')).toBe(0);
  });

  it('isolates concurrency between organizations', () => {
    const limiter = new StreamConcurrencyLimiter(1);
    limiter.acquire('org-a');
    // A different org is unaffected by org-a's usage.
    expect(() => limiter.acquire('org-b')).not.toThrow();
    expect(() => limiter.acquire('org-a')).toThrow(StreamLimitError);
  });
});
