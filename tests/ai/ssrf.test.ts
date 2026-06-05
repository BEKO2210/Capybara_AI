import { describe, it, expect } from 'vitest';
import { isBlockedAddress, assertUrlAllowed, SsrfBlockedError } from '../../src/net/ssrfGuard.js';

describe('net/ssrfGuard — blocked-range detection', () => {
  it('blocks private, loopback, link-local and metadata ranges', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.1.1', '172.16.0.1', '169.254.169.254', '::1']) {
      expect(isBlockedAddress(ip), ip).toBe(true);
    }
  });

  it('allows ordinary public addresses', () => {
    for (const ip of ['93.184.216.34', '8.8.8.8', '1.1.1.1']) {
      expect(isBlockedAddress(ip), ip).toBe(false);
    }
  });
});

describe('net/ssrfGuard — assertUrlAllowed (IP literals, no DNS)', () => {
  it('rejects the cloud metadata endpoint', async () => {
    await expect(assertUrlAllowed('http://169.254.169.254/latest/meta-data')).rejects.toThrow(
      SsrfBlockedError,
    );
  });

  it('rejects non-http(s) protocols', async () => {
    await expect(assertUrlAllowed('file:///etc/passwd')).rejects.toThrow(SsrfBlockedError);
  });

  it('permits a public IP literal', async () => {
    const { address } = await assertUrlAllowed('http://93.184.216.34/');
    expect(address).toBe('93.184.216.34');
  });

  it('permits a private target only when explicitly opted in', async () => {
    await expect(assertUrlAllowed('http://127.0.0.1:11434/')).rejects.toThrow(SsrfBlockedError);
    const { address } = await assertUrlAllowed('http://127.0.0.1:11434/', { allowPrivateRanges: true });
    expect(address).toBe('127.0.0.1');
  });
});
