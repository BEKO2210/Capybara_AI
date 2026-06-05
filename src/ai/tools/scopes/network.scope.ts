import { assertUrlAllowed } from '../../../net/ssrfGuard.js';
import type { NetCapability, NetworkScope } from '../tool.types.js';

export class NetworkAccessError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NetworkAccessError';
  }
}

/**
 * Network capability for tools. Two independent gates, both must pass:
 *   1. host allowlist — the target hostname must be declared in the scope.
 *   2. SSRF guard — the resolved IP must not be private/loopback/metadata
 *      (unless the scope explicitly opts into private ranges).
 *
 * Note the SSRF guard runs WITHOUT the host-allowlist shortcut, so even an
 * allowlisted hostname that resolves to a metadata/private IP is blocked.
 */
export function createNetCapability(
  scope: NetworkScope | undefined,
  fetchImpl: typeof fetch = fetch,
): NetCapability {
  return {
    async fetch(url: string, init?: RequestInit): Promise<Response> {
      if (!scope) throw new NetworkAccessError('network access not granted');

      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        throw new NetworkAccessError('invalid URL');
      }

      if (!scope.allowedHosts.includes(parsed.hostname)) {
        throw new NetworkAccessError(`host not allowlisted: ${parsed.hostname}`);
      }

      // Range checks always apply (do not pass allowedHosts here).
      await assertUrlAllowed(url, {
        ...(scope.allowPrivateRanges ? { allowPrivateRanges: true } : {}),
      });

      return fetchImpl(url, init);
    },
  };
}
