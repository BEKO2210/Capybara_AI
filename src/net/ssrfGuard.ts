import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/**
 * SSRF egress guard.
 *
 * Used for OUTBOUND requests whose target is influenced by less-trusted flows
 * (AI tool "network" scope). It resolves the host's IP and rejects private,
 * loopback, link-local, and cloud-metadata ranges unless the deployment has
 * explicitly opted in (e.g. to reach a self-hosted internal service).
 *
 * NOTE: server-configured LLM provider endpoints are trusted by construction
 * and are NOT routed through this guard — the SSRF risk Odysseus had came from
 * letting a *caller* supply the target URL, which this codebase forbids.
 */

export interface SsrfGuardOptions {
  /** Hostnames explicitly permitted even if they resolve to private ranges. */
  allowedHosts?: readonly string[];
  /** Allow private/loopback/link-local targets (self-hosted internal services). */
  allowPrivateRanges?: boolean;
}

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfBlockedError';
  }
}

function ipToParts(ip: string): number[] {
  return ip.split('.').map((p) => Number.parseInt(p, 10));
}

/** True for IPv4/IPv6 ranges that must never be reached from untrusted flows. */
export function isBlockedAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) {
    const [a, b] = ipToParts(ip);
    if (a === undefined || b === undefined) return true; // malformed => block
    if (a === 10) return true; // 10.0.0.0/8 private
    if (a === 127) return true; // loopback
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 169 && b === 254) return true; // link-local + cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    return false;
  }
  // IPv6
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true; // loopback / unspecified
  if (lower.startsWith('fe80')) return true; // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local fc00::/7
  if (lower.startsWith('::ffff:')) {
    // IPv4-mapped — re-check the embedded v4 address.
    const v4 = lower.slice('::ffff:'.length);
    if (isIP(v4) === 4) return isBlockedAddress(v4);
  }
  return false;
}

/**
 * Assert that `urlString` is safe to fetch. Resolves DNS and checks every
 * resolved address. Returns the resolved IP that should be connected to (DNS
 * pinning: the caller should connect to this exact IP to avoid rebinding).
 */
export async function assertUrlAllowed(
  urlString: string,
  options: SsrfGuardOptions = {},
): Promise<{ url: URL; address: string }> {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    throw new SsrfBlockedError('invalid URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfBlockedError(`disallowed protocol: ${url.protocol}`);
  }

  const host = url.hostname;
  if (options.allowedHosts?.includes(host)) {
    // Still need a concrete address to connect to.
    const literal = isIP(host) ? host : (await dnsLookup(host)).address;
    return { url, address: literal };
  }

  // Resolve all addresses; block if ANY is in a forbidden range (defense
  // against multi-record DNS rebinding).
  const resolved = isIP(host)
    ? [{ address: host }]
    : await dnsLookup(host, { all: true });

  for (const r of resolved) {
    if (isBlockedAddress(r.address) && !options.allowPrivateRanges) {
      throw new SsrfBlockedError(`target resolves to a blocked address: ${r.address}`);
    }
  }

  const first = resolved[0];
  if (!first) throw new SsrfBlockedError('host did not resolve');
  return { url, address: first.address };
}
