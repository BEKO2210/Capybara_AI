import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { generateKeyPair, exportJWK, SignJWT, type JWK, type CryptoKey } from 'jose';
import { OidcAuthProvider } from '../../src/auth/oidc.provider.js';

const CLIENT_ID = 'test-client';
const CLIENT_SECRET = 'test-secret';
const REDIRECT_URI = 'http://127.0.0.1:9999/callback';

type ScenarioKind = 'happy' | 'expired' | 'wrongIssuer' | 'missingNonce' | 'tampered';
interface Scenario {
  kind: ScenarioKind;
  nonce?: string;
}

let server: Server;
let issuer: string;
let privateKey: CryptoKey;
let publicJwk: JWK;
let scenario: Scenario = { kind: 'happy' };

function sendJson(res: ServerResponse, body: unknown): void {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function mintIdToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  let iss = issuer;
  let expDelta = 3600;
  let nonce = scenario.nonce;
  let tamper = false;
  switch (scenario.kind) {
    case 'expired':
      expDelta = -120;
      break;
    case 'wrongIssuer':
      iss = 'https://attacker.example';
      break;
    case 'missingNonce':
      nonce = undefined;
      break;
    case 'tampered':
      tamper = true;
      break;
  }
  const payload: Record<string, unknown> = {
    sub: 'user-123',
    aud: CLIENT_ID,
    email: 'oidc-user@example.com',
  };
  if (nonce) payload['nonce'] = nonce;

  let jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(iss)
    .setIssuedAt(now)
    .setExpirationTime(now + expDelta)
    .sign(privateKey);

  if (tamper) {
    const parts = jwt.split('.');
    parts[2] = parts[2]!.split('').reverse().join(''); // corrupt signature
    jwt = parts.join('.');
  }
  return jwt;
}

beforeAll(async () => {
  const kp = await generateKeyPair('RS256', { extractable: true });
  privateKey = kp.privateKey;
  publicJwk = { ...(await exportJWK(kp.publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };

  server = createServer((req, res) => {
    const url = req.url ?? '';
    if (url.startsWith('/.well-known/openid-configuration')) {
      sendJson(res, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        grant_types_supported: ['authorization_code'],
        code_challenge_methods_supported: ['S256'],
      });
      return;
    }
    if (url.startsWith('/jwks')) {
      sendJson(res, { keys: [publicJwk] });
      return;
    }
    if (req.method === 'POST' && url.startsWith('/token')) {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        void mintIdToken().then((idToken) =>
          sendJson(res, {
            access_token: 'access-token',
            token_type: 'Bearer',
            expires_in: 3600,
            id_token: idToken,
          }),
        );
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

function newProvider(): OidcAuthProvider {
  return new OidcAuthProvider({
    issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    allowInsecure: true, // http test IdP
  });
}

async function runFlow(kind: ScenarioKind) {
  const provider = newProvider();
  const start = await provider.start();
  scenario = { kind, nonce: start.nonce };
  const currentUrl = `${REDIRECT_URI}?code=auth-code&state=${start.state}`;
  return provider.complete(currentUrl, {
    state: start.state,
    nonce: start.nonce,
    codeVerifier: start.codeVerifier,
  });
}

describe('auth/oidc — PKCE authorization-code flow', () => {
  it('builds a PKCE authorization URL (no implicit grant)', async () => {
    const start = await newProvider().start();
    const url = new URL(start.authorizationUrl);
    expect(url.searchParams.get('response_type')).toBe('code');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('state')).toBe(start.state);
    expect(url.searchParams.get('nonce')).toBe(start.nonce);
  });

  it('verifies a valid ID token (happy path)', async () => {
    const identity = await runFlow('happy');
    expect(identity.subject).toBe('user-123');
    expect(identity.email).toBe('oidc-user@example.com');
    expect(identity.issuer).toBe(issuer);
  });

  it('fails closed on an expired ID token', async () => {
    await expect(runFlow('expired')).rejects.toThrow();
  });

  it('fails closed on a wrong issuer', async () => {
    await expect(runFlow('wrongIssuer')).rejects.toThrow();
  });

  it('fails closed on a missing nonce', async () => {
    await expect(runFlow('missingNonce')).rejects.toThrow();
  });

  it('fails closed on a tampered (invalid signature) ID token', async () => {
    await expect(runFlow('tampered')).rejects.toThrow();
  });

  it('fails closed on a state mismatch', async () => {
    const provider = newProvider();
    const start = await provider.start();
    scenario = { kind: 'happy', nonce: start.nonce };
    const currentUrl = `${REDIRECT_URI}?code=auth-code&state=tampered-state`;
    await expect(
      provider.complete(currentUrl, {
        state: start.state,
        nonce: start.nonce,
        codeVerifier: start.codeVerifier,
      }),
    ).rejects.toThrow();
  });
});
