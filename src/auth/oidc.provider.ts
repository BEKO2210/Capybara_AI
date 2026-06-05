import * as client from 'openid-client';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { AuthProvider } from './provider.js';

/** Clock-skew tolerance for ID token exp/iat checks. */
const CLOCK_TOLERANCE_SECONDS = 30;

/**
 * OIDC authentication provider (authorization-code flow with PKCE; no implicit
 * grant). Built on `openid-client`, which performs discovery, JWKS-based ID
 * token signature verification, and validation of issuer, audience, expiry
 * (with clock-skew tolerance), state and nonce. Any failure throws — callers
 * treat a thrown error as authentication denied (fail-closed).
 *
 * `start()` returns values the caller must persist (state, nonce, codeVerifier)
 * — typically in a short-lived, signed cookie — and replay back into
 * `complete()`. They are never trusted from the OIDC redirect alone.
 */
export interface OidcProviderConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope?: string;
  /** Allow plain-HTTP issuer (dev/test only). Never enable in production. */
  allowInsecure?: boolean;
}

export interface OidcAuthStart {
  authorizationUrl: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}

export interface OidcVerifiedIdentity {
  subject: string;
  email: string | undefined;
  issuer: string;
}

export class OidcAuthProvider implements AuthProvider {
  readonly id = 'oidc';
  readonly kind = 'oidc' as const;
  private discovered: Promise<client.Configuration> | null = null;
  private jwks: JWTVerifyGetKey | null = null;

  constructor(private readonly cfg: OidcProviderConfig) {}

  private jwksFor(config: client.Configuration): JWTVerifyGetKey {
    if (!this.jwks) {
      const jwksUri = config.serverMetadata().jwks_uri;
      if (!jwksUri) throw new Error('OIDC: issuer metadata has no jwks_uri');
      this.jwks = createRemoteJWKSet(new URL(jwksUri));
    }
    return this.jwks;
  }

  private configuration(): Promise<client.Configuration> {
    if (!this.discovered) {
      const options = this.cfg.allowInsecure
        ? { execute: [client.allowInsecureRequests] }
        : undefined;
      this.discovered = client.discovery(
        new URL(this.cfg.issuer),
        this.cfg.clientId,
        this.cfg.clientSecret,
        undefined,
        options,
      );
    }
    return this.discovered;
  }

  /** Begin login: returns the authorization URL + the values to store server-side. */
  async start(): Promise<OidcAuthStart> {
    const config = await this.configuration();
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    const state = client.randomState();
    const nonce = client.randomNonce();
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: this.cfg.redirectUri,
      scope: this.cfg.scope ?? 'openid email profile',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
      nonce,
    });
    return { authorizationUrl: url.href, state, nonce, codeVerifier };
  }

  /** Complete login from the redirect URL; verifies the ID token end-to-end. */
  async complete(
    currentUrl: string,
    expected: { state: string; nonce: string; codeVerifier: string },
  ): Promise<OidcVerifiedIdentity> {
    const config = await this.configuration();
    const tokens = await client.authorizationCodeGrant(config, new URL(currentUrl), {
      expectedState: expected.state,
      expectedNonce: expected.nonce,
      pkceCodeVerifier: expected.codeVerifier,
    });

    // Defense in depth: the code flow MAY rely on TLS for ID token integrity,
    // so we additionally verify the ID token signature against the issuer JWKS
    // and re-check issuer/audience/expiry with explicit clock-skew tolerance.
    const idToken = tokens.id_token;
    if (!idToken) throw new Error('OIDC: no ID token returned');
    await jwtVerify(idToken, this.jwksFor(config), {
      issuer: this.cfg.issuer,
      audience: this.cfg.clientId,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    });

    const claims = tokens.claims();
    if (!claims || typeof claims.sub !== 'string') {
      throw new Error('OIDC: ID token missing subject claim');
    }
    return {
      subject: claims.sub,
      email: typeof claims.email === 'string' ? claims.email : undefined,
      issuer: String(claims.iss),
    };
  }
}
