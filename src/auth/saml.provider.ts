import type { AuthProvider } from './provider.js';

/**
 * SAML 2.0 provider — INTERFACE STUB.
 *
 * SAML is intentionally deferred to P2 (it is significantly more complex than
 * OIDC: XML signature canonicalization/verification, metadata exchange,
 * assertion encryption). This stub exists to prove the AuthProvider abstraction
 * accommodates SAML without rework: it slots in as `kind: 'saml'` with the same
 * begin/complete shape as OIDC. All operations fail closed until implemented.
 */
export class SamlNotImplementedError extends Error {
  constructor() {
    super('SAML authentication is not implemented yet (planned for P2)');
    this.name = 'SamlNotImplementedError';
  }
}

export interface SamlVerifiedIdentity {
  subject: string;
  email: string | undefined;
}

export class SamlAuthProvider implements AuthProvider {
  readonly id = 'saml';
  readonly kind = 'saml' as const;

  /** Would return the IdP SSO redirect (AuthnRequest). Not yet implemented. */
  begin(): Promise<{ redirectUrl: string; relayState: string }> {
    return Promise.reject(new SamlNotImplementedError());
  }

  /** Would verify a signed SAML assertion and return the identity. Not yet implemented. */
  complete(_samlResponse: string, _expectedRelayState: string): Promise<SamlVerifiedIdentity> {
    return Promise.reject(new SamlNotImplementedError());
  }
}
