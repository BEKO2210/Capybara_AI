import { SAML } from '@node-saml/node-saml';
import type { AuthProvider } from './provider.js';

/**
 * SAML 2.0 Service-Provider (SP-initiated POST binding).
 *
 * Signature verification, exclusive-C14N canonicalization, and the defenses
 * against XML Signature Wrapping (XSW) are delegated to `@node-saml/node-saml`
 * (built on `xml-crypto`) — these MUST NOT be hand-rolled. On top of the
 * signature we require signed assertions and validate audience, recipient, and
 * NotOnOrAfter. Any failure throws; callers treat a thrown error as denied
 * (fail-closed), mirroring the OIDC provider.
 */
export interface SamlProviderConfig {
  /** IdP SSO endpoint (where the AuthnRequest is sent). */
  entryPoint: string;
  /** SP entity id (this application's issuer). */
  issuer: string;
  /** Assertion Consumer Service URL (where the IdP POSTs the response). */
  callbackUrl: string;
  /** IdP signing certificate(s), PEM (with or without headers). */
  idpCert: string | string[];
  /** Expected audience (defaults to `issuer`). */
  audience?: string;
  /** Clock-skew tolerance for time-bound conditions (ms). Default 30s. */
  acceptedClockSkewMs?: number;
  /** Optional SP private key (PEM) to sign the AuthnRequest. */
  privateKey?: string;
}

export interface SamlVerifiedIdentity {
  subject: string;
  email: string | undefined;
}

/** Narrow shape of the validated SAML profile we depend on. */
interface SamlProfile {
  nameID?: string | null;
  email?: string | null;
  mail?: string | null;
  attributes?: Record<string, unknown> | null;
}

function emailFrom(profile: SamlProfile): string | undefined {
  const direct = profile.email ?? profile.mail;
  if (typeof direct === 'string' && direct.length > 0) return direct.toLowerCase();
  const attrs = profile.attributes ?? {};
  for (const key of ['email', 'mail', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress']) {
    const v = attrs[key];
    if (typeof v === 'string' && v.includes('@')) return v.toLowerCase();
    if (Array.isArray(v) && typeof v[0] === 'string' && v[0].includes('@')) return v[0].toLowerCase();
  }
  return undefined;
}

export class SamlAuthProvider implements AuthProvider {
  readonly id = 'saml';
  readonly kind = 'saml' as const;
  private readonly saml: SAML;

  constructor(cfg: SamlProviderConfig) {
    this.saml = new SAML({
      entryPoint: cfg.entryPoint,
      issuer: cfg.issuer,
      callbackUrl: cfg.callbackUrl,
      idpCert: cfg.idpCert,
      audience: cfg.audience ?? cfg.issuer,
      // Security posture: demand signed assertions; accept signatures on the
      // assertion or the response, but never an unsigned message.
      wantAssertionsSigned: true,
      wantAuthnResponseSigned: false,
      acceptedClockSkewMs: cfg.acceptedClockSkewMs ?? 30_000,
      signatureAlgorithm: 'sha256',
      digestAlgorithm: 'sha256',
      ...(cfg.privateKey ? { privateKey: cfg.privateKey } : {}),
    });
  }

  /** Begin login: returns the IdP redirect URL carrying a (deflated) AuthnRequest. */
  async begin(relayState: string): Promise<{ redirectUrl: string; relayState: string }> {
    const redirectUrl = await this.saml.getAuthorizeUrlAsync(relayState, '', {});
    return { redirectUrl, relayState };
  }

  /**
   * Complete login from a POSTed SAMLResponse (base64). Verifies the signature
   * and time/audience conditions, then returns the identity. Throws on any
   * validation failure.
   */
  async complete(samlResponseBase64: string): Promise<SamlVerifiedIdentity> {
    const { profile } = await this.saml.validatePostResponseAsync({ SAMLResponse: samlResponseBase64 });
    if (!profile || typeof profile.nameID !== 'string' || profile.nameID.length === 0) {
      throw new Error('SAML: response missing a subject (nameID)');
    }
    return { subject: profile.nameID, email: emailFrom(profile as SamlProfile) };
  }
}
