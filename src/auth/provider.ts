/**
 * Authentication provider abstraction.
 *
 * The system authenticates against pluggable providers. The local
 * username/password provider is the development/self-host default; OIDC and
 * SAML providers will implement the same base contract later WITHOUT changing
 * call sites. Keeping credential specifics out of the base interface is what
 * makes it OIDC/SAML-ready.
 */

/** A successfully authenticated global identity (pre-tenant-selection). */
export interface AuthenticatedIdentity {
  readonly userId: string;
  readonly email: string;
}

export type AuthProviderKind = 'password' | 'oidc' | 'saml';

export interface AuthProvider {
  /** Stable identifier, e.g. 'local', 'okta-oidc'. */
  readonly id: string;
  readonly kind: AuthProviderKind;
}

/**
 * Password-based provider (local dev auth now). OIDC/SAML providers will define
 * their own flow-specific methods (authorize/callback) under the same
 * `AuthProvider` base, so consumers depend on the abstraction, not on passwords.
 */
export interface PasswordAuthProvider extends AuthProvider {
  readonly kind: 'password';
  /** Returns the identity on success, or null on any failure (fail-closed). */
  authenticate(email: string, password: string): Promise<AuthenticatedIdentity | null>;
}
