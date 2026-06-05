import type { Role } from '../db/schema/index.js';

/**
 * The authenticated request context, established by the auth layer after a
 * session is validated and a tenant (org) is selected. This is the single
 * source of truth for authorization decisions — it is derived server-side from
 * the session, NEVER from client-supplied headers or body fields.
 */
export interface AuthContext {
  readonly userId: string;
  readonly email: string;
  readonly orgId: string;
  readonly role: Role;
  readonly sessionId: string;
}
