import type { AuthContext } from '../auth/context.js';

/**
 * Augment Fastify's request with the server-derived authentication context.
 * It is OPTIONAL on the type because unauthenticated requests exist; guards
 * (requireAuth/requirePermission) narrow it and fail closed when absent.
 */
declare module 'fastify' {
  interface FastifyRequest {
    authContext?: AuthContext;
    apiKey?: { keyId: string; orgId: string; scopes: string[] };
    scimOrgId?: string;
  }
}

export {};
