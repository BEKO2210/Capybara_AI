import type { Role } from '../db/schema/index.js';
import { ROLE_PERMISSIONS, ROLE_RANK, type Permission } from './roles.js';

/** Raised when an authenticated principal lacks a required capability. */
export class ForbiddenError extends Error {
  readonly permission: Permission | undefined;
  constructor(message: string, permission?: Permission) {
    super(message);
    this.name = 'ForbiddenError';
    this.permission = permission;
  }
}

/** True iff `role` holds `permission`. Unknown roles fail closed (false). */
export function can(role: Role, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role]?.has(permission) ?? false;
}

/** True iff `role` is at least as privileged as `minimum`. */
export function hasAtLeastRole(role: Role, minimum: Role): boolean {
  return (ROLE_RANK[role] ?? -1) >= (ROLE_RANK[minimum] ?? Number.POSITIVE_INFINITY);
}

/** Throw ForbiddenError unless `role` holds `permission`. */
export function assertCan(role: Role, permission: Permission): void {
  if (!can(role, permission)) {
    throw new ForbiddenError(`role "${role}" lacks permission "${permission}"`, permission);
  }
}
