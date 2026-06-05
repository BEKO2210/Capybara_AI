import type { Role } from '../db/schema/index.js';

/**
 * Role-based access control: a small, auditable, least-privilege capability
 * model. Permissions are explicit `resource:action` strings. Each role's
 * capability set is built additively from the less-privileged role, so the
 * ordering owner > admin > member > viewer is a strict superset chain.
 */

export const PERMISSIONS = [
  'org:read',
  'org:update',
  'org:delete',
  'member:read',
  'member:invite',
  'member:remove',
  'member:update_role',
  'content:read',
  'content:create',
  'content:update',
  'content:delete',
  'ai:invoke',
  'ai:approve_tool',
  'audit:read',
  // Document intelligence (RAG)
  'document:read',
  'document:query',
  'document:upload',
  'document:delete',
  'document:hold',
  'document:release_hold',
  'gdpr:erase',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

/** Numeric rank for "at least this role" comparisons. Higher = more power. */
export const ROLE_RANK: Readonly<Record<Role, number>> = {
  viewer: 0,
  member: 1,
  admin: 2,
  owner: 3,
};

const viewer: Permission[] = ['org:read', 'member:read', 'content:read', 'document:read', 'document:query'];

const member: Permission[] = [
  ...viewer,
  'content:create',
  'content:update',
  'ai:invoke',
  'document:upload',
  'document:delete',
];

const admin: Permission[] = [
  ...member,
  'org:update',
  'member:invite',
  'member:remove',
  'member:update_role',
  'content:delete',
  'ai:approve_tool',
  'audit:read',
  'document:hold',
];

const owner: Permission[] = [...admin, 'org:delete', 'document:release_hold', 'gdpr:erase'];

/**
 * A user's maximum document classification clearance, by role:
 *   viewer→PUBLIC(0), member→INTERNAL(1), admin→CONFIDENTIAL(2), owner→SECRET(3).
 */
export function clearanceForRole(role: Role): number {
  return ROLE_RANK[role];
}

/** Frozen capability matrix: role -> the exact permissions it holds. */
export const ROLE_PERMISSIONS: Readonly<Record<Role, ReadonlySet<Permission>>> = Object.freeze({
  viewer: new Set(viewer),
  member: new Set(member),
  admin: new Set(admin),
  owner: new Set(owner),
});
