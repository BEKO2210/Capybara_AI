import { randomBytes, createHash } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { organizations, users, memberships, type Role } from '../../src/db/schema/index.js';
import { clearanceForRole } from '../../src/rbac/roles.js';
import type { Embedder } from '../../src/ai/embeddings/embedder.js';
import type { AppDatabase } from '../../src/db/client.js';

export const DOC_DIMS = 768;
export const MASTER_KEY = randomBytes(32);

/**
 * Deterministic, offline bag-of-words embedder for tests: hashes each word into
 * a 768-dim term-frequency vector and L2-normalizes. Texts sharing words get
 * higher cosine similarity, so relevance ordering is meaningful without a model.
 * (Production uses the real Ollama/OpenAI embedders — this lives only in tests.)
 */
export function bowEmbedder(): Embedder {
  return {
    dimensions: DOC_DIMS,
    embed: async (texts: string[]) => texts.map(bow),
  };
}

function bow(text: string): number[] {
  const v = new Array<number>(DOC_DIMS).fill(0);
  for (const tok of text.toLowerCase().match(/[a-z0-9]+/g) ?? []) {
    const idx = createHash('sha1').update(tok).digest().readUInt16BE(0) % DOC_DIMS;
    v[idx]! += 1;
  }
  const norm = Math.sqrt(v.reduce((s, x) => s + x * x, 0)) || 1;
  return v.map((x) => x / norm);
}

export interface SeededPrincipal {
  orgId: string;
  userId: string;
  role: Role;
  clearance: number;
}

/** Seed an org + user + membership via the admin (superuser) connection. */
export async function seedOrgUser(
  adminDb: AppDatabase,
  opts: { slug: string; email: string; role: Role },
): Promise<SeededPrincipal> {
  const [o] = await adminDb
    .insert(organizations)
    .values({ slug: opts.slug, name: opts.slug })
    .returning({ id: organizations.id });
  const [u] = await adminDb
    .insert(users)
    .values({ email: opts.email, passwordHash: 'x' })
    .returning({ id: users.id });
  await adminDb.insert(memberships).values({ orgId: o!.id, userId: u!.id, role: opts.role });
  return { orgId: o!.id, userId: u!.id, role: opts.role, clearance: clearanceForRole(opts.role) };
}

/** Add another member to an existing org. */
export async function seedMember(
  adminDb: AppDatabase,
  orgId: string,
  opts: { email: string; role: Role },
): Promise<SeededPrincipal> {
  const [u] = await adminDb
    .insert(users)
    .values({ email: opts.email, passwordHash: 'x' })
    .returning({ id: users.id });
  await adminDb.insert(memberships).values({ orgId, userId: u!.id, role: opts.role });
  return { orgId, userId: u!.id, role: opts.role, clearance: clearanceForRole(opts.role) };
}

export async function tmpStorageDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'capy-docs-'));
}
