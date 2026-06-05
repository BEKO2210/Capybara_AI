import { hash, verify } from '@node-rs/argon2';

/**
 * Password hashing with Argon2id (the @node-rs/argon2 default algorithm, and
 * the OWASP-recommended choice). Parameters follow OWASP guidance (>= 19 MiB
 * memory, time cost 2, parallelism 1) and can be tuned via environment in later
 * phases. Verification is constant-time within argon2 and fails closed: any
 * error yields `false`, never an exception that could be mistaken for success.
 */
const ARGON2_OPTIONS = {
  memoryCost: 19_456, // KiB (~19 MiB)
  timeCost: 2,
  parallelism: 1,
} as const;

export async function hashPassword(plain: string): Promise<string> {
  return hash(plain, ARGON2_OPTIONS);
}

export async function verifyPassword(hashString: string, plain: string): Promise<boolean> {
  try {
    return await verify(hashString, plain, ARGON2_OPTIONS);
  } catch {
    return false;
  }
}
