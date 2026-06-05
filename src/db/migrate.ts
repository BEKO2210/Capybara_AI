import { readFile, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import postgres from 'postgres';

/**
 * Database migrator.
 *
 * Runs as a PRIVILEGED role (superuser/owner). It:
 *   1. Creates the restricted application role `capybara_app`
 *      (LOGIN, NOSUPERUSER, NOBYPASSRLS) — the role the app connects as.
 *   2. Grants it CONNECT on the target database.
 *   3. Applies the ordered, idempotent SQL migrations in ./sql, which create
 *      tables and enable Row-Level Security + least-privilege table grants.
 *
 * Keeping role creation here (not in committed SQL) lets the app-role password
 * be supplied at runtime instead of hardcoded.
 */

export const APP_ROLE = 'capybara_app';

const sqlDir = join(dirname(fileURLToPath(import.meta.url)), 'sql');

function quoteIdent(ident: string): string {
  return `"${ident.replace(/"/g, '""')}"`;
}

function quoteLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/** Derive the restricted-app connection URL from a privileged admin URL. */
export function deriveAppUrl(adminUrl: string, appPassword: string): string {
  const u = new URL(adminUrl);
  u.username = APP_ROLE;
  u.password = appPassword;
  return u.toString();
}

export interface MigrateOptions {
  /** Password to set on the restricted application role. */
  appPassword: string;
}

export async function migrate(adminUrl: string, opts: MigrateOptions): Promise<void> {
  const sql = postgres(adminUrl, { max: 1, onnotice: () => {} });
  try {
    const dbRows = await sql<{ current_database: string }[]>`SELECT current_database()`;
    const dbName = dbRows[0]?.current_database;
    if (!dbName) throw new Error('could not determine current database name');

    // 1. Create the restricted application role (idempotent).
    await sql.unsafe(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${APP_ROLE}') THEN
          CREATE ROLE ${APP_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
        END IF;
      END
      $$;
    `);
    // Always (re)set the password and re-assert the safe attributes.
    await sql.unsafe(
      `ALTER ROLE ${APP_ROLE} WITH LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD ${quoteLiteral(
        opts.appPassword,
      )};`,
    );

    // 2. Grant CONNECT on the concrete database.
    await sql.unsafe(`GRANT CONNECT ON DATABASE ${quoteIdent(dbName)} TO ${APP_ROLE};`);

    // 3. Apply ordered SQL migrations.
    const files = (await readdir(sqlDir)).filter((f) => f.endsWith('.sql')).sort();
    for (const file of files) {
      const contents = await readFile(join(sqlDir, file), 'utf8');
      await sql.unsafe(contents);
    }
  } finally {
    await sql.end({ timeout: 5 });
  }
}
