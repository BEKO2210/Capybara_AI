import { defineConfig } from 'drizzle-kit';

// Drizzle Kit configuration. Note: the runtime migrator (src/db/migrate.ts)
// applies hand-authored, idempotent SQL migrations (src/db/sql/*.sql) so that
// Row-Level-Security policies and the restricted application role are created
// deterministically alongside table DDL. This config exists for `drizzle-kit`
// introspection/diffing against the typed schema (src/db/schema).
export default defineConfig({
  dialect: 'postgresql',
  schema: './src/db/schema/index.ts',
  out: './src/db/sql',
  dbCredentials: {
    // Never read from a committed default; supplied by environment when used.
    url: process.env['DATABASE_MIGRATION_URL'] ?? process.env['DATABASE_URL'] ?? '',
  },
});
