import { migrate } from './migrate.js';

/**
 * Migration runner, intended to run as a one-shot using the PRIVILEGED
 * migration role. It creates/updates the restricted application role
 * (capybara_app) with the supplied password and applies all SQL migrations.
 *
 * Required environment:
 *   DATABASE_MIGRATION_URL — DSN for the privileged (superuser/owner) role.
 *   DB_APP_PASSWORD        — password to set on the restricted app role; the
 *                            app's DATABASE_URL must use this same password.
 */
async function main(): Promise<void> {
  const adminUrl = process.env['DATABASE_MIGRATION_URL'];
  const appPassword = process.env['DB_APP_PASSWORD'];
  if (!adminUrl || !appPassword) {
    console.error('DATABASE_MIGRATION_URL and DB_APP_PASSWORD are required');
    process.exit(1);
  }
  await migrate(adminUrl, { appPassword });
  console.log('migrations applied');
}

main().catch((err: unknown) => {
  console.error('migration failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
