import { randomBytes } from 'node:crypto';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { migrate, deriveAppUrl } from '../../src/db/migrate.js';
import { createDbClient, type DbClient } from '../../src/db/client.js';

/**
 * Spins up a real PostgreSQL 16 instance via Testcontainers, runs migrations
 * (which create the restricted `capybara_app` role + RLS), and returns two
 * clients:
 *   - `admin`: the container superuser. Superusers bypass RLS — used only for
 *     seeding/administrative setup in tests.
 *   - `app`:   the restricted `capybara_app` role. RLS is ENFORCED here; this
 *     is what production uses.
 */
export interface TestDb {
  container: StartedPostgreSqlContainer;
  adminUrl: string;
  appUrl: string;
  admin: DbClient;
  app: DbClient;
  stop(): Promise<void>;
}

export async function startTestDb(): Promise<TestDb> {
  const container = await new PostgreSqlContainer('postgres:16-alpine').start();
  const adminUrl = container.getConnectionUri();

  const appPassword = randomBytes(18).toString('base64url');
  await migrate(adminUrl, { appPassword });
  const appUrl = deriveAppUrl(adminUrl, appPassword);

  const admin = createDbClient(adminUrl);
  const app = createDbClient(appUrl);

  return {
    container,
    adminUrl,
    appUrl,
    admin,
    app,
    async stop() {
      await admin.close();
      await app.close();
      await container.stop();
    },
  };
}
