import { drizzle, type PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema/index.js';

export type AppDatabase = PostgresJsDatabase<typeof schema>;

export interface DbClient {
  readonly db: AppDatabase;
  readonly sql: postgres.Sql;
  close(): Promise<void>;
}

/**
 * Create a Drizzle client bound to a connection URL. In production this URL is
 * the RESTRICTED `capybara_app` role; migrations use a separate privileged URL.
 */
export function createDbClient(url: string, max = 5): DbClient {
  const sql = postgres(url, { max, onnotice: () => {} });
  const db = drizzle(sql, { schema });
  return {
    db,
    sql,
    close: () => sql.end({ timeout: 5 }),
  };
}
