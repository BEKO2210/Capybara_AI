import { loadConfig, ConfigError } from './config/index.js';
import { buildServer } from './server.js';

/**
 * Production entrypoint. Loads and validates configuration FIRST — if anything
 * is missing or weak in production, loadConfig throws and the process exits
 * non-zero before binding a socket (fail-closed). Otherwise it starts the
 * server bound to the configured address (loopback by default).
 */
async function main(): Promise<void> {
  const config = loadConfig();
  const app = await buildServer({ config });
  await app.listen({ host: config.bind, port: config.port });
  app.log.info({ env: config.appEnv, bind: config.bind, port: config.port }, 'capybara_ai started');
}

main().catch((err: unknown) => {
  if (err instanceof ConfigError) {
    // Never print secret values — ConfigError only carries variable + reason.
    console.error(err.message);
  } else {
    console.error('failed to start:', err instanceof Error ? err.message : err);
  }
  process.exit(1);
});
