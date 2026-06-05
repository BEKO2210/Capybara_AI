import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Testcontainers spins up real Postgres; allow generous timeouts and avoid
    // parallel container contention by running test files sequentially.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    fileParallelism: false,
    pool: 'forks',
    reporters: ['default'],
  },
});
