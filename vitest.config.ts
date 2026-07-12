import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Unit tests live in test/. Playwright specs in e2e/ must NOT be collected.
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
