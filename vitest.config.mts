import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    // Keep test output readable; tests that assert on logging stub LOG_LEVEL themselves.
    env: { LOG_LEVEL: "silent" },
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "json-summary"],
      // Server-side logic: API routes, libraries, services and pure UI helpers.
      // React components and pages are not unit-tested and are excluded rather
      // than counted as 0%.
      include: ["app/api/**/*.ts", "lib/**/*.ts", "services/**/*.ts", "utils/**/*.ts"],
      // A little below the current numbers, so CI fails if coverage regresses.
      thresholds: { lines: 90, statements: 90, functions: 90, branches: 75 },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "."),
    },
  },
});
