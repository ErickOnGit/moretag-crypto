import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    exclude: ["dist/**", "node_modules/**"],
    environment: "node",
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
  },
});
