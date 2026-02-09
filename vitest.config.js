import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "edge-runtime",
    typecheck: {
      tsconfig: "./tsconfig.test.json",
    },
    coverage: {
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/test.ts",
        "src/**/_generated/**",
        "src/**/*.test.ts",
      ],
    },
  },
});
