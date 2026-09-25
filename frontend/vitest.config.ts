import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/setupTests.ts"],
    css: false,
    // e2e/*.spec.ts are real-browser Playwright tests (its own `test`
    // import, run only via `npm run test:e2e`), not vitest component
    // tests - vitest's default include glob would otherwise also pick
    // them up and fail on Playwright's async describe() restriction.
    exclude: ["e2e/**", "node_modules/**"],
  },
});
