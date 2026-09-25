import { defineConfig, devices } from "@playwright/test";

// Real browser E2E tests (roadmap phase 9 "Dashboard" exit gate:
// component tests alone - vitest/jsdom - are not enough). These run
// against the real Vite dev server and a real Chromium engine, with the
// API layer mocked at the browser network layer (page.route) rather than
// against a live backend: that keeps this CI-cheap (no Postgres/API
// container needed in the frontend job) while still exercising the real
// bundle, real routing, real DOM, and real user interaction - what a
// jsdom-based component test cannot.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  // "list" for readable terminal output locally and in CI logs; "html"
  // (never auto-opened) so a failed CI run has something to upload as an
  // artifact - trace/screenshots are otherwise unreachable after the fact.
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev -- --port 5173 --strictPort",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
