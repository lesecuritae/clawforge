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
    // --host 127.0.0.1 explicitly, not Vite's default `localhost`: on
    // some CI runners `localhost` resolves to the IPv6 loopback first,
    // Vite ends up listening only there, and Playwright's readiness poll
    // against the literal IPv4 127.0.0.1 above never connects - observed
    // as a full 120s webServer timeout in CI while the exact same command
    // starts in under a second locally.
    command: "npm run dev -- --port 5173 --strictPort --host 127.0.0.1",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    // Surface the dev server's own stdout/stderr in CI logs - otherwise
    // a webServer startup failure shows only Playwright's generic timeout
    // with no clue why the server itself never came up.
    stdout: "pipe",
    stderr: "pipe",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
