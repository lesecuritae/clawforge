import type { Page } from "@playwright/test";

/// Intercepts every `/api/**` request the real browser issues and answers
/// it without a live backend. `overrides` maps a path prefix (matched
/// against the request's pathname+search, stripped of the leading `/api`)
/// to the JSON `data` an envelope should carry; anything unmatched gets an
/// empty-but-well-formed default so views this test doesn't care about
/// (e.g. Overview's dozen queries on first render) don't error out.
/// `/api/metrics` is handled separately - it is plain text, not an
/// envelope (see api.ts's `textApi`).
export async function mockApi(page: Page, overrides: Record<string, unknown> = {}): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api/, "") + url.search;

    if (path.startsWith("/metrics")) {
      await route.fulfill({ status: 200, contentType: "text/plain", body: "" });
      return;
    }

    if (route.request().method() === "POST" && path.startsWith("/admin/auth/login")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          status: "ok",
          data: { token: "e2e-test-token" },
          timestamp: new Date().toISOString(),
          errors: [],
        }),
      });
      return;
    }

    const match = Object.entries(overrides).find(([prefix]) => path.startsWith(prefix));
    const data = match ? match[1] : defaultFor(path);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ status: "ok", data, timestamp: new Date().toISOString(), errors: [] }),
    });
  });
}

// A handful of endpoints return a single object, not a list, when
// unmocked - listed here so the default-fallback shape doesn't make an
// object-typed view throw on `.someField` of an array.
const OBJECT_SHAPED_PREFIXES = [
  "/health",
  "/ready",
  "/operations/summary",
  "/operations/state",
  "/security/briefing",
  "/system/graph",
  "/events/status",
  "/visualization/network",
  "/visualization/incidents",
  "/visualization/trust",
];

function defaultFor(path: string): unknown[] | Record<string, never> {
  return OBJECT_SHAPED_PREFIXES.some((prefix) => path.startsWith(prefix)) ? {} : [];
}

/// Logs in through the real login form (not a sessionStorage shortcut) -
/// the login flow itself is part of what "real browser" coverage should
/// prove, not just the views behind it.
export async function login(page: Page, overrides: Record<string, unknown> = {}): Promise<void> {
  await mockApi(page, overrides);
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("test-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByText("CLAWFORGE", { exact: true }).waitFor();
}
