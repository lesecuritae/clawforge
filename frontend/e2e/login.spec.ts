import { test, expect } from "@playwright/test";
import { login, mockApi } from "./helpers";

// Roadmap phase 9 "Dashboard" exit gate: component tests (vitest/jsdom)
// alone are not enough - this runs the real bundle in a real Chromium
// engine. The login form itself is the one piece of UI every other E2E
// test in this suite depends on, so it gets its own, explicit coverage.

test("signs in through the real login form and reaches the dashboard shell", async ({ page }) => {
  await login(page);
  await expect(page.getByText("INTELLIGENCE CONSOLE")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Clawforge Console" })).toHaveCount(0);
});

test("shows the API's own error message instead of signing in on bad credentials", async ({ page }) => {
  await mockApi(page);
  await page.route("**/api/admin/auth/login", async (route) => {
    await route.fulfill({
      status: 401,
      contentType: "application/json",
      body: JSON.stringify({ status: "error", data: null, timestamp: new Date().toISOString(), errors: ["invalid credentials"] }),
    });
  });

  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("wrong-password");
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page.getByText("invalid credentials")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign out" })).toHaveCount(0);
});
