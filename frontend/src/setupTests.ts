import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

// Vitest does not auto-register React Testing Library's cleanup the way
// Jest's testing-library preset does - without this, a previous test's
// rendered DOM stays mounted into the next test within the same file,
// causing spurious "found multiple elements" failures.
afterEach(() => {
  cleanup();
});
