import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FirewallStatus } from "./FirewallStatus";
import * as apiModule from "./api";
import type { FirewallExpiredTarget, FirewallKillSwitchRequest, FirewallReceipt } from "./types";

// Roadmap phase 9 "Dashboard" exit gate: "TypeScript-Kompilierung allein
// reicht nicht als Frontend-Test" - these exercise the rendered DOM
// against a mocked API, not just that the component compiles.

const receipt: FirewallReceipt = {
  id: "receipt-1",
  execution_id: "exec-1",
  adapter: "nftables",
  action_name: "nftables.block_indicator",
  receipt_kind: "apply",
  target_fingerprint: "203.0.113.7",
  is_dry_run: true,
  verification_result: "verified",
  ttl_seconds: 3600,
  expires_at: "2026-09-25T12:00:00Z",
  created_at: "2026-09-25T11:00:00Z",
  rendered_commands: [],
  rollback_plan: {},
};

const expiredTarget: FirewallExpiredTarget = {
  receipt_id: "receipt-2",
  adapter: "haproxy",
  target_fingerprint: "198.51.100.9",
  target_json: { kind: "threat_intel_indicator", cidr: "198.51.100.9/32", source: "test" },
};

const killSwitchRequest: FirewallKillSwitchRequest = {
  id: "kill-1",
  adapter: "nftables",
  target_fingerprint: "203.0.113.7",
  target_json: { kind: "threat_intel_indicator", cidr: "203.0.113.7/32", source: "test" },
  reason: "False positive",
  requested_by: "test-admin",
  created_at: "2026-09-25T10:00:00Z",
  processed_at: null,
};

function mockApiFor(routes: Record<string, unknown>) {
  return vi.spyOn(apiModule, "api").mockImplementation(async (path: string) => {
    for (const [prefix, data] of Object.entries(routes)) {
      if (path.startsWith(prefix)) {
        return { status: "ok", data, timestamp: new Date().toISOString(), errors: [] };
      }
    }
    throw new Error("unexpected path in test: " + path);
  });
}

describe("FirewallStatus", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders receipts, drift, and kill-switch data from the API", async () => {
    mockApiFor({
      "/firewall/receipts": [receipt],
      "/firewall/expired": [expiredTarget],
      "/firewall/kill-switch": [killSwitchRequest],
    });

    render(<FirewallStatus token="test-token" />);

    // Drift section - the redacted target fingerprint, never a raw IP
    // beyond what the backend already redacts.
    await waitFor(() => expect(screen.getByText("198.51.100.9")).toBeInTheDocument());

    // Kill-switch section.
    expect(screen.getByText("False positive")).toBeInTheDocument();
    expect(screen.getByText("test-admin")).toBeInTheDocument();
    expect(screen.getByText("pending")).toBeInTheDocument();

    // Receipts section.
    expect(screen.getByText("verified")).toBeInTheDocument();
    expect(screen.getByText("3600s")).toBeInTheDocument();
  });

  it("shows empty states when the API returns no data", async () => {
    mockApiFor({
      "/firewall/receipts": [],
      "/firewall/expired": [],
      "/firewall/kill-switch": [],
    });

    render(<FirewallStatus token="test-token" />);

    await waitFor(() =>
      expect(
        screen.getByText(
          "No expired, unrolled-back targets - every real block is within its TTL or already rolled back."
        )
      ).toBeInTheDocument()
    );
    expect(screen.getByText("No kill-switch requests recorded.")).toBeInTheDocument();
    expect(screen.getByText("No firewall action receipts recorded yet.")).toBeInTheDocument();
  });

  it("submits a kill-switch request with the form fields and reloads the list", async () => {
    const apiSpy = mockApiFor({
      "/firewall/receipts": [],
      "/firewall/expired": [],
      "/firewall/kill-switch": [],
    });
    apiSpy.mockImplementation(async (path: string, _token?: string, init?: RequestInit) => {
      if (path.startsWith("/firewall/kill-switch") && init?.method === "POST") {
        const body = JSON.parse(String(init.body));
        expect(body.adapter).toBe("nftables");
        expect(body.target_fingerprint).toBe("203.0.113.99");
        expect(body.target_json).toEqual({ kind: "threat_intel_indicator", cidr: "203.0.113.99/32", source: "manual" });
        expect(body.reason).toBe("Manual test rollback");
        return { status: "ok", data: { id: "new-request", status: "pending" }, timestamp: new Date().toISOString(), errors: [] };
      }
      return { status: "ok", data: [], timestamp: new Date().toISOString(), errors: [] };
    });

    const user = userEvent.setup();
    render(<FirewallStatus token="test-token" />);

    await waitFor(() => expect(screen.getByText("No kill-switch requests recorded.")).toBeInTheDocument());

    await user.type(screen.getByLabelText("Target fingerprint"), "203.0.113.99");
    const targetJsonInput = screen.getByLabelText("Target JSON");
    await user.clear(targetJsonInput);
    // userEvent's `{` is a special-key escape character (doubled to type a
    // literal brace); `}` is not special and needs no escaping.
    await user.type(
      targetJsonInput,
      '{{"kind":"threat_intel_indicator","cidr":"203.0.113.99/32","source":"manual"}'
    );
    await user.type(screen.getByLabelText("Reason"), "Manual test rollback");
    await user.click(screen.getByRole("button", { name: "Request rollback" }));

    await waitFor(() =>
      expect(apiSpy).toHaveBeenCalledWith(
        "/firewall/kill-switch",
        "test-token",
        expect.objectContaining({ method: "POST" })
      )
    );
  });

  it("shows a validation error for malformed target JSON instead of submitting", async () => {
    const apiSpy = mockApiFor({
      "/firewall/receipts": [],
      "/firewall/expired": [],
      "/firewall/kill-switch": [],
    });

    const user = userEvent.setup();
    render(<FirewallStatus token="test-token" />);
    await waitFor(() => expect(screen.getByText("No kill-switch requests recorded.")).toBeInTheDocument());

    await user.type(screen.getByLabelText("Target fingerprint"), "203.0.113.99");
    const targetJsonInput = screen.getByLabelText("Target JSON");
    await user.clear(targetJsonInput);
    await user.type(targetJsonInput, "not valid json");
    await user.click(screen.getByRole("button", { name: "Request rollback" }));

    expect(await screen.findByText("target_json must be valid JSON")).toBeInTheDocument();
    expect(apiSpy).not.toHaveBeenCalledWith(
      "/firewall/kill-switch",
      expect.anything(),
      expect.objectContaining({ method: "POST" })
    );
  });
});
