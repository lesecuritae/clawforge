import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ExecutionConfirmations } from "./ExecutionConfirmations";
import * as apiModule from "./api";

const HASH = "a".repeat(64);
const waitingRow = { id: "exec-1", action_name: "nftables.block_incident_source", status: "waiting_approval", risk_level: "critical", requested_by: "policy-bridge", created_at: "2026-10-27T10:00:00Z" };

function detail(overrides: Record<string, unknown> = {}, confirmation: Record<string, unknown> = {}) {
  return {
    id: "exec-1", action_name: waitingRow.action_name, status: "waiting_approval", risk_level: "critical", requested_by: "policy-bridge",
    target: { kind: "incident_source", pseudonym: "ip-pseudonym:x", ttl_seconds: 900 }, approval_context_hash: HASH, required_approvals: 1,
    approval_expires_at: "2099-01-01T00:00:00Z", approval_profile: { mode: "single_operator", policy_required_approvals: 2 }, approvals: [],
    confirmation: { profile_mode: "single_operator", you_are_designated_operator: true, available: true, signed_in_as: "owner", ...confirmation },
    ...overrides,
  };
}

function mockApi(detailBody: unknown, post?: (path: string, init?: RequestInit) => Promise<unknown>) {
  return vi.spyOn(apiModule, "api").mockImplementation(async (path: string, _token?: string, init?: RequestInit) => {
    if (init?.method === "POST") return (post ? await post(path, init) : { data: {} }) as never;
    if (path.startsWith("/executions?")) return { status: "ok", data: [waitingRow], errors: [], timestamp: "t" } as never;
    if (path.startsWith("/executions/exec-1")) return { status: "ok", data: detailBody, errors: [], timestamp: "t" } as never;
    return { status: "ok", data: null, errors: [], timestamp: "t" } as never;
  });
}

async function openReview() {
  render(<ExecutionConfirmations token="session-token" />);
  await userEvent.click(await screen.findByRole("button", { name: "Review" }));
  await screen.findByRole("region", { name: "Request review" });
}

describe("ExecutionConfirmations (single-operator confirmation)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows the trusted profile, the exact context and offers the confirmation only after an explicit review", async () => {
    const spy = mockApi(detail());
    await openReview();
    expect(screen.getByText(/single operator \(deliberate\)/)).toBeInTheDocument();
    expect(screen.getByText(/policy normally requires 2 approvals/)).toBeInTheDocument();
    expect(screen.getByText(HASH)).toBeInTheDocument();
    const button = screen.getByRole("button", { name: "Confirm request" });
    expect(button).toBeDisabled();
    expect(spy.mock.calls.filter(([, , init]) => init?.method === "POST")).toHaveLength(0);
  });

  it("posts the displayed hash to the profile-aware endpoint exactly once, even on a double submit", async () => {
    let release: (value: unknown) => void = () => {};
    const gate = new Promise((resolve) => { release = resolve; });
    const spy = mockApi(detail(), () => gate);
    await openReview();
    await userEvent.click(screen.getByRole("checkbox"));
    const button = screen.getByRole("button", { name: "Confirm request" });
    await userEvent.click(button);
    await userEvent.click(button);
    release({ data: { status: "approved" } });
    await screen.findByText(/Confirmed/);
    const posts = spy.mock.calls.filter(([, , init]) => init?.method === "POST");
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe("/admin/executions/exec-1/confirm-single-operator");
    expect(JSON.parse(String(posts[0][2]?.body))).toEqual({ context_hash: HASH });
  });

  it("shows a refusal as a refusal and never falls back to the ordinary approval route", async () => {
    const spy = mockApi(detail(), async () => { throw new Error("single-operator confirmation is not available"); });
    await openReview();
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: "Confirm request" }));
    expect(await screen.findByText(/Not confirmed: single-operator confirmation is not available/)).toBeInTheDocument();
    expect(spy.mock.calls.some(([path]) => String(path).endsWith("/approve"))).toBe(false);
    expect(spy.mock.calls.filter(([, , init]) => init?.method === "POST")).toHaveLength(1);
  });

  it("offers nothing to a signed-in user who is not the designated operator", async () => {
    mockApi(detail({}, { you_are_designated_operator: false, available: false, signed_in_as: "someone-else" }));
    await openReview();
    expect(screen.queryByRole("button", { name: "Confirm request" })).not.toBeInTheDocument();
    expect(screen.getByText(/not the designated operator/)).toBeInTheDocument();
  });

  it("offers nothing for an expired or otherwise unavailable request", async () => {
    mockApi(detail({ approval_expires_at: "2000-01-01T00:00:00Z" }, { available: false }));
    await openReview();
    expect(screen.queryByRole("button", { name: "Confirm request" })).not.toBeInTheDocument();
    expect(screen.getByText(/Confirmation is not available/)).toBeInTheDocument();
  });

  it("keeps the multi-person default: no confirmation button, the distinct-approval count is shown", async () => {
    mockApi(detail({ approval_profile: null, required_approvals: 2 }, { profile_mode: "multi_person", you_are_designated_operator: false, available: false }));
    await openReview();
    expect(screen.getByText(/multi-person \(default\)/)).toBeInTheDocument();
    expect(screen.getByText(/requires 2 distinct approvals/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Confirm request" })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/does not apply to this request/)).toBeInTheDocument());
  });

  it("does not offer the previous request while a different request is still loading", async () => {
    let resolveSecond!: (value: unknown) => void;
    const second = new Promise((resolve) => { resolveSecond = resolve; });
    vi.spyOn(apiModule, "api").mockImplementation(async (path: string) => {
      if (path.startsWith("/executions?")) return { data: [waitingRow, { ...waitingRow, id: "exec-2" }] } as never;
      if (path === "/executions/exec-1") return { data: detail() } as never;
      if (path === "/executions/exec-2") return await second as never;
      return { data: null } as never;
    });
    render(<ExecutionConfirmations token="session-token" />);
    const buttons = await screen.findAllByRole("button", { name: "Review" });
    await userEvent.click(buttons[0]);
    await screen.findByRole("region", { name: "Request review" });
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(buttons[1]);
    expect(screen.queryByRole("region", { name: "Request review" })).not.toBeInTheDocument();
    resolveSecond({ data: detail({ id: "exec-2", approval_context_hash: "b".repeat(64) }) });
    await screen.findByText("b".repeat(64));
    expect(screen.getByRole("checkbox")).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Confirm request" })).toBeDisabled();
  });

  it("does not let a pending confirmation be attributed to another selected request", async () => {
    let release!: (value: unknown) => void;
    const pending = new Promise((resolve) => { release = resolve; });
    vi.spyOn(apiModule, "api").mockImplementation(async (path: string, _token?: string, init?: RequestInit) => {
      if (init?.method === "POST") return await pending as never;
      if (path.startsWith("/executions?")) return { data: [waitingRow, { ...waitingRow, id: "exec-2" }] } as never;
      if (path === "/executions/exec-1") return { data: detail() } as never;
      if (path === "/executions/exec-2") return { data: detail({ id: "exec-2" }) } as never;
      return { data: null } as never;
    });
    render(<ExecutionConfirmations token="session-token" />);
    const buttons = await screen.findAllByRole("button", { name: "Review" });
    await userEvent.click(buttons[0]);
    await screen.findByRole("region", { name: "Request review" });
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: "Confirm request" }));
    try {
      expect(buttons[1]).toBeDisabled();
      await userEvent.click(buttons[1]);
      expect(screen.queryByText("b".repeat(64))).not.toBeInTheDocument();
    } finally {
      release({ data: { status: "approved" } });
    }
    await screen.findByText(/Confirmed/);
  });
});
