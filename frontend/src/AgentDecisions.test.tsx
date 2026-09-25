import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { AgentDecisions } from "./AgentDecisions";
import * as apiModule from "./api";
import type { SecurityPolicyDecision } from "./types";

// Roadmap phase 9 "Dashboard" exit gate: "TypeScript-Kompilierung allein
// reicht nicht als Frontend-Test" - these exercise the rendered DOM
// against a mocked API, not just that the component compiles.

const decision: SecurityPolicyDecision = {
  id: "decision-1",
  decision: "block",
  risk_score: 88,
  evidence_sources: 2,
  corroborated: true,
  rationale: "Behavioral signal corroborated by Spamhaus DROP",
  is_shadow: true,
  decided_at: "2026-09-25T10:00:10Z",
  incident_id: "incident-1",
  policy_name: "ssh_bruteforce-default",
  policy_version: 1,
  policy_class: "observe",
  rule_id: "ssh_bruteforce",
  resource: "ip-pseudonym:abc123",
  assessment_severity: "critical",
  assessment_summary: "5+ failed logins in 300s",
  assessment_confidence: 90,
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

describe("AgentDecisions", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders decisions with policy, analysis, and result fields from the API", async () => {
    mockApiFor({ "/admin/security/decisions": [decision] });

    render(<AgentDecisions token="test-token" />);

    await waitFor(() => expect(screen.getByText("ssh_bruteforce")).toBeInTheDocument());
    expect(screen.getByText(/ssh_bruteforce-default/)).toBeInTheDocument();
    expect(screen.getByText(/5\+ failed logins in 300s/)).toBeInTheDocument();
    expect(screen.getByText("Behavioral signal corroborated by Spamhaus DROP")).toBeInTheDocument();
    expect(screen.getByText("ip-pseudonym:abc123")).toBeInTheDocument();
  });

  it("shows an empty state when the API returns no decisions", async () => {
    mockApiFor({ "/admin/security/decisions": [] });

    render(<AgentDecisions token="test-token" />);

    await waitFor(() => expect(screen.getByText("No policy decisions recorded yet.")).toBeInTheDocument());
  });
});
