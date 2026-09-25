import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuditChain } from "./AuditChain";
import * as apiModule from "./api";
import type { FirewallReceipt, Incident, SecurityAssessment, SecurityPolicyDecision } from "./types";

// Roadmap phase 9 "Dashboard" exit gate: "TypeScript-Kompilierung allein
// reicht nicht als Frontend-Test" - these exercise the rendered DOM
// against a mocked API, not just that the component compiles.

const incidentA: Incident = {
  id: "incident-a",
  status: "detected",
  severity: "critical",
  risk_score: 99,
  summary: "SSH brute force detected",
  correlation_key: "key-a",
  created_at: "2026-09-25T09:00:00Z",
  updated_at: "2026-09-25T10:05:00Z",
};
const incidentB: Incident = {
  id: "incident-b",
  status: "resolved",
  severity: "medium",
  risk_score: 40,
  summary: "HTTP anomaly burst",
  correlation_key: "key-b",
  created_at: "2026-09-24T09:00:00Z",
  updated_at: "2026-09-24T09:30:00Z",
};

const correlatedEvent = { event_id: "event-1", event_type: "ssh_login_failure", source: "linux-sensor", timestamp: "2026-09-25T09:59:00Z" };

const assessment: SecurityAssessment = {
  id: "assessment-1",
  rule_id: "ssh_bruteforce",
  rule_version: "1",
  resource: "ip-pseudonym:abc123",
  severity: "critical",
  confidence: 90,
  summary: "5+ failed logins in 300s",
  event_count: 7,
  bucket_start: "2026-09-25T10:00:00Z",
  incident_id: "incident-a",
  threat_intel_corroborated: true,
  threat_intel: { source: "spamhaus_drop", confidence: 95, last_seen: "2026-09-24T00:00:00Z" },
};

const decision: SecurityPolicyDecision = {
  id: "decision-1",
  decision: "block",
  risk_score: 88,
  evidence_sources: 2,
  corroborated: true,
  rationale: "Behavioral signal corroborated by Spamhaus DROP",
  is_shadow: true,
  decided_at: "2026-09-25T10:00:10Z",
  incident_id: "incident-a",
  policy_name: "ssh_bruteforce-default",
  policy_version: 1,
  policy_class: "observe",
  rule_id: "ssh_bruteforce",
  resource: "ip-pseudonym:abc123",
  assessment_severity: "critical",
  assessment_summary: "5+ failed logins in 300s",
  assessment_confidence: 90,
};

const receiptMatching: FirewallReceipt = {
  id: "receipt-1",
  adapter: "nftables",
  action_name: "nftables.block_incident_source",
  receipt_kind: "apply",
  target_fingerprint: "ip-pseudonym:abc123",
  is_dry_run: true,
  ttl_seconds: 3600,
  expires_at: "2026-09-25T11:00:00Z",
  created_at: "2026-09-25T10:00:20Z",
  rendered_commands: [],
  rollback_plan: {},
};
const receiptUnrelated: FirewallReceipt = {
  id: "receipt-2",
  adapter: "nftables",
  action_name: "nftables.block_indicator",
  receipt_kind: "apply",
  target_fingerprint: "203.0.113.0/24",
  is_dry_run: true,
  ttl_seconds: 3600,
  expires_at: "2026-09-25T11:00:00Z",
  created_at: "2026-09-25T10:00:20Z",
  rendered_commands: [],
  rollback_plan: {},
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

describe("AuditChain", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("auto-selects the most recently updated incident and shows its full chain", async () => {
    mockApiFor({
      "/incidents/incident-a/events": [correlatedEvent],
      "/incidents/incident-b/events": [],
      "/admin/security/assessments?incident_id=incident-a": [assessment],
      "/admin/security/assessments?incident_id=incident-b": [],
      "/admin/security/decisions?incident_id=incident-a": [decision],
      "/admin/security/decisions?incident_id=incident-b": [],
      "/firewall/receipts": [receiptMatching, receiptUnrelated],
      "/incidents": [incidentB, incidentA],
    });

    render(<AuditChain token="test-token" />);

    // Most recently updated (incident-a) is auto-selected, not incident-b.
    await waitFor(() => expect(screen.getByRole("heading", { name: "SSH brute force detected" })).toBeInTheDocument());
    // Each stage loads via its own independent request; wait for the
    // slowest (the receipts fetch, asserted last) rather than assuming
    // they all resolve within the same tick as the heading above.
    await waitFor(() => expect(screen.getByText("ssh_login_failure")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("ssh_bruteforce")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("Behavioral signal corroborated by Spamhaus DROP")).toBeInTheDocument());
    // The matching receipt (same pseudonym) is shown; the unrelated one is not.
    await waitFor(() => expect(screen.getAllByText((content) => content.includes("ip-pseudonym:abc123")).length).toBe(2));
    expect(screen.queryByText((content) => content.includes("203.0.113.0/24"))).not.toBeInTheDocument();
  });

  it("switches the chain when a different incident is selected", async () => {
    mockApiFor({
      "/incidents/incident-a/events": [correlatedEvent],
      "/incidents/incident-b/events": [],
      "/admin/security/assessments?incident_id=incident-a": [assessment],
      "/admin/security/assessments?incident_id=incident-b": [],
      "/admin/security/decisions?incident_id=incident-a": [decision],
      "/admin/security/decisions?incident_id=incident-b": [],
      "/firewall/receipts": [],
      "/incidents": [incidentB, incidentA],
    });

    const user = userEvent.setup();
    render(<AuditChain token="test-token" />);
    await waitFor(() => expect(screen.getByRole("heading", { name: "SSH brute force detected" })).toBeInTheDocument());

    await user.click(screen.getByText("HTTP anomaly burst"));

    await waitFor(() => expect(screen.getByText("No correlated events.")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("No assessments link to this incident.")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("No policy decisions link to this incident.")).toBeInTheDocument());
  });
});
