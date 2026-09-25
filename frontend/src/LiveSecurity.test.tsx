import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { LiveSecurity } from "./LiveSecurity";
import * as apiModule from "./api";
import type { Incident, SecurityAssessment, SecurityEvent } from "./types";

// Roadmap phase 9 "Dashboard" exit gate: "TypeScript-Kompilierung allein
// reicht nicht als Frontend-Test" - these exercise the rendered DOM
// against a mocked API, not just that the component compiles.

const event: SecurityEvent = {
  id: "event-1",
  event_type: "ssh_login_failure",
  sensor_id: "sensor-1",
  occurred_at: "2026-09-25T10:00:00Z",
  received_at: "2026-09-25T10:00:01Z",
  severity: "high",
  resource: "ip-pseudonym:abc123",
  evidence: {},
  created_at: "2026-09-25T10:00:01Z",
};

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
  incident_id: "incident-1",
  threat_intel_corroborated: true,
  threat_intel: { source: "spamhaus_drop", confidence: 95, last_seen: "2026-09-24T00:00:00Z" },
};

const incident: Incident = {
  id: "incident-1",
  status: "detected",
  severity: "critical",
  risk_score: 99,
  summary: "SSH brute force detected",
  correlation_key: "key-1",
  event_count: 7,
  created_at: "2026-09-25T10:00:00Z",
  updated_at: "2026-09-25T10:00:05Z",
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

describe("LiveSecurity", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders sensor events, assessments, and incidents from the API", async () => {
    mockApiFor({
      "/admin/security/events": [event],
      "/admin/security/assessments": [assessment],
      "/incidents": [incident],
    });

    render(<LiveSecurity token="test-token" />);

    await waitFor(() => expect(screen.getByText("ssh_login_failure")).toBeInTheDocument());
    expect(screen.getByText("ssh_bruteforce")).toBeInTheDocument();
    expect(screen.getByText("spamhaus_drop (95)")).toBeInTheDocument();
    expect(screen.getByText("SSH brute force detected")).toBeInTheDocument();
    expect(screen.getAllByText("ip-pseudonym:abc123").length).toBeGreaterThan(0);
  });

  it("shows empty states when the API returns no data", async () => {
    mockApiFor({
      "/admin/security/events": [],
      "/admin/security/assessments": [],
      "/incidents": [],
    });

    render(<LiveSecurity token="test-token" />);

    await waitFor(() => expect(screen.getByText("No assessments recorded yet.")).toBeInTheDocument());
    expect(screen.getByText("No open incidents.")).toBeInTheDocument();
    expect(screen.getByText("No sensor events recorded yet.")).toBeInTheDocument();
  });
});
