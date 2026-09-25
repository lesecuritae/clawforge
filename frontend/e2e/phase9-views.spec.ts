import { test, expect } from "@playwright/test";
import { login } from "./helpers";

// Roadmap phase 9 "Dashboard" exit gate: real browser coverage (not just
// vitest/jsdom component tests) for the four required views, navigated to
// through the real sidebar in a real Chromium engine.

const receipt = {
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

const securityEvent = {
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

const assessment = {
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

const decision = {
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

const incidentA = {
  id: "incident-a",
  status: "detected",
  severity: "critical",
  risk_score: 99,
  summary: "SSH brute force detected",
  correlation_key: "key-a",
  created_at: "2026-09-25T09:00:00Z",
  updated_at: "2026-09-25T10:05:00Z",
};

test("Firewall Status: navigates via the sidebar and renders receipts, drift, and kill-switch data", async ({ page }) => {
  await login(page, {
    "/firewall/receipts": [receipt],
    "/firewall/expired": [],
    "/firewall/kill-switch": [],
  });

  await page.getByRole("navigation").getByText("Firewall Status").click();

  await expect(page.getByRole("heading", { name: "Firewall Status" })).toBeVisible();
  await expect(page.getByText("203.0.113.7")).toBeVisible();
  await expect(page.getByText("verified")).toBeVisible();
});

test("Live Security: navigates via the sidebar and renders the attack/assessment/incident pipeline", async ({ page }) => {
  await login(page, {
    "/admin/security/events": [securityEvent],
    "/admin/security/assessments": [assessment],
    "/incidents": [incidentA],
  });

  await page.getByRole("navigation").getByText("Live Security").click();

  await expect(page.getByRole("heading", { name: "Live Security" })).toBeVisible();
  await expect(page.getByText("ssh_login_failure")).toBeVisible();
  await expect(page.getByText("ssh_bruteforce")).toBeVisible();
  await expect(page.getByRole("cell", { name: "SSH brute force detected" })).toBeVisible();
});

test("Agent Decisions: navigates via the sidebar and renders analysis/policy/recommendation/result", async ({ page }) => {
  await login(page, { "/admin/security/decisions": [decision] });

  await page.getByRole("navigation").getByText("Agent Decisions").click();

  await expect(page.getByRole("heading", { name: "Agent Decisions" })).toBeVisible();
  await expect(page.getByText("Behavioral signal corroborated by Spamhaus DROP")).toBeVisible();
  await expect(page.getByText(/ssh_bruteforce-default/)).toBeVisible();
});

test("Audit Chain: selects an incident and traces its full chain from event to firewall action", async ({ page }) => {
  await login(page, {
    "/incidents/incident-a/events": [{ event_id: "event-1", event_type: "ssh_login_failure", source: "linux-sensor", timestamp: "2026-09-25T09:59:00Z" }],
    "/admin/security/assessments?incident_id=incident-a": [assessment],
    "/admin/security/decisions?incident_id=incident-a": [decision],
    "/firewall/receipts": [{ ...receipt, target_fingerprint: "ip-pseudonym:abc123" }],
    "/incidents": [incidentA],
  });

  await page.getByRole("navigation").getByText("Audit Chain").click();

  await expect(page.getByRole("heading", { name: "Audit Chain" })).toBeVisible();
  // Auto-selects the (only) incident and shows all four stages.
  await expect(page.getByRole("heading", { name: "SSH brute force detected" })).toBeVisible();
  await expect(page.getByText("1. Events (1)")).toBeVisible();
  await expect(page.getByText("2. Assessments (1)")).toBeVisible();
  await expect(page.getByText("3. Policy decisions (1)")).toBeVisible();
  await expect(page.getByText("4. Firewall action & rollback (1)")).toBeVisible();
});
