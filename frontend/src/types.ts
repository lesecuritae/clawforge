export type Provider = { id: string; name: string; source: string; enabled: boolean; status?: string; last_success_at?: string; last_failure_at?: string; last_data_at?: string; last_error?: string; quality_score?: number; data_age_seconds?: number; indicator_count?: number; sync_duration_ms?: number };
export type Incident = { id: string; title?: string; status: string; severity: string; source?: string; risk_score: number; summary: string; correlation_key: string; event_count?: number; created_at: string; updated_at: string };
export type Indicator = { id: number; value: string; indicator_type: string; source: string; confidence: number; risk_score?: number; trust_score?: number; last_seen: string; expires_at: string; status?: string };
export type NetworkRecord = Record<string, unknown> & { timestamp?: string; source?: string; status?: string; confidence?: number };
export type AuditEvent = { id: number; actor: string; action: string; resource: string; severity: string; reason: string; recorded_at: string };
export type OperationsSummary = { overall_status: string; risk_level: string; active_incidents: number; critical_events: number; provider_health: { total: number; enabled: number; healthy: number; failed: number; average_quality_score: number; items: Provider[] }; attention_points: Array<Record<string, unknown>>; recommended_checks: Array<Record<string, unknown>>; correlation_confidence?: Record<string, unknown>; trust?: Record<string, unknown>; alerts?: Record<string, number>; system_status?: string; system?: Record<string, unknown>; trend?: Record<string, Record<string, unknown>>; change_direction?: string; change_reason?: string; confidence?: number };

// Roadmap phase 6/7 - the real firewall action layer's own admin surface
// (clawforge-executor's dispatch, clawforge-api's read-only receipt/
// expired/kill-switch endpoints - see docs/firewall-agent.md). Every
// field here is already safe to show: target_fingerprint/rendered_commands/
// rollback_plan never carry a raw IP for a resolved incident source, only
// the redacted element reference - see clawforge-firewall-agent's
// redacted_element_reference.
export type FirewallReceipt = { id: string; execution_id?: string | null; adapter: string; action_name: string; receipt_kind: "apply" | "rollback"; target_fingerprint?: string | null; is_dry_run: boolean; verification_result?: string | null; ttl_seconds: number; expires_at: string; created_at: string; rendered_commands: unknown; rollback_plan: unknown; observed_state?: unknown };
export type FirewallExpiredTarget = { receipt_id: string; adapter: string; target_fingerprint: string; target_json: unknown };
export type FirewallKillSwitchRequest = { id: string; adapter: string; target_fingerprint: string; target_json: unknown; reason?: string | null; requested_by: string; created_at: string; processed_at?: string | null };

// Roadmap phase 9 "Dashboard" - "Live Security mit Angriffen, Assessments
// und Incidents". `resource` on both types below is already the
// pseudonymized HMAC reference by the time it is persisted
// (clawforge-storage's `record_security_event`/`persist_security_assessment`
// via the shared IP-HMAC machinery) - never a raw IP, see
// docs/security-events.md and docs/security-engine.md.
export type SecurityEvent = { id: string; event_type: string; sensor_id: string; occurred_at: string; received_at: string; severity: string; resource: string; evidence: Record<string, unknown>; created_at: string };
export type IpReputationHit = { source: string; confidence: number; last_seen: string };
export type SecurityAssessment = { id: string; rule_id: string; rule_version: string; resource: string; severity: string; confidence: number; summary: string; event_count: number; bucket_start: string; incident_id?: string | null; threat_intel_corroborated: boolean; threat_intel?: IpReputationHit | null };

// Roadmap phase 9 "Dashboard" - "Agentenentscheidungen mit Analyse,
// Empfehlung, Policy und Resultat". Analyse = resource/assessment_*
// (from security_assessments), Empfehlung = decision, Policy =
// policy_name/policy_version/policy_class/rule_id, Resultat =
// risk_score/evidence_sources/corroborated/rationale. is_shadow is
// always true today - clawforge-policy-engine never executes anything,
// see docs/policy-engine.md.
export type SecurityPolicyDecision = { id: string; decision: "observe" | "challenge" | "rate_limit" | "block"; risk_score: number; evidence_sources: number; corroborated: boolean; rationale: string; is_shadow: boolean; decided_at: string; incident_id?: string | null; policy_name: string; policy_version: number; policy_class: "observe" | "approval" | "automatic"; rule_id: string; resource: string; assessment_severity: string; assessment_summary: string; assessment_confidence: number };
