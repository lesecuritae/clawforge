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
