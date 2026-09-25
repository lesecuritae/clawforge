import { useState } from "react";
import { useApi, Empty, Loading, PageTitle, Badge, ErrorNotice, formatDate } from "./ui";
import type { Incident, SecurityAssessment, SecurityPolicyDecision, FirewallReceipt } from "./types";

/// Roadmap phase 9 "Dashboard" exit gate: "durchgaengige Auditkette vom
/// Event bis zum Rollback". Picking an incident assembles its full chain
/// from four independently-read, already-existing sources rather than a
/// new combined table - each stage is exactly what the corresponding
/// service itself persisted:
///   1. Event    - the correlated events an incident groups
///      (GET /incidents/{id}/events, unchanged since phase 4).
///   2. Assessment - clawforge-security-engine's rule firing(s) that fed
///      this incident (GET /admin/security/assessments?incident_id=...).
///   3. Decision - clawforge-policy-engine's shadow decision(s) derived
///      from those assessments (GET /admin/security/decisions?incident_id=...).
///   4. Rollback - any firewall action receipt whose target_fingerprint
///      matches one of this incident's assessment resources (matched by
///      value, not a foreign key - see the "target_fingerprint" comment
///      below for why that is the correct, and only, link today).
function AuditChainDetail({ token, incident }: { token: string; incident: Incident }) {
  const events = useApi<Array<Record<string, unknown>>>("/incidents/" + incident.id + "/events", token, []);
  const assessments = useApi<SecurityAssessment[]>(
    "/admin/security/assessments?incident_id=" + incident.id + "&limit=500",
    token,
    []
  );
  const decisions = useApi<SecurityPolicyDecision[]>(
    "/admin/security/decisions?incident_id=" + incident.id + "&limit=500",
    token,
    []
  );
  // firewall_action_receipts has no incident_id column - a firewall
  // action targets a resolved IP/CIDR, never an incident row directly.
  // target_fingerprint (the pseudonym persisted for a resolved incident
  // source, see clawforge-firewall-agent's redacted_element_reference)
  // is the same pseudonym an assessment's own `resource` carries, so
  // matching by that value is the real link this pipeline actually has.
  const receipts = useApi<FirewallReceipt[]>("/firewall/receipts?limit=200", token, []);
  const resources = new Set(assessments.data.map((item) => item.resource));
  const matchedReceipts = receipts.data.filter((item) => item.target_fingerprint && resources.has(item.target_fingerprint));
  const error = events.error || assessments.error || decisions.error || receipts.error;

  return (
    <section className="card detail-panel">
      <div className="section-title">
        <div>
          <p className="eyebrow">{incident.id}</p>
          <h3>{incident.summary}</h3>
        </div>
        <Badge value={incident.status} />
      </div>
      <ErrorNotice error={error} />

      <h4>1. Events ({events.loading ? "…" : events.data.length})</h4>
      {events.loading ? (
        <Loading />
      ) : events.data.length ? (
        <div className="visual-timeline">
          {events.data.map((event, index) => (
            <div className="visual-timeline-item" key={String(event.event_id ?? index)}>
              <span className="timeline-dot" />
              <div>
                <b>{String(event.event_type ?? event.action ?? "event")}</b>
                <small>{String(event.source ?? "API")} · {formatDate(String(event.timestamp ?? event.recorded_at ?? ""))}</small>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <Empty text="No correlated events." />
      )}

      <h4>2. Assessments ({assessments.loading ? "…" : assessments.data.length})</h4>
      {assessments.loading ? (
        <Loading />
      ) : assessments.data.length ? (
        <div className="visual-timeline">
          {assessments.data.map((item) => (
            <div className="visual-timeline-item" key={item.id}>
              <span className="timeline-dot" />
              <div>
                <b>{item.rule_id}</b> <Badge value={item.severity} />
                <small className="mono">{item.resource} · {formatDate(item.bucket_start)}</small>
                <p>{item.summary}</p>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <Empty text="No assessments link to this incident." />
      )}

      <h4>3. Policy decisions ({decisions.loading ? "…" : decisions.data.length})</h4>
      {decisions.loading ? (
        <Loading />
      ) : decisions.data.length ? (
        <div className="visual-timeline">
          {decisions.data.map((item) => (
            <div className="visual-timeline-item" key={item.id}>
              <span className="timeline-dot" />
              <div>
                <b><Badge value={item.decision} /></b> via {item.policy_name} v{item.policy_version}
                <small>{formatDate(item.decided_at)} · {item.is_shadow ? "shadow (never executed)" : "executed"}</small>
                <p>{item.rationale}</p>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <Empty text="No policy decisions link to this incident." />
      )}

      <h4>4. Firewall action &amp; rollback ({receipts.loading ? "…" : matchedReceipts.length})</h4>
      {receipts.loading ? (
        <Loading />
      ) : matchedReceipts.length ? (
        <div className="visual-timeline">
          {matchedReceipts.map((item) => (
            <div className="visual-timeline-item" key={item.id}>
              <span className="timeline-dot" />
              <div>
                <b><Badge value={item.adapter} /> <Badge value={item.receipt_kind} /></b>
                <small className="mono">{item.target_fingerprint} · {formatDate(item.created_at)}</small>
                <p>{item.is_dry_run ? "Dry-run only" : "Real action"} · expires {formatDate(item.expires_at)}</p>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <Empty text="No firewall action was ever taken for this incident's resource (expected while CLAWFORGE_EXECUTOR_DRY_RUN stays enabled, or if no firewall response was configured)." />
      )}
    </section>
  );
}

export function AuditChain({ token }: { token: string }) {
  const incidents = useApi<Incident[]>("/incidents?page_size=50", token, []);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const sorted = [...incidents.data].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  const selected = sorted.find((item) => item.id === selectedId) ?? sorted[0];

  return (
    <>
      <PageTitle
        eyebrow="TRACEABILITY"
        title="Audit Chain"
        subtitle="Pick an incident to see its full chain: the correlated events it groups, the security-engine assessment(s) it was derived from, the policy decision(s) evaluated against them, and any firewall action or rollback taken on its resource."
      />
      <ErrorNotice error={incidents.error} />
      <div className="incident-layout">
        <section className="card incident-list">
          <div className="section-title">
            <h3>Incidents</h3>
            <span>{incidents.pagination?.total ?? incidents.data.length} total</span>
          </div>
          {incidents.loading ? (
            <Loading />
          ) : sorted.length ? (
            sorted.map((item) => (
              <button
                className={"incident-row " + (selected?.id === item.id ? "selected" : "")}
                key={item.id}
                onClick={() => setSelectedId(item.id)}
              >
                <Badge value={item.severity} />
                <span>
                  <b>{item.summary}</b>
                  <small>{item.status} · {formatDate(item.updated_at)}</small>
                </span>
                <strong>{item.risk_score}</strong>
              </button>
            ))
          ) : (
            <Empty />
          )}
        </section>
        {selected ? <AuditChainDetail token={token} incident={selected} /> : <section className="card detail-panel"><Empty text="Select an incident to trace its audit chain." /></section>}
      </div>
    </>
  );
}
