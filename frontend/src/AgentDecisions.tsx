import { useApi, Card, Table, Empty, Loading, PageTitle, Badge, Meter, ErrorNotice, formatDate } from "./ui";
import type { SecurityPolicyDecision } from "./types";

/// Roadmap phase 9 "Dashboard": "Agentenentscheidungen mit Analyse,
/// Empfehlung, Policy und Resultat" - every shadow decision
/// clawforge-policy-engine has recorded, joined with the policy it was
/// evaluated against and the assessment ("Analyse") it came from. Nothing
/// here was ever executed: `is_shadow` is always true today, there is no
/// action layer wired to a decision yet (see docs/policy-engine.md) -
/// this view is purely explanatory.
export function AgentDecisions({ token }: { token: string }) {
  const decisions = useApi<SecurityPolicyDecision[]>("/admin/security/decisions?limit=100", token, []);

  const blocks = decisions.data.filter((item) => item.decision === "block").length;
  const corroborated = decisions.data.filter((item) => item.corroborated).length;
  const promoted = decisions.data.filter((item) => item.incident_id).length;

  return (
    <>
      <PageTitle
        eyebrow="POLICY ENGINE · SHADOW MODE"
        title="Agent Decisions"
        subtitle="Every shadow decision the policy engine has derived from an assessment - what it saw, which policy it evaluated, and what it would have recommended. Nothing here has ever been executed."
      />
      <ErrorNotice error={decisions.error} />
      <div className="metric-grid six-metrics">
        <Card title="Decisions" value={decisions.data.length} hint="Last 100" />
        <Card title="Block (shadow)" value={blocks} tone={blocks ? "alert" : "default"} />
        <Card title="Corroborated" value={corroborated} tone={corroborated ? "alert" : "default"} />
        <Card title="Linked to incident" value={promoted} />
        <Card title="Mode" value="Shadow only" hint="No action ever taken" />
      </div>

      <section className="card">
        <div className="section-title">
          <h3>Decisions</h3>
          <span>Analyse · Policy · Empfehlung · Resultat</span>
        </div>
        {decisions.loading ? (
          <Loading />
        ) : decisions.data.length ? (
          <Table>
            <thead>
              <tr>
                <th>Decision</th>
                <th>Policy</th>
                <th>Rule</th>
                <th>Resource</th>
                <th>Assessment</th>
                <th>Risk</th>
                <th>Evidence</th>
                <th>Corroborated</th>
                <th>Rationale</th>
                <th>Decided</th>
              </tr>
            </thead>
            <tbody>
              {decisions.data.map((item) => (
                <tr key={item.id}>
                  <td><Badge value={item.decision} /></td>
                  <td>{item.policy_name} v{item.policy_version} <Badge value={item.policy_class} /></td>
                  <td>{item.rule_id}</td>
                  <td className="mono">{item.resource}</td>
                  <td><Badge value={item.assessment_severity} /> {item.assessment_summary}</td>
                  <td><Meter value={item.risk_score} /></td>
                  <td>{item.evidence_sources}</td>
                  <td>{item.corroborated ? <Badge value="corroborated" /> : "—"}</td>
                  <td>{item.rationale}</td>
                  <td>{formatDate(item.decided_at)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty text="No policy decisions recorded yet." />
        )}
      </section>
    </>
  );
}
