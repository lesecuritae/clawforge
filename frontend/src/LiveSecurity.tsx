import { useApi, Card, Table, Empty, Loading, PageTitle, Badge, Meter, ErrorNotice, formatDate } from "./ui";
import type { SecurityEvent, SecurityAssessment, Incident } from "./types";

/// Roadmap phase 9 "Dashboard": "Live Security mit Angriffen, Assessments
/// und Incidents" - the three-stage pipeline in one view: a raw sensor
/// event (an "Angriff" - one observation) can feed a security-engine
/// assessment (a rule firing over a window of events), which can in turn
/// get promoted to an incident. All three admin endpoints are read-only;
/// this view changes nothing.
export function LiveSecurity({ token }: { token: string }) {
  const events = useApi<SecurityEvent[]>("/admin/security/events?limit=100", token, []);
  const assessments = useApi<SecurityAssessment[]>("/admin/security/assessments?limit=100", token, []);
  const incidents = useApi<Incident[]>("/incidents?status=detected&page_size=25", token, []);
  const error = events.error || assessments.error || incidents.error;

  const corroborated = assessments.data.filter((item) => item.threat_intel_corroborated).length;
  const promoted = assessments.data.filter((item) => item.incident_id).length;
  const highSeverityEvents = events.data.filter((item) => ["high", "critical"].includes(item.severity)).length;

  return (
    <>
      <PageTitle
        eyebrow="SECURITY ENGINE"
        title="Live Security"
        subtitle="Raw sensor events, the assessments the security engine derived from them, and the incidents they were promoted to - the same pipeline clawforge-security-engine and clawforge-policy-engine themselves run."
      />
      <ErrorNotice error={error} />
      <div className="metric-grid six-metrics">
        <Card title="Recent attacks" value={events.data.length} hint="Last 100 sensor events" />
        <Card title="High/critical" value={highSeverityEvents} tone={highSeverityEvents ? "alert" : "good"} />
        <Card title="Assessments" value={assessments.data.length} hint="Last 100 rule firings" />
        <Card title="Threat-intel corroborated" value={corroborated} tone={corroborated ? "alert" : "default"} />
        <Card title="Promoted to incident" value={promoted} />
        <Card title="Open incidents" value={incidents.pagination?.total ?? incidents.data.length} tone={incidents.data.length ? "alert" : "good"} />
      </div>

      <section className="card">
        <div className="section-title">
          <h3>Assessments</h3>
          <span>Rule firings over a window of correlated events</span>
        </div>
        {assessments.loading ? (
          <Loading />
        ) : assessments.data.length ? (
          <Table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Resource</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Events</th>
                <th>Threat intel</th>
                <th>Incident</th>
                <th>Bucket start</th>
              </tr>
            </thead>
            <tbody>
              {assessments.data.map((item) => (
                <tr key={item.id}>
                  <td>{item.rule_id}</td>
                  <td className="mono">{item.resource}</td>
                  <td><Badge value={item.severity} /></td>
                  <td><Meter value={item.confidence} /></td>
                  <td>{item.event_count}</td>
                  <td>{item.threat_intel ? item.threat_intel.source + " (" + item.threat_intel.confidence + ")" : "—"}</td>
                  <td className="mono">{item.incident_id ?? "—"}</td>
                  <td>{formatDate(item.bucket_start)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty text="No assessments recorded yet." />
        )}
      </section>

      <section className="card">
        <div className="section-title">
          <h3>Open incidents</h3>
          <span>Promoted from assessments, correlated and tracked</span>
        </div>
        {incidents.loading ? (
          <Loading />
        ) : incidents.data.length ? (
          <Table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Status</th>
                <th>Summary</th>
                <th>Risk</th>
                <th>Events</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {incidents.data.map((item) => (
                <tr key={item.id}>
                  <td><Badge value={item.severity} /></td>
                  <td><Badge value={item.status} /></td>
                  <td>{item.summary}</td>
                  <td>{item.risk_score}</td>
                  <td>{item.event_count ?? "—"}</td>
                  <td>{formatDate(item.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty text="No open incidents." />
        )}
      </section>

      <section className="card">
        <div className="section-title">
          <h3>Raw sensor events</h3>
          <span>What each assessment's rule fired on</span>
        </div>
        {events.loading ? (
          <Loading />
        ) : events.data.length ? (
          <Table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Resource</th>
                <th>Severity</th>
                <th>Occurred</th>
              </tr>
            </thead>
            <tbody>
              {events.data.map((item) => (
                <tr key={item.id}>
                  <td>{item.event_type}</td>
                  <td className="mono">{item.resource}</td>
                  <td><Badge value={item.severity} /></td>
                  <td>{formatDate(item.occurred_at)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty text="No sensor events recorded yet." />
        )}
      </section>
    </>
  );
}
