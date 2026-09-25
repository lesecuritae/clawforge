import React, { useState } from "react";
import { api, type Envelope } from "./api";
import { useApi, Card, Table, Empty, Loading, PageTitle, Badge, ErrorNotice, formatDate } from "./ui";
import type { FirewallReceipt, FirewallExpiredTarget, FirewallKillSwitchRequest } from "./types";

/// Roadmap phase 9 "Dashboard": "Firewall Status mit Desired/Actual State,
/// Sperren, TTL und Drift". Assembles the three read-only admin endpoints
/// phase 6/7 built (`/firewall/receipts`, `/firewall/expired`,
/// `/firewall/kill-switch`) plus the one write action that already exists
/// on the backend (`POST /firewall/kill-switch`) - a per-target rollback,
/// distinct from the all-or-nothing break-glass script, which has no API
/// surface at all on purpose (it is meant to be run directly on a host,
/// independent of this API/database).
export function FirewallStatus({ token }: { token: string }) {
  const receipts = useApi<FirewallReceipt[]>("/firewall/receipts?limit=100", token, []);
  const expired = useApi<FirewallExpiredTarget[]>("/firewall/expired", token, []);
  const killSwitch = useApi<FirewallKillSwitchRequest[]>("/firewall/kill-switch?limit=100", token, []);
  const error = receipts.error || expired.error || killSwitch.error;

  const [adapter, setAdapter] = useState("nftables");
  const [targetFingerprint, setTargetFingerprint] = useState("");
  const [targetJson, setTargetJson] = useState('{"kind":"threat_intel_indicator","cidr":"","source":""}');
  const [reason, setReason] = useState("");
  const [submitError, setSubmitError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submitKillSwitch(event: React.FormEvent) {
    event.preventDefault();
    setSubmitError("");
    let parsedTarget: unknown;
    try {
      parsedTarget = JSON.parse(targetJson);
    } catch {
      setSubmitError("target_json must be valid JSON");
      return;
    }
    setSubmitting(true);
    try {
      await api<Envelope<{ id: string; status: string }>>("/firewall/kill-switch", token, {
        method: "POST",
        body: JSON.stringify({
          adapter,
          target_fingerprint: targetFingerprint,
          target_json: parsedTarget,
          reason: reason || undefined,
        }),
      });
      setTargetFingerprint("");
      setReason("");
      killSwitch.reload();
    } catch (reason) {
      setSubmitError(reason instanceof Error ? reason.message : "Kill-switch request failed");
    } finally {
      setSubmitting(false);
    }
  }

  const applyReceipts = receipts.data.filter((item) => item.receipt_kind === "apply");
  const realApplies = applyReceipts.filter((item) => !item.is_dry_run).length;
  const pendingKillSwitch = killSwitch.data.filter((item) => !item.processed_at).length;

  return (
    <>
      <PageTitle
        eyebrow="FIREWALL ACTION LAYER"
        title="Firewall Status"
        subtitle="Desired/actual state, active blocks, TTL, and drift - assembled from the same data the TTL sweep and kill-switch themselves use, so this view can never disagree with what the executor actually does."
      />
      <ErrorNotice error={error} />
      <div className="metric-grid six-metrics">
        <Card title="Recent applies" value={applyReceipts.length} hint="Last 100 receipts" />
        <Card title="Real (non-dry-run)" value={realApplies} tone={realApplies ? "alert" : "good"} />
        <Card title="Drifted targets" value={expired.data.length} tone={expired.data.length ? "alert" : "good"} hint="Past TTL, not yet rolled back" />
        <Card title="Pending kill-switch" value={pendingKillSwitch} tone={pendingKillSwitch ? "alert" : "good"} />
      </div>

      <section className="card">
        <div className="section-title">
          <h3>Drift</h3>
          <span>Same query the TTL sweep itself runs</span>
        </div>
        {expired.loading ? (
          <Loading />
        ) : expired.data.length ? (
          <Table>
            <thead>
              <tr>
                <th>Receipt</th>
                <th>Adapter</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {expired.data.map((item) => (
                <tr key={item.receipt_id}>
                  <td className="mono">{item.receipt_id}</td>
                  <td>
                    <Badge value={item.adapter} />
                  </td>
                  <td className="mono">{item.target_fingerprint}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty text="No expired, unrolled-back targets - every real block is within its TTL or already rolled back." />
        )}
      </section>

      <section className="card">
        <div className="section-title">
          <h3>Kill-switch</h3>
          <span>{killSwitch.data.length} requests</span>
        </div>
        <form className="toolbar kill-switch-form" onSubmit={submitKillSwitch}>
          <label>
            Adapter
            <select value={adapter} onChange={(event) => setAdapter(event.target.value)}>
              <option value="nftables">nftables</option>
              <option value="haproxy">haproxy</option>
              <option value="haproxy_ratelimit">haproxy_ratelimit</option>
              <option value="tailscale">tailscale</option>
            </select>
          </label>
          <label>
            Target fingerprint
            <input value={targetFingerprint} onChange={(event) => setTargetFingerprint(event.target.value)} placeholder="203.0.113.7" required />
          </label>
          <label>
            Target JSON
            <input value={targetJson} onChange={(event) => setTargetJson(event.target.value)} className="mono" />
          </label>
          <label>
            Reason
            <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="False positive, operator requested" />
          </label>
          <button className="primary" type="submit" disabled={submitting}>
            {submitting ? "Requesting…" : "Request rollback"}
          </button>
        </form>
        <ErrorNotice error={submitError || null} />
        {killSwitch.loading ? (
          <Loading />
        ) : killSwitch.data.length ? (
          <Table>
            <thead>
              <tr>
                <th>Adapter</th>
                <th>Target</th>
                <th>Reason</th>
                <th>Requested by</th>
                <th>Requested</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {killSwitch.data.map((item) => (
                <tr key={item.id}>
                  <td>
                    <Badge value={item.adapter} />
                  </td>
                  <td className="mono">{item.target_fingerprint}</td>
                  <td>{item.reason ?? "—"}</td>
                  <td>{item.requested_by}</td>
                  <td>{formatDate(item.created_at)}</td>
                  <td>
                    <Badge value={item.processed_at ? "processed" : "pending"} />
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty text="No kill-switch requests recorded." />
        )}
      </section>

      <section className="card">
        <div className="section-title">
          <h3>Action receipts</h3>
          <span>Desired state, applied state, and rollback plan</span>
        </div>
        {receipts.loading ? (
          <Loading />
        ) : receipts.data.length ? (
          <Table>
            <thead>
              <tr>
                <th>Adapter</th>
                <th>Kind</th>
                <th>Target</th>
                <th>Dry-run</th>
                <th>Verification</th>
                <th>TTL</th>
                <th>Expires</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {receipts.data.map((item) => (
                <tr key={item.id}>
                  <td>
                    <Badge value={item.adapter} />
                  </td>
                  <td>
                    <Badge value={item.receipt_kind} />
                  </td>
                  <td className="mono">{item.target_fingerprint ?? "—"}</td>
                  <td>{item.is_dry_run ? "dry-run" : "real"}</td>
                  <td>{item.verification_result ?? "—"}</td>
                  <td>{item.ttl_seconds}s</td>
                  <td>{formatDate(item.expires_at)}</td>
                  <td>{formatDate(item.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <Empty text="No firewall action receipts recorded yet." />
        )}
      </section>
    </>
  );
}
