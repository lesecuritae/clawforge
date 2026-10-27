import React, { useState } from "react";
import { api, type Envelope } from "./api";
import { useApi, Table, Empty, Loading, Badge, ErrorNotice, formatDate } from "./ui";

type Waiting = { id: string; action_name: string; status: string; risk_level: string; requested_by: string; created_at: string };
type Confirmation = { profile_mode: string; you_are_designated_operator: boolean; available: boolean; signed_in_as: string };
type Detail = {
  id: string; action_name: string; status: string; risk_level: string; requested_by: string;
  target: Record<string, unknown> | null; approval_context_hash: string | null; required_approvals: number;
  approval_expires_at: string | null; approval_profile: { mode?: string; policy_required_approvals?: number } | null;
  approvals: Array<Record<string, unknown>>; confirmation: Confirmation;
};

/// Single-operator confirmation (docs/single-operator-profile.md). The profile is read from the trusted deployment
/// configuration through the API; this view never chooses it. The button exists only when the server says this signed-in
/// Administrator is the designated operator of an eligible, unexpired request, and it sends the context hash that is
/// displayed. There is no fallback to the ordinary approval route: an error is shown as an error.
export function ExecutionConfirmations({ token }: { token: string }) {
  const waiting = useApi<Waiting[]>("/executions?status=waiting_approval&page_size=50", token, []);
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useApi<Detail | null>(selected ? `/executions/${selected}` : "/health", token, null);
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const current = selected && detail.data && "confirmation" in detail.data ? detail.data : null;

  function choose(id: string) { setSelected(id); setReviewed(false); setMessage(""); }

  async function confirm() {
    if (!current || !current.approval_context_hash || busy) return;
    setBusy(true); setMessage("");
    try {
      await api<Envelope<unknown>>(`/admin/executions/${current.id}/confirm-single-operator`, token, {
        method: "POST", body: JSON.stringify({ context_hash: current.approval_context_hash }),
      });
      setMessage("Confirmed. The request is approved; the executor's own gates still decide whether anything runs.");
      setReviewed(false); waiting.reload(); detail.reload();
    } catch (error) {
      setMessage(`Not confirmed: ${error instanceof Error ? error.message : "request refused"}`);
      detail.reload();
    } finally { setBusy(false); }
  }

  return <section className="card" aria-label="Execution confirmations">
    <div className="section-title"><h3>Requests awaiting approval</h3><span>Review the exact request, then confirm</span></div>
    <ErrorNotice error={waiting.error || detail.error} />
    {waiting.loading ? <Loading /> : waiting.data.length ? <Table><thead><tr><th>Action</th><th>Risk</th><th>Requested by</th><th>Created</th><th /></tr></thead><tbody>
      {waiting.data.map((item) => <tr key={item.id}><td><b>{item.action_name}</b></td><td><Badge value={item.risk_level} /></td><td>{item.requested_by}</td><td>{formatDate(item.created_at)}</td>
        <td><button type="button" onClick={() => choose(item.id)}>Review</button></td></tr>)}</tbody></Table> : <Empty text="No requests are waiting for approval." />}
    {current ? <div className="card" role="region" aria-label="Request review">
      <h4>{current.action_name}</h4>
      <p>Approval profile: <Badge value={current.confirmation.profile_mode === "single_operator" ? "single operator (deliberate)" : "multi-person (default)"} /> {current.approval_profile?.mode === "single_operator" ? <span>policy normally requires {current.approval_profile.policy_required_approvals} approvals; this request needs 1 confirmation by the designated operator</span> : <span>requires {current.required_approvals} distinct approvals</span>}</p>
      <p>Target: <code>{JSON.stringify(current.target)}</code></p>
      <p>Context hash: <code>{current.approval_context_hash}</code></p>
      <p>Expires: {current.approval_expires_at ? formatDate(current.approval_expires_at) : "—"} · Signed in as {current.confirmation.signed_in_as}</p>
      {current.confirmation.available ? <>
        <label><input type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} /> I reviewed this exact request and confirm it myself</label>
        <button type="button" disabled={!reviewed || busy} onClick={confirm}>Confirm request</button>
      </> : <p className="muted">{current.confirmation.profile_mode === "single_operator" && !current.confirmation.you_are_designated_operator
        ? "You are not the designated operator for the single-operator profile."
        : current.approval_profile?.mode === "single_operator" ? "Confirmation is not available (expired, not waiting, or not an interactive session)." : "Single-operator confirmation does not apply to this request."}</p>}
      {message ? <p role="status">{message}</p> : null}
    </div> : null}
  </section>;
}
