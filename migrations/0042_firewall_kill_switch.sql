-- Phase 6 "Firewall Action Layer" (roadmap): kill-switch per target.
-- Closes the last open half of the roadmap's own Pflichtgate
-- ("Desired/Actual State, TTL, Drift, Kill-Switch und vollstaendige
-- Audit-Lineage sind vor einem Produktionspilot ueber ein geprueftes
-- Admin-Werkzeug sichtbar") - until now the only way to force a real
-- block off was scripts/nftables-clawforge-break-glass.sh, which is
-- all-or-nothing per host (removes the entire exclusive table), not a
-- per-target tool an operator can reach for a single false positive.
--
-- Only clawforge-executor is ever allowed to call a real adapter (see
-- clawforge-firewall-agent's own design), so an admin-triggered
-- kill-switch cannot roll a target back synchronously from
-- clawforge-api - it can only record the *intent*. This table is that
-- intent queue: clawforge-api inserts a row, clawforge-executor's sweep
-- (same poll tick as the TTL sweep, see executor/src/main.rs) picks up
-- every unprocessed row, performs the same rollback the TTL sweep would
-- have performed once expires_at passed anyway, and marks it
-- processed_at - the exact same rollback path, just triggered on demand
-- instead of by expiry. A row that fails to roll back stays unprocessed
-- and is retried next tick, mirroring the TTL sweep's own retry
-- behavior for a failed rollback.
CREATE TABLE firewall_kill_switch_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    adapter TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL,
    -- The same {"kind":...}/{"device_id":...} JSON contract
    -- firewall_action_receipts.target_json already carries - lets the
    -- sweep reconstruct a target without re-deriving one from anything
    -- else.
    target_json JSONB NOT NULL,
    reason TEXT,
    requested_by TEXT NOT NULL,
    requested_by_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

-- The sweep's own query: every request with no processed_at yet, oldest
-- first.
CREATE INDEX firewall_kill_switch_requests_pending_idx
    ON firewall_kill_switch_requests (created_at)
    WHERE processed_at IS NULL;
