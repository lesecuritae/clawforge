-- Phase 6 "Firewall Action Layer" (roadmap): concurrency budget across
-- multiple executor replicas targeting the same adapter/host.
--
-- Closes the last open half of "pro Adapter/Ziel gelten getestete Rate-,
-- Concurrency- und Mass-block-Budgets": the mass-block budget (migration
-- 0036/firewall_action_receipts) already bounds the *rate* of real
-- applies over time, DB-backed so it holds across replicas - but nothing
-- previously bounded how many real apply/rollback calls could be
-- *simultaneously in flight* against the same adapter's shared resource
-- (the HAProxy Runtime API socket, the local nftables/netlink interface,
-- the Tailscale Admin API) if several executor replicas each claimed a
-- different request at nearly the same instant.
--
-- This is a reservation table, not a log: a row exists only while its
-- operation is (believed to be) in flight, and is deleted once the
-- reservation is released (see clawforge-executor's begin/end-inflight
-- helpers). started_at exists so a crashed replica that reserved a slot
-- but never released it cannot leak that slot forever - the concurrency
-- check only counts rows younger than a configurable staleness window
-- (CLAWFORGE_FIREWALL_INFLIGHT_STALE_SECONDS), so a leaked row ages out
-- and stops counting on its own, the same self-healing property
-- execution_leases already has via its own expiry.
CREATE TABLE firewall_inflight_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    adapter TEXT NOT NULL,
    execution_id UUID,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The concurrency check's own query: count of live rows for one adapter.
CREATE INDEX firewall_inflight_operations_adapter_idx
    ON firewall_inflight_operations (adapter, started_at);
