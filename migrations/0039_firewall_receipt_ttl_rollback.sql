-- Phase 6 "Firewall Action Layer" (roadmap): TTL-driven auto-rollback.
-- Closes a real gap: ttl_seconds/expires_at were recorded on every
-- receipt since migration 0036, but nothing ever read expires_at back
-- and rolled a block back once it passed - a real (non-dry-run) block
-- stayed in effect indefinitely until something else removed it.
--
-- firewall_action_receipts is an append-only log (see
-- FirewallActionReceiptInput's own doc comment in storage/src/lib.rs) -
-- a rollback gets its own new row, never an UPDATE of the apply row it
-- undoes. receipt_kind distinguishes the two; target_fingerprint (the
-- adapter's own already-redacted, safe-to-persist element reference -
-- see clawforge-firewall-agent's redacted_element_reference) is what
-- matches a rollback row to the apply row it undoes; target_json is the
-- same {"kind":...} JSON contract execution_requests.approval_context
-- already carries, kept here so a caller (the TTL sweep) can reconstruct
-- a FirewallTarget without re-deriving it from rendered_commands text.

ALTER TABLE firewall_action_receipts
    ADD COLUMN receipt_kind TEXT NOT NULL DEFAULT 'apply'
        CHECK (receipt_kind IN ('apply', 'rollback')),
    ADD COLUMN target_fingerprint TEXT,
    ADD COLUMN target_json JSONB;

-- The sweep's own query: "every real apply whose TTL has passed, that
-- has no later rollback row for the same adapter+target_fingerprint".
CREATE INDEX firewall_action_receipts_ttl_sweep_idx
    ON firewall_action_receipts (adapter, target_fingerprint, receipt_kind, created_at)
    WHERE target_fingerprint IS NOT NULL;
