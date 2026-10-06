-- Write-ahead intent for every executor-driven firewall adapter operation.
-- The executor records this before calling an adapter. If the process dies
-- between an external mutation and its append-only receipt, the unresolved
-- row and local recovery marker prevent an unreviewed retry.
CREATE TABLE firewall_action_intents (
    id UUID PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES execution_requests(id),
    adapter TEXT NOT NULL,
    action_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'prepared'
        CHECK (status IN ('prepared', 'completed', 'not_applied')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX firewall_action_intents_pending_idx
    ON firewall_action_intents (created_at)
    WHERE status = 'prepared';

ALTER TABLE firewall_action_receipts
    ADD COLUMN intent_id UUID REFERENCES firewall_action_intents(id);

CREATE UNIQUE INDEX firewall_action_receipts_intent_idx
    ON firewall_action_receipts (intent_id)
    WHERE intent_id IS NOT NULL;
