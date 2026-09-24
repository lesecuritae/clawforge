-- Phase 6 "Firewall Action Layer" (roadmap), first increment: the typed
-- adapter contract's persistence (Action Receipt: preflight, observed
-- state, verification, TTL, rollback plan) and connector/action
-- registration for clawforge-firewall-agent's nftables adapter - still
-- entirely preflight/render only. No code path capable of a live nftables
-- mutation exists yet (see firewall-agent/src/lib.rs's own doc comment);
-- this migration only makes room for one, deliberately disabled.

ALTER TABLE connector_registry DROP CONSTRAINT connector_registry_connector_type_check;
ALTER TABLE connector_registry ADD CONSTRAINT connector_registry_connector_type_check
    CHECK (connector_type IN ('docker', 'github', 'proxmox', 'firewall'));

INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES ('00000000-0000-4000-8000-000000000060', 'Firewall Connector', '0.1.0', 'firewall', 'configured', 'unknown')
ON CONFLICT (id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
    ('00000000-0000-4000-8000-000000000060', 'nftables.preflight', TRUE, 'read'),
    ('00000000-0000-4000-8000-000000000060', 'nftables.block_indicator', FALSE, 'execute'),
    ('00000000-0000-4000-8000-000000000060', 'nftables.block_incident_source', FALSE, 'execute')
ON CONFLICT (connector_id, capability) DO NOTHING;

-- Registered but disabled, matching migration 0027's own precedent for
-- every other connector action: the executor stays dry-run-only until a
-- separately reviewed change explicitly enables one. Two actions, not one
-- - see firewall-agent/src/lib.rs's FirewallTarget doc comment for why a
-- threat-intel-sourced block (a raw, already-public CIDR) and an
-- incident-sourced block (a pseudonymized resource, resolved only through
-- security_ip_resolutions's own short TTL, never persisted into a receipt)
-- are two different risk shapes, not one action with two target kinds.
INSERT INTO actions (id, connector_id, name, type, description, risk_level, required_scope, requires_approval, enabled)
VALUES
    ('00000000-0000-4000-8000-0000000000a0', '00000000-0000-4000-8000-000000000060',
     'nftables.block_indicator', 'connector_action',
     'Render (preflight only - no apply path exists yet) an nftables rule blocking a threat-intel-sourced CIDR/IP indicator.',
     'high', 'agent:action:read', TRUE, FALSE),
    ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-000000000060',
     'nftables.block_incident_source', 'connector_action',
     'Render (preflight only - no apply path exists yet) an nftables rule blocking a corroborated incident''s source, resolved through security_ip_resolutions at apply time only, never persisted in the receipt.',
     'critical', 'agent:action:read', TRUE, FALSE)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = NOW();

-- Action Receipt: preflight state, observed state ("Istzustand"),
-- verification result, TTL, and the rollback plan, persisted per
-- execution_request (nullable FK - a receipt can exist for a preflight
-- render that was never even turned into an execution_request yet, e.g.
-- from an ad-hoc dry-run check).
CREATE TABLE firewall_action_receipts (
    id UUID PRIMARY KEY,
    execution_id UUID REFERENCES execution_requests (id),
    adapter TEXT NOT NULL,
    action_name TEXT NOT NULL,
    -- What preflight found (current ruleset state relevant to this
    -- target) and what apply would render (the exact commands - see
    -- adapter doc comment for why an incident-sourced target's rendered
    -- commands reference the pseudonym, never a resolved raw IP).
    preflight_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    rendered_commands JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Populated only once a real apply path exists (not yet) - observed
    -- state after apply, and its verification against what was intended.
    observed_state JSONB,
    verification_result TEXT CHECK (verification_result IS NULL OR verification_result IN ('pending', 'verified', 'mismatch', 'failed')),
    ttl_seconds INTEGER NOT NULL CHECK (ttl_seconds > 0),
    rollback_plan JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_dry_run BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX firewall_action_receipts_execution_idx ON firewall_action_receipts (execution_id);
CREATE INDEX firewall_action_receipts_expiry_idx ON firewall_action_receipts (expires_at);

-- The one, deliberately narrow exception to this codebase's fail-closed
-- "never persist a raw IP" rule (events.correlation_id,
-- security_events.resource, security_assessments.resource all stay
-- pseudonymized): record_security_event writes one row here for every
-- security event it records, not only a threat-intel reputation hit -
-- corroboration can also come from two independent *behavioral* rules
-- firing for the same source (a plain ssh_bruteforce first, then later
-- the same source starts an http_scan, with no external reputation hit at
-- either point) - and clawforge-security-engine, working only from
-- pseudonyms, could never resolve that combination back to a real address
-- later if the mapping did not already exist by then. What keeps this
-- from being a blanket raw-IP log: a short, fixed TTL (default 24h, see
-- CLAWFORGE_IP_RESOLUTION_TTL_SECONDS, refreshed on every new event from
-- the same source so sustained activity stays resolvable and a one-off
-- expires quickly) and the rule that a resolved IP may only ever be used
-- just-in-time by a real apply step (not built yet) - never copied into a
-- rendered receipt or any other longer-lived record. Nothing reads this
-- table yet (no apply path exists) - see migration's own top comment.
CREATE TABLE security_ip_resolutions (
    pseudonym TEXT PRIMARY KEY,
    raw_ip INET NOT NULL,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX security_ip_resolutions_expiry_idx ON security_ip_resolutions (expires_at);
