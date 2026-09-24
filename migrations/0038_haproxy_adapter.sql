-- Phase 6 "Firewall Action Layer" (roadmap): HAProxy adapter - the
-- "Maps/ACLs" half of "HAProxy-Adapter fuer Maps/ACLs und Rate-Limits
-- implementieren". clawforge-firewall-agent's HaproxyAdapter has real
-- apply/verify/rollback via the HAProxy Runtime API's `add acl`/`del
-- acl`/`show acl` commands against Clawforge's own exclusively-owned ACL
-- pattern file - never touches haproxy.cfg itself (see
-- docs/firewall-agent.md). Rate-limiting (HAProxy stick-tables) is a
-- materially different mechanism (a counter/threshold, not a membership
-- set) and is NOT built here - this migration only registers the
-- membership-blocking actions.

INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES ('00000000-0000-4000-8000-000000000062', 'HAProxy Connector', '0.1.0', 'firewall', 'configured', 'unknown')
ON CONFLICT (id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
    ('00000000-0000-4000-8000-000000000062', 'haproxy.preflight', TRUE, 'read'),
    ('00000000-0000-4000-8000-000000000062', 'haproxy.block_indicator', FALSE, 'execute'),
    ('00000000-0000-4000-8000-000000000062', 'haproxy.block_incident_source', FALSE, 'execute')
ON CONFLICT (connector_id, capability) DO NOTHING;

-- Registered but disabled, same precedent as every connector action
-- since migration 0027 - and the same two-action split as nftables
-- (migration 0036) for the same reason: a threat-intel-sourced block (a
-- raw, already-public CIDR) and an incident-sourced block (a
-- pseudonymized resource, resolved only through security_ip_resolutions's
-- own short TTL, never persisted into a receipt) are two different risk
-- shapes, not one action with two target kinds.
INSERT INTO actions (id, connector_id, name, type, description, risk_level, required_scope, requires_approval, enabled)
VALUES
    ('00000000-0000-4000-8000-0000000000a3', '00000000-0000-4000-8000-000000000062',
     'haproxy.block_indicator', 'connector_action',
     'Adds a threat-intel-sourced CIDR/IP indicator to Clawforge''s HAProxy ACL pattern file via the Runtime API.',
     'high', 'agent:action:read', TRUE, FALSE),
    ('00000000-0000-4000-8000-0000000000a4', '00000000-0000-4000-8000-000000000062',
     'haproxy.block_incident_source', 'connector_action',
     'Adds a corroborated incident''s source to Clawforge''s HAProxy ACL pattern file, resolved through security_ip_resolutions at apply time only, never persisted in the receipt.',
     'critical', 'agent:action:read', TRUE, FALSE)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = NOW();
