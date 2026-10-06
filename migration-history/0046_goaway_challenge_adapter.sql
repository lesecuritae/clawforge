-- Phase 6 "Firewall Action Layer": challenge a source through go-away's
-- policy engine. The adapter updates only a Clawforge-owned network
-- snippet consumed through --policy-snippets. Operators add the static
-- challenge rule to their main go-away policy; Clawforge never replaces
-- that policy. Both actions remain disabled and approval-gated.

INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES ('00000000-0000-4000-8000-000000000065', 'go-away Challenge Connector', '0.1.0', 'firewall', 'configured', 'unknown')
ON CONFLICT (id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
    ('00000000-0000-4000-8000-000000000065', 'goaway.preflight', TRUE, 'read'),
    ('00000000-0000-4000-8000-000000000065', 'goaway.challenge_indicator', FALSE, 'execute')
ON CONFLICT (connector_id, capability) DO NOTHING;

INSERT INTO actions (id, connector_id, name, type, description, risk_level, required_scope, requires_approval, enabled)
VALUES
    ('00000000-0000-4000-8000-0000000000a9', '00000000-0000-4000-8000-000000000065',
     'goaway.challenge_indicator', 'connector_action',
     'Adds a threat-intel-sourced CIDR/IP to go-away’s Clawforge-managed challenge network; the main policy must define the matching challenge rule.',
     'high', 'agent:action:read', TRUE, FALSE)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = NOW();
