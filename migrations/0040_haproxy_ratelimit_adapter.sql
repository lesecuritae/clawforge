-- Phase 6 "Firewall Action Layer" (roadmap): the "Rate-Limits" half of
-- "HAProxy-Adapter fuer Maps/ACLs und Rate-Limits implementieren" -
-- migration 0038 already covered "Maps/ACLs". clawforge-firewall-agent's
-- HaproxyRateLimitAdapter has real apply/verify/rollback via the HAProxy
-- Runtime API's `set table`/`clear table`/`show table` commands against
-- Clawforge's own exclusively-owned stick-table, flagging a key's `gpc0`
-- general-purpose counter rather than adding it to a membership list -
-- never touches haproxy.cfg itself (see docs/firewall-agent.md).

INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES ('00000000-0000-4000-8000-000000000063', 'HAProxy Rate Limit Connector', '0.1.0', 'firewall', 'configured', 'unknown')
ON CONFLICT (id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
    ('00000000-0000-4000-8000-000000000063', 'haproxy_ratelimit.preflight', TRUE, 'read'),
    ('00000000-0000-4000-8000-000000000063', 'haproxy_ratelimit.block_indicator', FALSE, 'execute'),
    ('00000000-0000-4000-8000-000000000063', 'haproxy_ratelimit.block_incident_source', FALSE, 'execute')
ON CONFLICT (connector_id, capability) DO NOTHING;

-- Registered but disabled, same precedent as every connector action
-- since migration 0027, and the same two-action split as nftables/
-- haproxy (migrations 0036/0038) for the same reason: a threat-intel-
-- sourced block and an incident-sourced block are two different risk
-- shapes, not one action with two target kinds.
INSERT INTO actions (id, connector_id, name, type, description, risk_level, required_scope, requires_approval, enabled)
VALUES
    ('00000000-0000-4000-8000-0000000000a5', '00000000-0000-4000-8000-000000000063',
     'haproxy_ratelimit.block_indicator', 'connector_action',
     'Flags a threat-intel-sourced CIDR/IP indicator in Clawforge''s HAProxy stick-table (gpc0) via the Runtime API.',
     'high', 'agent:action:read', TRUE, FALSE),
    ('00000000-0000-4000-8000-0000000000a6', '00000000-0000-4000-8000-000000000063',
     'haproxy_ratelimit.block_incident_source', 'connector_action',
     'Flags a corroborated incident''s source in Clawforge''s HAProxy stick-table, resolved through security_ip_resolutions at apply time only, never persisted in the receipt.',
     'critical', 'agent:action:read', TRUE, FALSE)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = NOW();
