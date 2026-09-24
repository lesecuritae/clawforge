-- Phase 6 "Firewall Action Layer" (roadmap): multi-adapter dispatch. A
-- Block decision must be able to protect *any* externally-facing service
-- on a host, not only the ones fronted by HAProxy - a `firewall.*`
-- action (as opposed to a single-adapter `nftables.*`/`haproxy.*`/
-- `haproxy_ratelimit.*` one) fans out to every adapter
-- CLAWFORGE_FIREWALL_ADAPTERS configures, always including the
-- host-wide `nftables` adapter regardless of that configuration (see
-- clawforge-executor's MANDATORY_MULTI_ADAPTER and
-- dispatch_multi_adapter). Same two-action split as every other
-- connector for the same reason: a threat-intel-sourced block and an
-- incident-sourced block are two different risk shapes.

INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES ('00000000-0000-4000-8000-000000000064', 'Multi-Adapter Firewall Connector', '0.1.0', 'firewall', 'configured', 'unknown')
ON CONFLICT (id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
    ('00000000-0000-4000-8000-000000000064', 'firewall.block_indicator', FALSE, 'execute'),
    ('00000000-0000-4000-8000-000000000064', 'firewall.block_incident_source', FALSE, 'execute')
ON CONFLICT (connector_id, capability) DO NOTHING;

INSERT INTO actions (id, connector_id, name, type, description, risk_level, required_scope, requires_approval, enabled)
VALUES
    ('00000000-0000-4000-8000-0000000000a7', '00000000-0000-4000-8000-000000000064',
     'firewall.block_indicator', 'connector_action',
     'Applies a threat-intel-sourced CIDR/IP indicator across every adapter CLAWFORGE_FIREWALL_ADAPTERS configures (always including nftables), covering any externally-facing service on the host, not only ones fronted by HAProxy.',
     'high', 'agent:action:read', TRUE, FALSE),
    ('00000000-0000-4000-8000-0000000000a8', '00000000-0000-4000-8000-000000000064',
     'firewall.block_incident_source', 'connector_action',
     'Applies a corroborated incident''s source across every configured adapter (always including nftables), resolved through security_ip_resolutions at apply time only, never persisted in any receipt.',
     'critical', 'agent:action:read', TRUE, FALSE)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = NOW();
