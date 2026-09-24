-- Phase 6 "Firewall Action Layer" (roadmap): Tailscale's own first
-- increment - the roadmap is explicit that Tailscale should "zunaechst
-- nur als freigabepflichtigen Adapter vorbereiten" (prepare it initially
-- only as an approval-required adapter), narrower than nftables' own
-- first increment even. This migration only registers the connector and
-- action - `requires_approval=TRUE, enabled=FALSE`, matching migration
-- 0027's precedent for every connector action. There is no code path in
-- clawforge-firewall-agent's TailscaleAdapter capable of ever calling the
-- real Tailscale Admin API: no `apply`, `verify`, or `rollback` method
-- exists on that type at all (not "an apply that always errors" - an
-- apply that is not a method to call in the first place). See
-- docs/firewall-agent.md's "Tailscale adapter (prepared, not operable)"
-- section.

ALTER TABLE connector_registry DROP CONSTRAINT connector_registry_connector_type_check;
ALTER TABLE connector_registry ADD CONSTRAINT connector_registry_connector_type_check
    CHECK (connector_type IN ('docker', 'github', 'proxmox', 'firewall', 'tailscale'));

INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES ('00000000-0000-4000-8000-000000000061', 'Tailscale Connector', '0.1.0', 'tailscale', 'configured', 'unknown')
ON CONFLICT (id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
    ('00000000-0000-4000-8000-000000000061', 'tailscale.quarantine_device', FALSE, 'execute')
ON CONFLICT (connector_id, capability) DO NOTHING;

INSERT INTO actions (id, connector_id, name, type, description, risk_level, required_scope, requires_approval, enabled)
VALUES
    ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-000000000061',
     'tailscale.quarantine_device', 'connector_action',
     'Prepared only - no apply path exists yet. Would describe (never call) the Tailscale Admin API call that disables a device suspected of compromise.',
     'critical', 'agent:action:read', TRUE, FALSE)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, updated_at = NOW();
