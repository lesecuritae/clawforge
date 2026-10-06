-- Disabled by default. Registration grants no production execution permission.
UPDATE approval_policies SET required_approvals = GREATEST(required_approvals, 2)
WHERE risk_level = 'critical';
INSERT INTO connector_capabilities (connector_id, capability, read_only, mode) VALUES
('00000000-0000-4000-8000-000000000050','docker.quarantine_container',FALSE,'execute'),
('00000000-0000-4000-8000-000000000052','proxmox.quarantine_vm',FALSE,'execute')
ON CONFLICT (connector_id,capability) DO NOTHING;
INSERT INTO actions (id,connector_id,name,type,description,risk_level,required_scope,requires_approval,enabled) VALUES
('00000000-0000-4000-8000-0000000000b2','00000000-0000-4000-8000-000000000050','docker.quarantine_container','connector_action','Reversible container-network isolation; disabled pending reviewed rollout.','critical','agent:action:read',TRUE,FALSE),
('00000000-0000-4000-8000-0000000000b3','00000000-0000-4000-8000-000000000052','proxmox.quarantine_vm','connector_action','Reversible VM isolation; disabled pending reviewed rollout.','critical','agent:action:read',TRUE,FALSE)
ON CONFLICT (name) DO UPDATE SET risk_level='critical',requires_approval=TRUE,enabled=FALSE,updated_at=NOW();
