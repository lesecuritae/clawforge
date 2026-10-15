-- Q2b: operator-initiated reconciliation of a specific recovery_required quarantine
-- generation. Disabled by default; registration grants no execution permission. Critical
-- and dual-approval, like the quarantine actions. The executor resolves the EXISTING
-- generation (prove remote completion via the recorded UPID, authoritative readback,
-- matching safe restore, atomic terminal status); it does NOT create a new intent.
INSERT INTO connector_capabilities (connector_id, capability, read_only, mode) VALUES
('00000000-0000-4000-8000-000000000050','docker.reconcile_quarantine',FALSE,'execute'),
('00000000-0000-4000-8000-000000000052','proxmox.reconcile_quarantine',FALSE,'execute')
ON CONFLICT (connector_id,capability) DO NOTHING;
INSERT INTO actions (id,connector_id,name,type,description,risk_level,required_scope,requires_approval,enabled) VALUES
('00000000-0000-4000-8000-0000000000b4','00000000-0000-4000-8000-000000000050','docker.reconcile_quarantine','connector_action','Operator reconciliation of a recovery_required container quarantine generation; disabled pending reviewed rollout.','critical','agent:action:read',TRUE,FALSE),
('00000000-0000-4000-8000-0000000000b5','00000000-0000-4000-8000-000000000052','proxmox.reconcile_quarantine','connector_action','Operator reconciliation of a recovery_required VM quarantine generation; disabled pending reviewed rollout.','critical','agent:action:read',TRUE,FALSE)
ON CONFLICT (name) DO UPDATE SET risk_level='critical',requires_approval=TRUE,enabled=FALSE,updated_at=NOW();

-- Extend the quarantine approval lock to also cover the reconcile actions, so the executor
-- can hold the reconcile request approval through the reconciliation (same contract as the
-- quarantine path). CREATE OR REPLACE preserves the existing REVOKE-from-PUBLIC ACL.
CREATE OR REPLACE FUNCTION clawforge_lock_quarantine_approval(execution UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM 1 FROM public.execution_requests e
      JOIN public.actions a ON a.id=e.action_id
      JOIN public.approval_policies p ON p.risk_level=a.risk_level
      WHERE e.id=execution AND a.name IN
        ('docker.quarantine_container','proxmox.quarantine_vm','tailscale.quarantine_device',
         'docker.reconcile_quarantine','proxmox.reconcile_quarantine')
      FOR UPDATE OF e,a,p;
    IF NOT FOUND THEN RAISE EXCEPTION 'quarantine approval context not found'; END IF;
END;
$$;
