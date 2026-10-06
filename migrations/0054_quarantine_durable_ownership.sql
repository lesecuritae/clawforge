-- Extend native write-ahead intents; no second recovery journal.
ALTER TABLE firewall_action_intents
    DROP CONSTRAINT firewall_action_intents_status_check,
    ADD CONSTRAINT firewall_action_intents_status_check CHECK
      (status IN ('prepared','completed','not_applied','recovery_required','rolled_back')),
    ADD COLUMN target_fingerprint TEXT,
    ADD COLUMN target_json JSONB,
    ADD COLUMN preflight_state JSONB,
    ADD COLUMN rollback_plan JSONB,
    ADD COLUMN ttl_seconds INTEGER CHECK (ttl_seconds >= 60 AND ttl_seconds <= 86400),
    ADD COLUMN expires_at TIMESTAMPTZ,
    ADD COLUMN error_summary TEXT,
    ADD CONSTRAINT quarantine_intent_snapshot_complete CHECK
      (target_fingerprint IS NULL OR
        (adapter IN ('docker','proxmox','tailscale')
         AND action_name = CASE adapter
           WHEN 'docker' THEN 'docker.quarantine_container'
           WHEN 'proxmox' THEN 'proxmox.quarantine_vm'
           WHEN 'tailscale' THEN 'tailscale.quarantine_device' END
         AND length(target_fingerprint) BETWEEN 1 AND 256
         AND target_json IS NOT NULL AND jsonb_typeof(target_json) = 'object'
         AND target_json->>'kind' IS NOT DISTINCT FROM adapter
         AND preflight_state IS NOT NULL AND jsonb_typeof(preflight_state) = 'object'
         AND rollback_plan IS NOT NULL AND jsonb_typeof(rollback_plan) = 'object'
         AND ttl_seconds IS NOT NULL AND expires_at IS NOT NULL));
CREATE UNIQUE INDEX firewall_quarantine_active_generation
    ON firewall_action_intents(adapter,target_fingerprint)
    WHERE target_fingerprint IS NOT NULL AND status IN ('prepared','completed','recovery_required');
CREATE INDEX firewall_quarantine_expiry ON firewall_action_intents(expires_at)
    WHERE target_fingerprint IS NOT NULL AND status IN ('prepared','completed','recovery_required');
-- One append-only apply and one verified rollback receipt per generation.
DROP INDEX firewall_action_receipts_intent_idx;
CREATE UNIQUE INDEX firewall_action_receipts_intent_idx
    ON firewall_action_receipts(intent_id,receipt_kind) WHERE intent_id IS NOT NULL;

CREATE FUNCTION protect_quarantine_intent_snapshot() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.target_fingerprint IS NOT NULL AND
       (OLD.id IS DISTINCT FROM NEW.id OR OLD.execution_id IS DISTINCT FROM NEW.execution_id
        OR OLD.adapter IS DISTINCT FROM NEW.adapter OR OLD.action_name IS DISTINCT FROM NEW.action_name
        OR OLD.created_at IS DISTINCT FROM NEW.created_at
        OR OLD.target_fingerprint IS DISTINCT FROM NEW.target_fingerprint
        OR OLD.target_json IS DISTINCT FROM NEW.target_json
        OR OLD.preflight_state IS DISTINCT FROM NEW.preflight_state
        OR OLD.rollback_plan IS DISTINCT FROM NEW.rollback_plan
        OR OLD.ttl_seconds IS DISTINCT FROM NEW.ttl_seconds
        OR OLD.expires_at IS DISTINCT FROM NEW.expires_at) THEN
        RAISE EXCEPTION 'quarantine intent snapshot is immutable';
    END IF;
    IF OLD.target_fingerprint IS NOT NULL AND OLD.status IS DISTINCT FROM NEW.status
       AND NOT ((OLD.status = 'prepared' AND NEW.status IN ('completed','not_applied','recovery_required','rolled_back'))
                OR (OLD.status = 'completed' AND NEW.status IN ('recovery_required','rolled_back'))
                OR (OLD.status = 'recovery_required' AND NEW.status = 'rolled_back')) THEN
        RAISE EXCEPTION 'quarantine generation transition refused';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER quarantine_intent_snapshot_immutable BEFORE UPDATE ON firewall_action_intents
    FOR EACH ROW EXECUTE FUNCTION protect_quarantine_intent_snapshot();

-- Restore requests bind to an immutable generation, so a delayed request cannot
-- affect a later quarantine of the same external target.
ALTER TABLE firewall_kill_switch_requests
    ADD COLUMN quarantine_intent_id UUID REFERENCES firewall_action_intents(id);

-- Lock policy/action rows without granting the executor policy mutation rights.
-- This function can only lock the three quarantine action contexts; it writes nothing.
CREATE FUNCTION clawforge_lock_quarantine_approval(execution UUID) RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
    PERFORM 1 FROM public.execution_requests e
      JOIN public.actions a ON a.id=e.action_id
      JOIN public.approval_policies p ON p.risk_level=a.risk_level
      WHERE e.id=execution AND a.name IN
        ('docker.quarantine_container','proxmox.quarantine_vm','tailscale.quarantine_device')
      FOR UPDATE OF e,a,p;
    IF NOT FOUND THEN RAISE EXCEPTION 'quarantine approval context not found'; END IF;
END;
$$;
REVOKE ALL ON FUNCTION clawforge_lock_quarantine_approval(UUID) FROM PUBLIC;
