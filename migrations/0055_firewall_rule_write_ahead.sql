-- F2: durable write-ahead ownership for generic firewall rule applies
-- (nftables / haproxy / haproxy_ratelimit), the same discipline migration 0054
-- gave VM/container quarantine, via a typed rule contract. Additive and
-- independent of the quarantine columns/constraints: a quarantine generation
-- (target_fingerprint) and a rule generation (fw_rule_fingerprint) can never be
-- the same row, and this migration never alters a 0054 object.
--
-- The executor commits a prepared rule intent BEFORE calling the adapter, so a
-- crash between a real mutation and its append-only receipt leaves a durably
-- owned, visible generation that is reconciled, never blindly replayed.
ALTER TABLE firewall_action_intents
    ADD COLUMN fw_rule_fingerprint TEXT,
    -- Binds the concrete rule, not just an IP: the adapter's ruleset scope
    -- (nftables set, haproxy acl file, or rate-limit table) the element lives in.
    ADD COLUMN fw_rule_scope TEXT,
    ADD COLUMN fw_target_json JSONB,
    ADD COLUMN fw_preflight_state JSONB,
    ADD COLUMN fw_rollback_plan JSONB,
    ADD COLUMN fw_ttl_seconds INTEGER
        CHECK (fw_ttl_seconds IS NULL OR (fw_ttl_seconds >= 60 AND fw_ttl_seconds <= 86400)),
    ADD COLUMN fw_expires_at TIMESTAMPTZ,
    ADD COLUMN fw_error_summary TEXT,
    ADD CONSTRAINT firewall_rule_intent_snapshot_complete CHECK
      (fw_rule_fingerprint IS NULL OR
        (adapter IN ('nftables','haproxy','haproxy_ratelimit')
         -- Never both a quarantine and a rule intent in one row.
         AND target_fingerprint IS NULL
         AND length(fw_rule_fingerprint) BETWEEN 1 AND 256
         AND fw_rule_scope IS NOT NULL AND length(fw_rule_scope) BETWEEN 1 AND 256
         AND fw_target_json IS NOT NULL AND jsonb_typeof(fw_target_json) = 'object'
         AND fw_preflight_state IS NOT NULL AND jsonb_typeof(fw_preflight_state) = 'object'
         AND fw_rollback_plan IS NOT NULL AND jsonb_typeof(fw_rollback_plan) = 'object'
         AND fw_ttl_seconds IS NOT NULL AND fw_expires_at IS NOT NULL));

-- One active owner per concrete rule (adapter + scope + element) at a time.
CREATE UNIQUE INDEX firewall_rule_active_generation
    ON firewall_action_intents(adapter, fw_rule_scope, fw_rule_fingerprint)
    WHERE fw_rule_fingerprint IS NOT NULL AND status IN ('prepared','completed','recovery_required');
CREATE INDEX firewall_rule_expiry ON firewall_action_intents(fw_expires_at)
    WHERE fw_rule_fingerprint IS NOT NULL AND status IN ('prepared','completed','recovery_required');

-- Immutable snapshot + fenced transitions for rule generations. Independent of
-- the 0054 quarantine trigger (that one only fires for target_fingerprint rows).
CREATE FUNCTION protect_firewall_rule_intent_snapshot() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.fw_rule_fingerprint IS NOT NULL AND
       (OLD.id IS DISTINCT FROM NEW.id OR OLD.execution_id IS DISTINCT FROM NEW.execution_id
        OR OLD.adapter IS DISTINCT FROM NEW.adapter OR OLD.action_name IS DISTINCT FROM NEW.action_name
        OR OLD.created_at IS DISTINCT FROM NEW.created_at
        OR OLD.fw_rule_fingerprint IS DISTINCT FROM NEW.fw_rule_fingerprint
        OR OLD.fw_rule_scope IS DISTINCT FROM NEW.fw_rule_scope
        OR OLD.fw_target_json IS DISTINCT FROM NEW.fw_target_json
        OR OLD.fw_preflight_state IS DISTINCT FROM NEW.fw_preflight_state
        OR OLD.fw_rollback_plan IS DISTINCT FROM NEW.fw_rollback_plan
        OR OLD.fw_ttl_seconds IS DISTINCT FROM NEW.fw_ttl_seconds
        OR OLD.fw_expires_at IS DISTINCT FROM NEW.fw_expires_at) THEN
        RAISE EXCEPTION 'firewall rule intent snapshot is immutable';
    END IF;
    IF OLD.fw_rule_fingerprint IS NOT NULL AND OLD.status IS DISTINCT FROM NEW.status
       AND NOT ((OLD.status = 'prepared' AND NEW.status IN ('completed','not_applied','recovery_required','rolled_back'))
                OR (OLD.status = 'completed' AND NEW.status IN ('recovery_required','rolled_back'))
                OR (OLD.status = 'recovery_required' AND NEW.status = 'rolled_back')) THEN
        RAISE EXCEPTION 'firewall rule generation transition refused';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER firewall_rule_intent_snapshot_immutable BEFORE UPDATE ON firewall_action_intents
    FOR EACH ROW EXECUTE FUNCTION protect_firewall_rule_intent_snapshot();
