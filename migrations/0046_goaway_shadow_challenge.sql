-- Go-Away is registered for a shadow-only policy-to-executor drill. These
-- actions remain disabled for normal execution requests and cannot be enabled
-- by this migration.
INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES ('00000000-0000-4000-8000-000000000065', 'Go-Away Challenge Connector', '0.1.0', 'firewall', 'configured', 'unknown')
ON CONFLICT (id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
    ('00000000-0000-4000-8000-000000000065', 'goaway.challenge_incident_source', FALSE, 'execute')
ON CONFLICT (connector_id, capability) DO NOTHING;

INSERT INTO actions (id, connector_id, name, type, description, risk_level, required_scope, requires_approval, enabled)
VALUES
    ('00000000-0000-4000-8000-0000000000a9', '00000000-0000-4000-8000-000000000065',
     'goaway.challenge_incident_source', 'connector_action',
     'Challenges an incident source through a Clawforge-owned Go-Away network snippet; disabled pending a separate live rollout.',
     'high', 'agent:action:read', TRUE, FALSE)
ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description,
    requires_approval = TRUE, enabled = FALSE, updated_at = NOW();

-- The policy-engine role can execute only this narrow function, not INSERT
-- into execution_requests. It accepts only a persisted shadow Challenge
-- decision for an IP pseudonym and creates a request whose immutable target
-- carries simulation_only=true. The executor enforces that marker even if its
-- global Dry-Run gate is relaxed in a later, separately reviewed release.
CREATE OR REPLACE FUNCTION clawforge_enqueue_goaway_shadow_challenge(p_decision_id UUID)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    selected_action_id UUID;
    selected_resource TEXT;
    request_id UUID;
    request_key TEXT;
BEGIN
    SELECT a.id, s.resource
      INTO selected_action_id, selected_resource
      FROM security_policy_decisions d
      JOIN security_assessments s ON s.id = d.assessment_id
      JOIN actions a ON a.name = 'goaway.challenge_incident_source'
     WHERE d.id = p_decision_id
       AND d.decision = 'challenge'
       AND d.is_shadow = TRUE
       AND s.resource LIKE 'ip-pseudonym:%'
       AND char_length(s.resource) > char_length('ip-pseudonym:')
       AND a.enabled = FALSE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    request_key := 'shadow-goaway:' || p_decision_id::TEXT;
    INSERT INTO execution_requests
        (id, action_id, requested_by, status, idempotency_key, max_retries,
         approval_context)
    VALUES
        (gen_random_uuid(), selected_action_id, 'policy-engine', 'pending',
         request_key, 0,
         jsonb_build_object(
             'version', 1,
             'security_policy_decision_id', p_decision_id,
             'simulation_only', TRUE,
             'target', jsonb_build_object(
                 'kind', 'incident_source',
                 'pseudonym', selected_resource,
                 'ttl_seconds', 3600,
                 'simulation_only', TRUE)))
    ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
    RETURNING id INTO request_id;

    IF request_id IS NULL THEN
        SELECT id INTO request_id FROM execution_requests WHERE idempotency_key = request_key;
    END IF;
    RETURN request_id;
END;
$$;

REVOKE ALL ON FUNCTION clawforge_enqueue_goaway_shadow_challenge(UUID) FROM PUBLIC;
