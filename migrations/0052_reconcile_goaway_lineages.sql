-- Additive convergence for the reviewed main46 and production46 histories.
-- Preserve every existing action ID, request, approval and enabled flag.
-- Resolve actions by name: historical IDs legitimately differ by lineage.
INSERT INTO connector_capabilities (connector_id,capability,read_only,mode) VALUES
('00000000-0000-4000-8000-000000000065','goaway.preflight',TRUE,'read'),
('00000000-0000-4000-8000-000000000065','goaway.challenge_indicator',FALSE,'execute'),
('00000000-0000-4000-8000-000000000065','goaway.challenge_incident_source',FALSE,'execute')
ON CONFLICT (connector_id,capability) DO NOTHING;
INSERT INTO actions (id,connector_id,name,type,description,risk_level,required_scope,requires_approval,enabled) VALUES
('00000000-0000-4000-8000-0000000000b0','00000000-0000-4000-8000-000000000065','goaway.challenge_indicator','connector_action','Explicit indicator challenge; disabled pending reviewed rollout.','high','agent:action:read',TRUE,FALSE),
('00000000-0000-4000-8000-0000000000b1','00000000-0000-4000-8000-000000000065','goaway.challenge_incident_source','connector_action','Immutable incident-source shadow simulation.','high','agent:action:read',TRUE,FALSE)
ON CONFLICT (name) DO NOTHING;

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
