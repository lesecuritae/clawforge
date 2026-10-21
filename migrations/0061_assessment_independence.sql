-- Independent corroboration needs to know which event families stand behind an
-- assessment (ssh_login_failure, http_anomaly, ...). The policy-engine role has
-- no access to the events table (it carries evidence payloads); this narrow
-- function exposes only the distinct event types of one assessment.
CREATE OR REPLACE FUNCTION clawforge_assessment_event_types(p_assessment_id UUID)
RETURNS TEXT[]
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT COALESCE(array_agg(DISTINCT e.event_type ORDER BY e.event_type), ARRAY[]::TEXT[])
      FROM security_assessment_events se
      JOIN events e ON e.event_id = se.event_id
     WHERE se.assessment_id = p_assessment_id
$$;

REVOKE ALL ON FUNCTION clawforge_assessment_event_types(UUID) FROM PUBLIC;

-- Server-fault bursts (many 5xx answers to one source) are an operational
-- observation, not an attacker finding: record them under their own rule with an
-- observe-class policy. Existing rules and their policies are unchanged.
INSERT INTO security_policies (id, name, version, status, class, rule_id, min_severity)
VALUES ('00000000-0000-4000-9000-000000000004', 'http_server_fault_burst-default', 1, 'active',
        'observe', 'http_server_fault_burst', 'medium')
ON CONFLICT (id) DO NOTHING;

-- Overlapping windows of one episode yield several policy decisions for the same
-- source; they must not each create a simulated Go-Away challenge. One simulation
-- per source and action per hour (the decision-keyed idempotency stays as well).
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
    SELECT e.id INTO request_id FROM execution_requests e
     WHERE e.idempotency_key = request_key;
    IF request_id IS NOT NULL THEN
        RETURN request_id;
    END IF;
    SELECT e.id INTO request_id FROM execution_requests e
     WHERE e.action_id = selected_action_id
       AND e.approval_context -> 'target' ->> 'pseudonym' = selected_resource
       AND e.created_at > NOW() - INTERVAL '1 hour'
     ORDER BY e.created_at LIMIT 1;
    IF request_id IS NOT NULL THEN
        RETURN request_id;
    END IF;

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
