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
