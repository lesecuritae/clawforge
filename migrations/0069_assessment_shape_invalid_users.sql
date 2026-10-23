-- Attack shape v2: adds `distinct_invalid_usernames` to the counts of clawforge_assessment_shape.
-- The Linux sensor now carries sshd's own verdict per failed login (`invalid_user`: sshd logs
-- "invalid user" for an account that does not exist on the host). Several DIFFERENT nonexistent
-- account names from one source are guessing, not a user mistyping their own name; a handful of
-- existing accounts (users behind a NAT, a forgetful user) never count. Events without the field
-- (older sensors) count as unknown, not as invalid. Output is a superset of 0067 (same keys plus
-- one), so the 1.2.3 policy engine keeps working on this function body after a rollback.
-- CREATE OR REPLACE keeps the owner and the EXECUTE grants.
CREATE OR REPLACE FUNCTION clawforge_assessment_shape(p_assessment_id UUID, p_path_patterns TEXT[])
RETURNS JSONB
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    result JSONB;
BEGIN
    IF p_path_patterns IS NULL THEN
        p_path_patterns := ARRAY[]::TEXT[];
    END IF;
    IF cardinality(p_path_patterns) > 50
       OR EXISTS (SELECT 1 FROM unnest(p_path_patterns) AS p WHERE length(p) > 200) THEN
        RAISE EXCEPTION 'at most 50 path patterns of at most 200 characters';
    END IF;
    WITH m AS (
        SELECT e.event_type, e.payload
          FROM security_assessment_events se
          JOIN events e ON e.event_id = se.event_id
         WHERE se.assessment_id = p_assessment_id
         LIMIT 1000
    )
    SELECT jsonb_build_object(
               'events', count(*),
               'distinct_usernames', count(DISTINCT lower(left(m.payload ->> 'username', 64)))
                                         FILTER (WHERE m.event_type = 'ssh_login_failure'),
               'distinct_invalid_usernames', count(DISTINCT lower(left(m.payload ->> 'username', 64)))
                                                 FILTER (WHERE m.event_type = 'ssh_login_failure'
                                                           AND m.payload ->> 'invalid_user' = 'true'),
               'signature_paths', count(DISTINCT left(m.payload ->> 'path', 300))
                                      FILTER (WHERE m.event_type = 'http_anomaly'
                                                AND EXISTS (SELECT 1 FROM unnest(p_path_patterns) AS pat
                                                             WHERE (m.payload ->> 'path') ~* pat)))
      INTO result
      FROM m;
    RETURN result;
END
$$;

REVOKE ALL ON FUNCTION clawforge_assessment_shape(UUID, TEXT[]) FROM PUBLIC;
