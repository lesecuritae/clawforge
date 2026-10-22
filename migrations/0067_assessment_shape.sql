-- Attack shape of one assessment, as COUNTS only. The policy-engine role has no access to the
-- events table (payloads carry usernames and request paths); this function derives two
-- behaviour measures that a plain event count cannot express and returns numbers, never values:
--   distinct_usernames  how many different account names the failed logins tried
--                       (a handful of valid accounts = users behind a NAT; dozens = enumeration)
--   signature_paths     how many distinct request paths match one of the supplied POSIX
--                       expressions (the caller passes expressions for paths no legitimate
--                       client requests, e.g. /.env, /.git/config, /.aws/credentials)
-- Members are capped at 1000 events like every other bucket read.
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
