-- Retention must not erase the evidence behind a REAL execution request.
--
-- The worker deletes security assessments (and their policy decisions) that were never promoted to an
-- incident once they are past the retention window. A request created from a decision - the bridge in
-- `propose` or `automatic` mode, i.e. not simulation-only - keeps only the decision's id, policy
-- version, assessment id and evidence hash in its approval context; the decision row carries the
-- evidence snapshot (counts, shape, basis). Deleting that row would leave a real block whose reason can
-- no longer be reconstructed. Simulation-only requests (a Go-Away challenge is simulated for every
-- challenge decision, ~150 a day) are deliberately NOT protected: protecting them would defeat retention.
--
-- The worker role cannot read `execution_requests` (least privilege), so the check lives in a narrow
-- SECURITY DEFINER function that only deletes what the previous worker statement deleted, minus the
-- protected assessments (execution_requests.decision_id points at a different decision table and is not
-- used by the bridge, so only the two context references count). Additive: the previous image keeps working with its own statements.
CREATE OR REPLACE FUNCTION clawforge_delete_expired_security_assessments(p_older_than TIMESTAMPTZ)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    doomed UUID[];
    removed BIGINT;
BEGIN
    SELECT COALESCE(array_agg(a.id), ARRAY[]::UUID[]) INTO doomed
      FROM security_assessments a
     WHERE a.incident_id IS NULL
       AND a.last_seen < p_older_than
       AND NOT EXISTS (
            SELECT 1
              FROM security_policy_decisions d
              JOIN execution_requests r
                ON r.approval_context -> 'policy_bridge' ->> 'security_policy_decision_id' = d.id::TEXT
                OR r.approval_context ->> 'security_policy_decision_id' = d.id::TEXT
             WHERE d.assessment_id = a.id
               AND COALESCE((r.approval_context -> 'target' ->> 'simulation_only')::BOOLEAN, FALSE) = FALSE
               AND COALESCE((r.approval_context ->> 'simulation_only')::BOOLEAN, FALSE) = FALSE);
    DELETE FROM security_policy_decisions WHERE assessment_id = ANY (doomed);
    DELETE FROM security_assessments WHERE id = ANY (doomed);
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END
$$;

REVOKE ALL ON FUNCTION clawforge_delete_expired_security_assessments(TIMESTAMPTZ) FROM PUBLIC;
