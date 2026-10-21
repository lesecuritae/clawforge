-- Policy -> execution bridge (roadmap 7C), database side.
--
-- Turns a persisted Block / RateLimit shadow decision into one execution
-- request, under conditions the database itself re-derives. The policy-engine
-- role has no INSERT on execution_requests; these two SECURITY DEFINER
-- functions are its only path. Nothing here runs unless the policy engine is
-- configured to call it (default: off) and the target ACTION row is in the
-- state the chosen mode requires:
--
--   simulate  action disabled; request is pending and simulation_only, so the
--             executor can only produce a dry-run receipt (like the Go-Away
--             shadow challenge).
--   propose   action enabled AND requires approval; the request waits for the
--             action's approval policy (critical: two distinct approvers that
--             are not the requester). Requester = a configured Operator account.
--   automatic action enabled AND NOT requires_approval; the request is pending.
--             The executor's own gates (DRY_RUN, live authorization, TTL
--             ceiling, budgets, never-block list) still decide whether anything
--             happens. Requires an 'automatic' policy, a named rule, threat-
--             intel corroboration, a fresh healthy executor and no unresolved
--             firewall generations.
--
-- Because the approval hash is computed in Rust over the stored JSONB, Rust
-- obtains the context from clawforge_policy_bridge_plan(), hashes it, and the
-- enqueue function re-derives the same context and refuses any difference.

CREATE OR REPLACE FUNCTION clawforge_policy_bridge_plan(
    p_decision_id UUID,
    p_mode TEXT,
    p_action_name TEXT,
    p_ttl_seconds INTEGER,
    p_requester_id UUID,
    p_rule_id TEXT,
    p_max_evidence_age_seconds INTEGER,
    p_require_threat_intel BOOLEAN
) RETURNS TABLE (reason TEXT, context JSONB)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    d security_policy_decisions%ROWTYPE;
    p security_policies%ROWTYPE;
    s security_assessments%ROWTYPE;
    a actions%ROWTYPE;
    approvals INTEGER := 0;
    approval_timeout INTEGER;
    requester_ok BOOLEAN;
    needs_intel BOOLEAN;
    target JSONB;
BEGIN
    IF p_mode NOT IN ('simulate', 'propose', 'automatic') THEN
        RETURN QUERY SELECT 'mode_invalid'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF p_action_name NOT IN ('nftables.block_incident_source', 'haproxy.block_incident_source',
                             'firewall.block_incident_source',
                             'haproxy_ratelimit.block_incident_source') THEN
        RETURN QUERY SELECT 'action_not_allowed'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 86400
       OR p_max_evidence_age_seconds IS NULL OR p_max_evidence_age_seconds < 1 THEN
        RETURN QUERY SELECT 'parameters_invalid'::TEXT, NULL::JSONB; RETURN;
    END IF;

    SELECT * INTO d FROM security_policy_decisions WHERE id = p_decision_id;
    IF NOT FOUND OR d.is_shadow IS NOT TRUE THEN
        RETURN QUERY SELECT 'decision_not_found'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF d.decision IS DISTINCT FROM (CASE WHEN p_action_name = 'haproxy_ratelimit.block_incident_source'
                                         THEN 'rate_limit' ELSE 'block' END) THEN
        RETURN QUERY SELECT 'decision_does_not_match_action'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF d.corroborated IS NOT TRUE OR d.evidence_sources < 2 THEN
        RETURN QUERY SELECT 'not_corroborated'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF d.updated_at < NOW() - make_interval(secs => p_max_evidence_age_seconds) THEN
        RETURN QUERY SELECT 'decision_stale'::TEXT, NULL::JSONB; RETURN;
    END IF;

    SELECT * INTO p FROM security_policies WHERE id = d.policy_id AND version = d.policy_version;
    IF NOT FOUND OR p.status <> 'active' OR p.valid_from > NOW()
       OR (p.valid_until IS NOT NULL AND p.valid_until <= NOW()) THEN
        RETURN QUERY SELECT 'policy_inactive'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF (p_mode = 'propose' AND p.class NOT IN ('approval', 'automatic'))
       OR (p_mode = 'automatic' AND p.class <> 'automatic') THEN
        RETURN QUERY SELECT 'policy_class_insufficient'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF p_rule_id IS NULL AND p_mode = 'automatic' THEN
        RETURN QUERY SELECT 'rule_required'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF p_rule_id IS NOT NULL AND p.rule_id <> p_rule_id THEN
        RETURN QUERY SELECT 'rule_mismatch'::TEXT, NULL::JSONB; RETURN;
    END IF;

    SELECT * INTO s FROM security_assessments WHERE id = d.assessment_id;
    IF NOT FOUND OR s.resource NOT LIKE 'ip-pseudonym:%'
       OR char_length(s.resource) <= char_length('ip-pseudonym:') THEN
        RETURN QUERY SELECT 'resource_not_pseudonym'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF s.last_seen < NOW() - make_interval(secs => p_max_evidence_age_seconds) THEN
        RETURN QUERY SELECT 'assessment_stale'::TEXT, NULL::JSONB; RETURN;
    END IF;
    needs_intel := COALESCE(p_require_threat_intel, TRUE) OR p_mode = 'automatic';
    IF needs_intel AND s.threat_intel_corroborated IS NOT TRUE THEN
        RETURN QUERY SELECT 'threat_intel_required'::TEXT, NULL::JSONB; RETURN;
    END IF;
    IF p_mode <> 'simulate' AND NOT EXISTS (
        SELECT 1 FROM security_ip_resolutions r
         WHERE r.pseudonym = s.resource AND r.expires_at > NOW()
           AND masklen(r.raw_ip) = CASE family(r.raw_ip) WHEN 4 THEN 32 ELSE 128 END) THEN
        RETURN QUERY SELECT 'resolution_missing'::TEXT, NULL::JSONB; RETURN;
    END IF;

    SELECT * INTO a FROM actions WHERE name = p_action_name;
    IF NOT FOUND
       OR (p_mode = 'simulate' AND a.enabled)
       OR (p_mode = 'propose' AND NOT (a.enabled AND a.requires_approval))
       OR (p_mode = 'automatic' AND NOT (a.enabled AND NOT a.requires_approval)) THEN
        RETURN QUERY SELECT 'action_state_mismatch'::TEXT, NULL::JSONB; RETURN;
    END IF;

    IF p_mode = 'propose' THEN
        SELECT TRUE INTO requester_ok FROM admin_users
         WHERE id = p_requester_id AND enabled AND role = 'Operator';
        IF requester_ok IS NOT TRUE THEN
            RETURN QUERY SELECT 'requester_invalid'::TEXT, NULL::JSONB; RETURN;
        END IF;
        SELECT GREATEST(1, ap.required_approvals), ap.approval_timeout
          INTO approvals, approval_timeout
          FROM approval_policies ap WHERE ap.risk_level = a.risk_level;
        IF approvals IS NULL OR approval_timeout IS NULL THEN
            RETURN QUERY SELECT 'approval_policy_missing'::TEXT, NULL::JSONB; RETURN;
        END IF;
    ELSIF p_requester_id IS NOT NULL THEN
        RETURN QUERY SELECT 'requester_not_allowed'::TEXT, NULL::JSONB; RETURN;
    END IF;

    target := jsonb_build_object('kind', 'incident_source', 'pseudonym', s.resource,
                                 'ttl_seconds', p_ttl_seconds);
    IF p_mode = 'simulate' THEN
        target := target || jsonb_build_object('simulation_only', TRUE);
    END IF;

    RETURN QUERY SELECT NULL::TEXT, jsonb_build_object(
        'version', 1,
        'action_id', a.id,
        'action_name', a.name,
        'risk_level', a.risk_level,
        'requires_approval', p_mode = 'propose',
        'required_approvals', approvals,
        'approval_timeout_seconds', approval_timeout,
        'max_retries', 0,
        'execution_timeout_seconds', 60,
        'workflow_run_id', NULL,
        'decision_id', NULL,
        'requested_by', 'policy-bridge',
        'requested_by_id', p_requester_id,
        'idempotency_key', 'policy-bridge:' || p_mode || ':' || d.id::TEXT,
        'target', target,
        'policy_bridge', jsonb_build_object(
            'version', 1,
            'mode', p_mode,
            'security_policy_decision_id', d.id,
            'policy_id', p.id,
            'policy_version', p.version,
            'assessment_id', s.id,
            'rule_id', p.rule_id,
            'evidence_hash', d.evidence_hash));
END;
$$;

CREATE OR REPLACE FUNCTION clawforge_enqueue_policy_bridge_request(
    p_decision_id UUID,
    p_mode TEXT,
    p_action_name TEXT,
    p_ttl_seconds INTEGER,
    p_requester_id UUID,
    p_rule_id TEXT,
    p_max_evidence_age_seconds INTEGER,
    p_require_threat_intel BOOLEAN,
    p_max_per_window INTEGER,
    p_window_seconds INTEGER,
    p_context JSONB,
    p_context_hash TEXT
) RETURNS TABLE (outcome TEXT, request_id UUID)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    plan_reason TEXT;
    plan_context JSONB;
    existing UUID;
    new_id UUID := gen_random_uuid();
    action_row actions%ROWTYPE;
    key TEXT;
    audit_id BIGINT;
    details JSONB;
BEGIN
    IF p_max_per_window IS NULL OR p_max_per_window < 1 OR p_window_seconds IS NULL
       OR p_window_seconds < 1 OR p_context_hash IS NULL OR p_context_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN QUERY SELECT 'rejected:parameters_invalid'::TEXT, NULL::UUID; RETURN;
    END IF;

    SELECT pl.reason, pl.context INTO plan_reason, plan_context
      FROM clawforge_policy_bridge_plan(p_decision_id, p_mode, p_action_name, p_ttl_seconds,
               p_requester_id, p_rule_id, p_max_evidence_age_seconds, p_require_threat_intel) pl;
    IF plan_reason IS NOT NULL THEN
        RETURN QUERY SELECT 'rejected:' || plan_reason, NULL::UUID; RETURN;
    END IF;
    IF plan_context IS DISTINCT FROM p_context THEN
        RETURN QUERY SELECT 'rejected:context_changed'::TEXT, NULL::UUID; RETURN;
    END IF;
    key := plan_context ->> 'idempotency_key';

    -- Serialize budget, duplicate and health checks with the insert.
    PERFORM pg_advisory_xact_lock(hashtext('clawforge_policy_bridge'));

    SELECT id INTO existing FROM execution_requests WHERE idempotency_key = key;
    IF existing IS NOT NULL THEN
        RETURN QUERY SELECT 'duplicate'::TEXT, existing; RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM execution_requests e
                WHERE e.action_id = (plan_context ->> 'action_id')::UUID
                  AND e.approval_context -> 'target' ->> 'pseudonym' = plan_context -> 'target' ->> 'pseudonym'
                  AND e.status IN ('waiting_approval', 'approved', 'pending', 'queued', 'starting', 'running')) THEN
        RETURN QUERY SELECT 'rejected:target_already_active'::TEXT, NULL::UUID; RETURN;
    END IF;
    IF (SELECT count(*) FROM execution_requests
         WHERE requested_by = 'policy-bridge'
           AND created_at > NOW() - make_interval(secs => p_window_seconds)) >= p_max_per_window THEN
        RETURN QUERY SELECT 'rejected:budget_exhausted'::TEXT, NULL::UUID; RETURN;
    END IF;
    IF p_mode = 'automatic' THEN
        IF EXISTS (SELECT 1 FROM firewall_action_intents WHERE status IN ('prepared', 'recovery_required'))
           OR EXISTS (SELECT 1 FROM execution_requests WHERE status = 'rollback_required') THEN
            RETURN QUERY SELECT 'rejected:unresolved_firewall_state'::TEXT, NULL::UUID; RETURN;
        END IF;
        IF NOT EXISTS (SELECT 1 FROM runtime_status
                        WHERE component = 'executor' AND state = 'running'
                          AND last_heartbeat_at > NOW() - INTERVAL '5 minutes') THEN
            RETURN QUERY SELECT 'rejected:executor_not_healthy'::TEXT, NULL::UUID; RETURN;
        END IF;
    END IF;

    SELECT * INTO action_row FROM actions WHERE id = (plan_context ->> 'action_id')::UUID;
    INSERT INTO execution_requests
        (id, action_id, workflow_run_id, decision_id, requested_by, requested_by_id, status,
         idempotency_key, required_approvals, approval_expires_at, approval_context,
         approval_context_hash, max_retries, timeout_seconds)
    VALUES
        (new_id, action_row.id, NULL, NULL, 'policy-bridge', p_requester_id,
         CASE WHEN p_mode = 'propose' THEN 'waiting_approval' ELSE 'pending' END,
         key,
         COALESCE((plan_context ->> 'required_approvals')::INTEGER, 0),
         CASE WHEN p_mode = 'propose'
              THEN NOW() + make_interval(secs => (plan_context ->> 'approval_timeout_seconds')::INTEGER)
         END,
         plan_context, p_context_hash, 0, 60);

    details := jsonb_build_object('mode', p_mode, 'action_id', action_row.id,
                                  'decision_id', p_decision_id, 'context_hash', p_context_hash);
    INSERT INTO audit_events (actor, action, resource, details)
    VALUES ('policy-engine', 'policy_bridge_request_enqueued', new_id::TEXT, details)
    RETURNING id INTO audit_id;
    INSERT INTO audit_outbox (id, audit_event_id, event_type, resource, payload)
    VALUES (gen_random_uuid(), audit_id, 'policy_bridge_request_enqueued', new_id::TEXT, details);

    RETURN QUERY SELECT 'enqueued'::TEXT, new_id;
END;
$$;

REVOKE ALL ON FUNCTION clawforge_policy_bridge_plan(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN) FROM PUBLIC;
REVOKE ALL ON FUNCTION clawforge_enqueue_policy_bridge_request(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN, INTEGER, INTEGER, JSONB, TEXT) FROM PUBLIC;
