-- Policy -> execution bridge: judge reputation on the current source view.
--
-- 0060 required only the ingest-time boolean threat_intel_corroborated, which could
-- not see a later listing, a delisting or expiry, an ASN listing, or that a "hit"
-- came from a routing-context provider (see 0062). The plan now uses
-- clawforge_current_source_intel (0063): the address, or its origin ASN on an
-- ASN-DROP style list, must be listed by an unexpired indicator with at least
-- p_min_intel_confidence that was reconfirmed within p_max_evidence_age_seconds.
-- The approver sees which listing counted and the routing facts (prefix, origin
-- ASNs, RPKI summary, BGP-anomaly flag) in the immutable approval context. Routing
-- facts are shown, never counted.
--
-- The parameter list grows by one, so the old signatures are replaced.
DROP FUNCTION IF EXISTS clawforge_enqueue_policy_bridge_request(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN, INTEGER, INTEGER, JSONB, TEXT);
DROP FUNCTION IF EXISTS clawforge_policy_bridge_plan(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN);

CREATE OR REPLACE FUNCTION clawforge_policy_bridge_plan(
    p_decision_id UUID,
    p_mode TEXT,
    p_action_name TEXT,
    p_ttl_seconds INTEGER,
    p_requester_id UUID,
    p_rule_id TEXT,
    p_max_evidence_age_seconds INTEGER,
    p_require_threat_intel BOOLEAN,
    p_min_intel_confidence INTEGER
) RETURNS TABLE (reason TEXT, context JSONB, existing_request_id UUID)
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
    si RECORD;
    intel_basis TEXT;
    intel_ok BOOLEAN := FALSE;
    intel_source TEXT;
    intel_confidence INTEGER;
    target JSONB;
    existing UUID;
    request_key TEXT;
BEGIN
    IF p_mode NOT IN ('simulate', 'propose', 'automatic') THEN
        RETURN QUERY SELECT 'mode_invalid'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF p_action_name NOT IN ('nftables.block_incident_source', 'haproxy.block_incident_source',
                             'firewall.block_incident_source',
                             'haproxy_ratelimit.block_incident_source') THEN
        RETURN QUERY SELECT 'action_not_allowed'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 1 OR p_ttl_seconds > 86400
       OR p_max_evidence_age_seconds IS NULL OR p_max_evidence_age_seconds < 1
       OR p_max_evidence_age_seconds > 604800
       OR p_min_intel_confidence IS NULL OR p_min_intel_confidence < 1
       OR p_min_intel_confidence > 100 THEN
        RETURN QUERY SELECT 'parameters_invalid'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;

    SELECT * INTO d FROM security_policy_decisions WHERE id = p_decision_id;
    IF NOT FOUND OR d.is_shadow IS NOT TRUE THEN
        RETURN QUERY SELECT 'decision_not_found'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF d.decision IS DISTINCT FROM (CASE WHEN p_action_name = 'haproxy_ratelimit.block_incident_source'
                                         THEN 'rate_limit' ELSE 'block' END) THEN
        RETURN QUERY SELECT 'decision_does_not_match_action'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF d.corroborated IS NOT TRUE OR d.evidence_sources < 2 THEN
        RETURN QUERY SELECT 'not_corroborated'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF d.updated_at < NOW() - make_interval(secs => p_max_evidence_age_seconds) THEN
        RETURN QUERY SELECT 'decision_not_reconfirmed'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;

    SELECT * INTO p FROM security_policies WHERE id = d.policy_id AND version = d.policy_version;
    IF NOT FOUND OR p.status <> 'active' OR p.valid_from > NOW()
       OR (p.valid_until IS NOT NULL AND p.valid_until <= NOW()) THEN
        RETURN QUERY SELECT 'policy_inactive'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF (p_mode = 'propose' AND p.class NOT IN ('approval', 'automatic'))
       OR (p_mode = 'automatic' AND p.class <> 'automatic') THEN
        RETURN QUERY SELECT 'policy_class_insufficient'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF p_rule_id IS NULL AND p_mode = 'automatic' THEN
        RETURN QUERY SELECT 'rule_required'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF p_rule_id IS NOT NULL AND p.rule_id <> p_rule_id THEN
        RETURN QUERY SELECT 'rule_mismatch'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;

    SELECT * INTO s FROM security_assessments WHERE id = d.assessment_id;
    IF NOT FOUND OR s.resource NOT LIKE 'ip-pseudonym:%'
       OR char_length(s.resource) <= char_length('ip-pseudonym:') THEN
        RETURN QUERY SELECT 'resource_not_pseudonym'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    -- The decisions table is writable by the policy-engine role, so re-check what
    -- the database can: the assessment must belong to the policy's rule and meet
    -- its minimum severity. (A decision cannot be re-run through decide() here.)
    IF s.rule_id <> p.rule_id THEN
        RETURN QUERY SELECT 'assessment_rule_mismatch'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF (CASE s.severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END)
       < (CASE p.min_severity WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END) THEN
        RETURN QUERY SELECT 'severity_below_policy'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    IF s.last_seen < NOW() - make_interval(secs => p_max_evidence_age_seconds) THEN
        RETURN QUERY SELECT 'assessment_stale'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;
    needs_intel := COALESCE(p_require_threat_intel, TRUE) OR p_mode = 'automatic';
    IF p_mode <> 'simulate' AND NOT EXISTS (
        SELECT 1 FROM security_ip_resolutions r
         WHERE r.pseudonym = s.resource AND r.expires_at > NOW()
           AND masklen(r.raw_ip) = CASE family(r.raw_ip) WHEN 4 THEN 32 ELSE 128 END) THEN
        RETURN QUERY SELECT 'resolution_missing'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;

    -- Reputation is judged on the CURRENT view of the source (migration 0063): the
    -- address or its origin ASN must be listed by an unexpired reputation indicator
    -- that is confident and recently reconfirmed. A listing that has since been
    -- removed, or expired, does not count; routing facts alone never do. Without any
    -- current view only a simulation may fall back to the ingest-time snapshot, and
    -- only from a real reputation source.
    SELECT * INTO si FROM clawforge_current_source_intel(s.resource);
    IF si.resolved THEN
        IF si.ip_listed AND si.ip_confidence >= p_min_intel_confidence
           AND si.ip_last_seen >= NOW() - make_interval(secs => p_max_evidence_age_seconds) THEN
            intel_basis := 'ip'; intel_ok := TRUE;
            intel_source := si.ip_source; intel_confidence := si.ip_confidence;
        ELSIF si.asn_listed AND si.asn_confidence >= p_min_intel_confidence
           AND si.asn_last_seen >= NOW() - make_interval(secs => p_max_evidence_age_seconds) THEN
            intel_basis := 'asn'; intel_ok := TRUE;
            intel_source := si.asn_source; intel_confidence := si.asn_confidence;
        END IF;
    ELSIF p_mode = 'simulate' AND s.threat_intel_corroborated IS TRUE
          AND s.threat_intel_source IS NOT NULL
          AND NOT (s.threat_intel_source = ANY(ARRAY['routeviews', 'ripe_ris', 'ripestat_asn',
                'hackertarget_asn', 'peeringdb', 'caida_as_rank', 'team_cymru', 'bgpstream',
                'bgpview_asn', 'rpki_validator']))
          AND s.threat_intel_confidence >= p_min_intel_confidence
          AND s.threat_intel_indicator_last_seen >= NOW() - make_interval(secs => p_max_evidence_age_seconds) THEN
        intel_basis := 'snapshot'; intel_ok := TRUE;
        intel_source := s.threat_intel_source; intel_confidence := s.threat_intel_confidence;
    END IF;
    IF needs_intel AND NOT intel_ok THEN
        RETURN QUERY SELECT 'threat_intel_required'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;

    SELECT * INTO a FROM actions WHERE name = p_action_name;
    IF NOT FOUND
       OR (p_mode = 'simulate' AND a.enabled)
       OR (p_mode = 'propose' AND NOT (a.enabled AND a.requires_approval))
       OR (p_mode = 'automatic' AND NOT (a.enabled AND NOT a.requires_approval)) THEN
        RETURN QUERY SELECT 'action_state_mismatch'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;

    IF p_mode = 'propose' THEN
        SELECT TRUE INTO requester_ok FROM admin_users
         WHERE id = p_requester_id AND enabled AND role = 'Operator';
        IF requester_ok IS NOT TRUE THEN
            RETURN QUERY SELECT 'requester_invalid'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
        END IF;
        SELECT GREATEST(1, ap.required_approvals), ap.approval_timeout
          INTO approvals, approval_timeout
          FROM approval_policies ap WHERE ap.risk_level = a.risk_level;
        IF approvals IS NULL OR approval_timeout IS NULL THEN
            RETURN QUERY SELECT 'approval_policy_missing'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
        END IF;
    ELSIF p_requester_id IS NOT NULL THEN
        RETURN QUERY SELECT 'requester_not_allowed'::TEXT, NULL::JSONB, NULL::UUID; RETURN;
    END IF;

    target := jsonb_build_object('kind', 'incident_source', 'pseudonym', s.resource,
                                 'ttl_seconds', p_ttl_seconds);
    IF p_mode = 'simulate' THEN
        target := target || jsonb_build_object('simulation_only', TRUE);
    END IF;

    request_key := 'policy-bridge:' || p_mode || ':' || d.id::TEXT;
    SELECT e.id INTO existing FROM execution_requests e WHERE e.idempotency_key = request_key;

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
        'idempotency_key', request_key,
        'target', target,
        'policy_bridge', jsonb_build_object(
            'version', 1,
            'mode', p_mode,
            'security_policy_decision_id', d.id,
            'policy_id', p.id,
            'policy_version', p.version,
            'assessment_id', s.id,
            'rule_id', p.rule_id,
            'evidence_hash', d.evidence_hash,
            'intel_required', needs_intel,
            'min_intel_confidence', p_min_intel_confidence,
            'max_evidence_age_seconds', p_max_evidence_age_seconds,
            'intel', CASE WHEN intel_ok THEN jsonb_build_object(
                'basis', intel_basis, 'source', intel_source, 'confidence', intel_confidence)
                ELSE NULL END,
            'routing', CASE WHEN si.resolved THEN jsonb_build_object(
                'context_status', si.context_status, 'prefix', si.prefix_text,
                'origin_asns', to_jsonb(si.origin_asns), 'rpki', si.rpki,
                'bgp_anomaly', si.bgp_anomaly) ELSE NULL END)), existing;
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
    p_min_intel_confidence INTEGER,
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
    simulated BOOLEAN := (p_mode = 'simulate');
BEGIN
    -- Hard database-side bounds: the caller's values are inputs, never the limit.
    -- (The executor's own apply budgets remain an independent backstop.)
    IF p_max_per_window IS NULL OR p_max_per_window < 1 OR p_max_per_window > 100
       OR p_window_seconds IS NULL OR p_window_seconds < 60 OR p_window_seconds > 86400
       OR p_context_hash IS NULL OR p_context_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN QUERY SELECT 'rejected:parameters_invalid'::TEXT, NULL::UUID; RETURN;
    END IF;

    -- Serialize bridge callers, then lock the rows the plan depends on so an
    -- operator kill switch (disable the action, retire the policy, disable the
    -- requester) waits for this transaction instead of racing the insert.
    PERFORM pg_advisory_xact_lock(hashtext('clawforge_policy_bridge'));
    PERFORM 1 FROM actions WHERE name = p_action_name FOR SHARE;
    PERFORM 1 FROM security_policy_decisions d
              JOIN security_policies pol ON pol.id = d.policy_id AND pol.version = d.policy_version
             WHERE d.id = p_decision_id FOR SHARE OF pol;
    IF p_requester_id IS NOT NULL THEN
        PERFORM 1 FROM admin_users WHERE id = p_requester_id FOR SHARE;
    END IF;

    SELECT pl.reason, pl.context INTO plan_reason, plan_context
      FROM clawforge_policy_bridge_plan(p_decision_id, p_mode, p_action_name, p_ttl_seconds,
               p_requester_id, p_rule_id, p_max_evidence_age_seconds, p_require_threat_intel, p_min_intel_confidence) pl;
    IF plan_reason IS NOT NULL THEN
        RETURN QUERY SELECT 'rejected:' || plan_reason, NULL::UUID; RETURN;
    END IF;
    IF plan_context IS DISTINCT FROM p_context THEN
        RETURN QUERY SELECT 'rejected:context_changed'::TEXT, NULL::UUID; RETURN;
    END IF;
    key := plan_context ->> 'idempotency_key';

    SELECT id INTO existing FROM execution_requests WHERE idempotency_key = key;
    IF existing IS NOT NULL THEN
        RETURN QUERY SELECT 'duplicate'::TEXT, existing; RETURN;
    END IF;
    -- A simulation never blocks, and is never counted against, live requests
    -- (and vice versa); everything else active on the target does, including a
    -- partially applied one awaiting rollback.
    IF EXISTS (SELECT 1 FROM execution_requests e
                WHERE e.action_id = (plan_context ->> 'action_id')::UUID
                  AND e.approval_context -> 'target' ->> 'pseudonym' = plan_context -> 'target' ->> 'pseudonym'
                  AND e.status IN ('waiting_approval', 'approved', 'pending', 'queued', 'starting',
                                   'running', 'rollback_required')
                  AND ((e.approval_context -> 'target' -> 'simulation_only') IS NOT DISTINCT FROM 'true'::jsonb) = simulated) THEN
        RETURN QUERY SELECT 'rejected:target_already_active'::TEXT, NULL::UUID; RETURN;
    END IF;
    IF (SELECT count(*) FROM execution_requests e
         WHERE e.requested_by = 'policy-bridge'
           AND e.created_at > NOW() - make_interval(secs => p_window_seconds)
           AND ((e.approval_context -> 'target' -> 'simulation_only') IS NOT DISTINCT FROM 'true'::jsonb) = simulated
       ) >= p_max_per_window THEN
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


REVOKE ALL ON FUNCTION clawforge_policy_bridge_plan(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION clawforge_enqueue_policy_bridge_request(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN, INTEGER, INTEGER, INTEGER, JSONB, TEXT) FROM PUBLIC;

-- Dispatch-time revalidation. A request created by the bridge that required
-- reputation evidence is released to the executor only while that evidence still
-- holds: the address (or its origin ASN) must still be listed, confidently and
-- recently, exactly as the approval context recorded. A listing removed between
-- approval and apply therefore cancels the apply (the executor refuses and nothing
-- reaches the host). Requests that are not bridge requests are unaffected.
CREATE OR REPLACE FUNCTION clawforge_resolve_incident_source_for_apply(p_execution_id UUID)
RETURNS TABLE (pseudonym TEXT, raw_ip TEXT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT r.pseudonym, host(r.raw_ip)
      FROM execution_requests e
      JOIN actions a ON a.id = e.action_id
      JOIN security_ip_resolutions r
        ON r.pseudonym = e.approval_context -> 'target' ->> 'pseudonym'
     WHERE e.id = p_execution_id
       AND e.status = 'starting'
       AND a.name IN ('nftables.block_incident_source',
                      'haproxy.block_incident_source',
                      'haproxy_ratelimit.block_incident_source',
                      'firewall.block_incident_source')
       AND e.approval_context -> 'target' ->> 'kind' = 'incident_source'
       AND (e.approval_context -> 'target' -> 'simulation_only') IS DISTINCT FROM 'true'::jsonb
       AND r.expires_at > NOW()
       AND masklen(r.raw_ip) = CASE family(r.raw_ip) WHEN 4 THEN 32 ELSE 128 END
       AND ( e.approval_context -> 'policy_bridge' IS NULL
          OR COALESCE((e.approval_context -> 'policy_bridge' ->> 'intel_required')::BOOLEAN, TRUE) IS FALSE
          OR EXISTS (
               SELECT 1 FROM clawforge_current_source_intel(r.pseudonym) si
                WHERE si.resolved
                  AND ( (si.ip_listed
                         AND si.ip_confidence >= (e.approval_context -> 'policy_bridge' ->> 'min_intel_confidence')::INTEGER
                         AND si.ip_last_seen >= NOW() - make_interval(
                               secs => (e.approval_context -> 'policy_bridge' ->> 'max_evidence_age_seconds')::INTEGER))
                     OR (si.asn_listed
                         AND si.asn_confidence >= (e.approval_context -> 'policy_bridge' ->> 'min_intel_confidence')::INTEGER
                         AND si.asn_last_seen >= NOW() - make_interval(
                               secs => (e.approval_context -> 'policy_bridge' ->> 'max_evidence_age_seconds')::INTEGER)))))
$$;
