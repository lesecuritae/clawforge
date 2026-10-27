-- Policy -> execution bridge: honour the explicit single-operator profile in `propose` mode.
--
-- The plan function is the single place that derives a bridge request's approval context. In the trusted profile
-- (approval_profile, migration 0071) a proposal for a listed incident-source action carries required_approvals = 1 and the
-- profile marker (policy count and designated operator inside the hashed context), so the designated Administrator can
-- confirm it with the separate operator confirmation. Default deployments, unlisted actions, `simulate` and `automatic`
-- modes are unchanged; the insert guard of 0071 re-validates the marker against the CURRENT profile.
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
    prof RECORD;
    profile_json JSONB := NULL;
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
        -- Explicit single-operator profile (migration 0071): for the actions it lists, ONE confirmation by the designated
        -- operator replaces the policy's count. Everything else in this plan (evidence, intel, routing, budgets, requester)
        -- is judged exactly as before; the lowering is recorded in the hashed context.
        IF approvals > 1 THEN
            SELECT * INTO prof FROM clawforge_approval_profile();
            IF prof.mode = 'single_operator' AND p_action_name = ANY (prof.allowed_actions) THEN
                profile_json := jsonb_build_object('mode', 'single_operator', 'operator_user_id', prof.operator_user_id,
                                                   'policy_required_approvals', approvals);
                approvals := 1;
            END IF;
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
                'bgp_anomaly', si.bgp_anomaly) ELSE NULL END))
        || CASE WHEN profile_json IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('approval_profile', profile_json) END, existing;
END;
$$;

REVOKE ALL ON FUNCTION clawforge_policy_bridge_plan(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN, INTEGER) FROM PUBLIC;
