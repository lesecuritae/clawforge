-- Explicit single-operator approval profile (opt-in, deployment-configured, default OFF).
--
-- The default stays multi-person: high/critical actions need distinct humans (approval_policies, unchanged). A sole
-- owner can opt in by an OWNER-ROLE change of the one-row table below (scripts/ops/set-approval-profile.sql). The mode
-- is never a request field and no runtime role can write the table; every runtime role reads it only through
-- clawforge_approval_profile(), which fails closed to multi_person when the row is missing.
--
-- In the profile, for the listed incident-source firewall actions ONLY (quarantine and every other action are not
-- listable, by CHECK), a request is created with required_approvals = 1 and a hashed context that names the profile and
-- the one designated operator account. That operator then confirms through a separate operation whose approval row has
-- approval_mode = 'single_operator_confirmation'; the database accepts it only while the profile is still active, for
-- exactly that account, action, context hash and unexpired window. A request that carries the profile marker refuses
-- ordinary distinct-person approvals (so nobody else can quietly satisfy it) and a lowered requirement without the
-- marker and an active profile is refused at INSERT, so a direct database path cannot bypass the policy.
CREATE TABLE IF NOT EXISTS approval_profile (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    mode TEXT NOT NULL DEFAULT 'multi_person' CHECK (mode IN ('multi_person', 'single_operator')),
    operator_user_id UUID REFERENCES admin_users(id) ON DELETE RESTRICT,
    allowed_actions TEXT[] NOT NULL DEFAULT '{}'
        CHECK (allowed_actions <@ ARRAY['nftables.block_incident_source', 'haproxy.block_incident_source',
                                        'firewall.block_incident_source', 'haproxy_ratelimit.block_incident_source']::TEXT[]),
    note TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (mode = 'multi_person' OR (operator_user_id IS NOT NULL AND cardinality(allowed_actions) >= 1))
);
INSERT INTO approval_profile (singleton, mode) VALUES (TRUE, 'multi_person') ON CONFLICT (singleton) DO NOTHING;
REVOKE ALL ON TABLE approval_profile FROM PUBLIC;

CREATE OR REPLACE FUNCTION clawforge_approval_profile()
RETURNS TABLE (mode TEXT, operator_user_id UUID, allowed_actions TEXT[])
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT p.mode, p.operator_user_id, p.allowed_actions
      FROM approval_profile p
     WHERE p.singleton AND p.mode = 'single_operator'
       AND EXISTS (SELECT 1 FROM admin_users u WHERE u.id = p.operator_user_id AND u.enabled AND u.role = 'Administrator')
    UNION ALL
    SELECT 'multi_person', NULL::UUID, '{}'::TEXT[]
     WHERE NOT EXISTS (
        SELECT 1 FROM approval_profile p
         WHERE p.singleton AND p.mode = 'single_operator'
           AND EXISTS (SELECT 1 FROM admin_users u WHERE u.id = p.operator_user_id AND u.enabled AND u.role = 'Administrator'))
$$;
REVOKE ALL ON FUNCTION clawforge_approval_profile() FROM PUBLIC;

CREATE OR REPLACE FUNCTION clawforge_audit_approval_profile()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO audit_events (actor, action, resource, details)
    VALUES ('db-owner', 'approval_profile_changed', 'approval_profile',
            jsonb_build_object('mode', NEW.mode, 'operator_user_id', NEW.operator_user_id,
                               'allowed_actions', NEW.allowed_actions, 'previous_mode', OLD.mode));
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS approval_profile_audit ON approval_profile;
CREATE TRIGGER approval_profile_audit BEFORE UPDATE ON approval_profile
FOR EACH ROW EXECUTE FUNCTION clawforge_audit_approval_profile();

ALTER TABLE execution_approvals
    ADD COLUMN IF NOT EXISTS approval_mode TEXT NOT NULL DEFAULT 'distinct_person'
        CHECK (approval_mode IN ('distinct_person', 'single_operator_confirmation'));

CREATE OR REPLACE FUNCTION clawforge_validate_execution_approval()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    request_row execution_requests%ROWTYPE;
    approver_role TEXT;
    approver_enabled BOOLEAN;
    approver_username TEXT;
    prof RECORD;
    action_name TEXT;
    profile_marked BOOLEAN;
BEGIN
    SELECT * INTO request_row
      FROM execution_requests
     WHERE id = NEW.execution_id
     FOR UPDATE;
    IF NOT FOUND OR request_row.status <> 'waiting_approval' THEN
        RAISE EXCEPTION 'execution is not waiting for approval';
    END IF;
    IF request_row.requested_by_id IS NULL THEN
        RAISE EXCEPTION 'execution requester cannot approve the request';
    END IF;
    IF request_row.approval_expires_at IS NULL OR request_row.approval_expires_at <= NOW() THEN
        RAISE EXCEPTION 'execution approval window expired';
    END IF;
    IF request_row.approval_context_hash IS NULL
       OR request_row.approval_context_hash <> NEW.context_hash THEN
        RAISE EXCEPTION 'execution approval context mismatch';
    END IF;
    SELECT role, enabled, username INTO approver_role, approver_enabled, approver_username
      FROM admin_users
     WHERE id = NEW.approver_id;
    IF NOT FOUND OR NOT approver_enabled
       OR approver_role NOT IN ('Administrator', 'Approver') THEN
        RAISE EXCEPTION 'identity is not an active approver';
    END IF;
    IF approver_username <> NEW.approver_name THEN
        RAISE EXCEPTION 'approver identity does not match its name';
    END IF;

    profile_marked := COALESCE(request_row.approval_context -> 'approval_profile' ->> 'mode' = 'single_operator', FALSE);
    IF NEW.approval_mode = 'single_operator_confirmation' THEN
        SELECT * INTO prof FROM clawforge_approval_profile();
        SELECT a.name INTO action_name FROM actions a WHERE a.id = request_row.action_id;
        IF prof.mode IS DISTINCT FROM 'single_operator' OR NOT profile_marked
           OR NEW.approver_id IS DISTINCT FROM prof.operator_user_id
           OR request_row.approval_context -> 'approval_profile' ->> 'operator_user_id' IS DISTINCT FROM prof.operator_user_id::TEXT
           OR action_name IS NULL OR NOT (action_name = ANY (prof.allowed_actions))
           OR request_row.required_approvals <> 1
           OR approver_role <> 'Administrator' THEN
            RAISE EXCEPTION 'single-operator confirmation is not allowed here';
        END IF;
        RETURN NEW;
    END IF;

    IF profile_marked THEN
        RAISE EXCEPTION 'this request belongs to the single-operator profile and accepts only the operator confirmation';
    END IF;
    IF request_row.requested_by_id = NEW.approver_id THEN
        RAISE EXCEPTION 'execution requester cannot approve the request';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION clawforge_validate_execution_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    matching_approvals INTEGER;
    prof RECORD;
    action_name TEXT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status NOT IN ('pending', 'waiting_approval') THEN
            RAISE EXCEPTION 'new execution must start pending or waiting for approval';
        END IF;
        IF NEW.status = 'waiting_approval' AND (
            NEW.requested_by_id IS NULL
            OR NEW.required_approvals < 1
            OR NEW.approval_expires_at IS NULL
            OR NEW.approval_expires_at <= NOW()
            OR NEW.approval_context_hash IS NULL
        ) THEN
            RAISE EXCEPTION 'new approval-gated execution is missing its approval context';
        END IF;
        IF NEW.status = 'pending' AND NEW.required_approvals <> 0 THEN
            RAISE EXCEPTION 'pending execution cannot carry approval requirements';
        END IF;
        -- An approval-gated request may carry FEWER approvals than its risk level's policy only inside the
        -- explicit single-operator profile, for an action that profile lists, naming the profile's operator.
        IF NEW.status = 'waiting_approval' AND NEW.required_approvals < COALESCE((
                SELECT p.required_approvals FROM actions a JOIN approval_policies p ON p.risk_level = a.risk_level
                 WHERE a.id = NEW.action_id), 1) THEN
            SELECT * INTO prof FROM clawforge_approval_profile();
            SELECT name INTO action_name FROM actions WHERE id = NEW.action_id;
            IF prof.mode IS DISTINCT FROM 'single_operator'
               OR action_name IS NULL OR NOT (action_name = ANY (prof.allowed_actions))
               OR NEW.required_approvals <> 1
               OR NEW.approval_context -> 'approval_profile' ->> 'mode' IS DISTINCT FROM 'single_operator'
               OR NEW.approval_context -> 'approval_profile' ->> 'operator_user_id' IS DISTINCT FROM prof.operator_user_id::TEXT THEN
                RAISE EXCEPTION 'fewer approvals than the risk policy requires are only allowed in the single-operator profile';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.action_id IS DISTINCT FROM NEW.action_id
       OR OLD.workflow_run_id IS DISTINCT FROM NEW.workflow_run_id
       OR OLD.decision_id IS DISTINCT FROM NEW.decision_id
       OR OLD.requested_by IS DISTINCT FROM NEW.requested_by
       OR OLD.requested_by_id IS DISTINCT FROM NEW.requested_by_id
       OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR OLD.max_retries IS DISTINCT FROM NEW.max_retries
       OR OLD.timeout_seconds IS DISTINCT FROM NEW.timeout_seconds
       OR OLD.required_approvals IS DISTINCT FROM NEW.required_approvals
       OR OLD.approval_expires_at IS DISTINCT FROM NEW.approval_expires_at
       OR OLD.approval_context IS DISTINCT FROM NEW.approval_context
       OR OLD.approval_context_hash IS DISTINCT FROM NEW.approval_context_hash THEN
        RAISE EXCEPTION 'execution approval context is immutable';
    END IF;

    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.status = 'waiting_approval' AND NEW.status IN ('approved', 'cancelled'))
        OR (OLD.status = 'pending' AND NEW.status IN ('queued', 'starting', 'cancelled'))
        OR (OLD.status = 'approved' AND NEW.status IN ('queued', 'starting', 'cancelled'))
        OR (OLD.status = 'queued' AND NEW.status IN ('starting', 'cancelled'))
        OR (OLD.status = 'starting' AND NEW.status IN ('running', 'queued', 'failed', 'timeout', 'rollback_required', 'cancelled'))
        OR (OLD.status = 'running' AND NEW.status IN ('success', 'completed', 'queued', 'failed', 'timeout', 'rollback_required', 'cancelled'))
        OR (OLD.status = 'failed' AND NEW.status = 'queued'
            AND NEW.retry_count = OLD.retry_count + 1
            AND NEW.retry_count <= NEW.max_retries)
        OR (OLD.status = 'rollback_required' AND NEW.status = 'cancelled')
    ) THEN
        RAISE EXCEPTION 'invalid execution status transition: % -> %', OLD.status, NEW.status;
    END IF;

    IF NEW.status = 'approved' THEN
        IF OLD.required_approvals < 1
           OR OLD.approval_context_hash IS NULL
           OR OLD.approval_expires_at IS NULL
           OR OLD.approval_expires_at <= NOW() THEN
            RAISE EXCEPTION 'execution approval requirements are not valid';
        END IF;
        SELECT COUNT(*)::INTEGER INTO matching_approvals
          FROM execution_approvals
         WHERE execution_id = OLD.id
           AND context_hash = OLD.approval_context_hash;
        IF matching_approvals < OLD.required_approvals THEN
            RAISE EXCEPTION 'execution requires % distinct approvals, found %',
                OLD.required_approvals, matching_approvals;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

