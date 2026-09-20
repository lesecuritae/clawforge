-- Bind execution approvals to an immutable request snapshot and enforce the
-- execution state machine at the database boundary.
ALTER TABLE execution_requests
    ADD COLUMN IF NOT EXISTS requested_by_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS required_approvals INTEGER NOT NULL DEFAULT 0 CHECK (required_approvals BETWEEN 0 AND 10),
    ADD COLUMN IF NOT EXISTS approval_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approval_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS approval_context_hash TEXT CHECK (approval_context_hash IS NULL OR approval_context_hash ~ '^[0-9a-f]{64}$');

CREATE TABLE IF NOT EXISTS execution_approvals (
    id UUID PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES execution_requests(id) ON DELETE CASCADE,
    approver_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE RESTRICT,
    approver_name TEXT NOT NULL CHECK (char_length(approver_name) BETWEEN 1 AND 160),
    context_hash TEXT NOT NULL CHECK (context_hash ~ '^[0-9a-f]{64}$'),
    approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (execution_id, approver_id)
);
CREATE INDEX IF NOT EXISTS execution_approvals_execution_idx
    ON execution_approvals(execution_id, approved_at);

CREATE OR REPLACE FUNCTION clawforge_validate_execution_approval()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    request_row execution_requests%ROWTYPE;
    approver_role TEXT;
    approver_enabled BOOLEAN;
    approver_username TEXT;
BEGIN
    SELECT * INTO request_row
      FROM execution_requests
     WHERE id = NEW.execution_id
     FOR UPDATE;
    IF NOT FOUND OR request_row.status <> 'waiting_approval' THEN
        RAISE EXCEPTION 'execution is not waiting for approval';
    END IF;
    IF request_row.requested_by_id IS NULL OR request_row.requested_by_id = NEW.approver_id THEN
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
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS execution_approval_guard ON execution_approvals;
CREATE TRIGGER execution_approval_guard
BEFORE INSERT ON execution_approvals
FOR EACH ROW EXECUTE FUNCTION clawforge_validate_execution_approval();

CREATE OR REPLACE FUNCTION clawforge_forbid_execution_approval_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'execution approval records are immutable';
END;
$$;

DROP TRIGGER IF EXISTS execution_approval_immutable ON execution_approvals;
CREATE TRIGGER execution_approval_immutable
BEFORE UPDATE OR DELETE ON execution_approvals
FOR EACH ROW EXECUTE FUNCTION clawforge_forbid_execution_approval_mutation();

CREATE OR REPLACE FUNCTION clawforge_validate_execution_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    matching_approvals INTEGER;
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

DROP TRIGGER IF EXISTS execution_transition_guard ON execution_requests;
CREATE TRIGGER execution_transition_guard
BEFORE INSERT OR UPDATE ON execution_requests
FOR EACH ROW EXECUTE FUNCTION clawforge_validate_execution_transition();
