-- Controlled, auditable workflow preparation. Workflows never execute shell
-- commands or mutate external systems; approval only records authorization.
CREATE TABLE IF NOT EXISTS workflows (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 10000),
    category TEXT NOT NULL CHECK (char_length(category) BETWEEN 1 AND 128),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS workflow_steps (
    id UUID PRIMARY KEY,
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    step_order INTEGER NOT NULL CHECK (step_order > 0),
    type TEXT NOT NULL CHECK (type IN ('notification','analysis','approval','external_check','manual')),
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    required_approval BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workflow_id, step_order)
);

CREATE INDEX IF NOT EXISTS workflow_steps_workflow_order_idx
    ON workflow_steps (workflow_id, step_order);

CREATE TABLE IF NOT EXISTS workflow_runs (
    id UUID PRIMARY KEY,
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    decision_id UUID REFERENCES decisions(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','waiting_approval','completed','failed','cancelled')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    result JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS workflow_runs_workflow_time_idx
    ON workflow_runs (workflow_id, started_at DESC);
CREATE INDEX IF NOT EXISTS workflow_runs_status_idx
    ON workflow_runs (status, started_at DESC);
CREATE INDEX IF NOT EXISTS workflow_runs_decision_idx
    ON workflow_runs (decision_id, started_at DESC);

ALTER TABLE approvals ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES admin_users(id) ON DELETE SET NULL;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS comment TEXT CHECK (comment IS NULL OR char_length(comment) <= 10000);
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS decision_reason TEXT CHECK (decision_reason IS NULL OR char_length(decision_reason) <= 10000);

CREATE TABLE IF NOT EXISTS workflow_audit_log (
    id UUID PRIMARY KEY,
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    actor TEXT NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 160),
    action TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 160),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS workflow_audit_workflow_time_idx
    ON workflow_audit_log (workflow_id, timestamp DESC);

INSERT INTO workflows (id, name, description, category, enabled, metadata)
VALUES
    ('00000000-0000-4000-8000-000000000030', 'Security Incident Workflow', 'Prepare an approval-gated review and notification path for critical incidents.', 'incident', TRUE, '{"approval_required":true,"automatic_actions":false}'::jsonb),
    ('00000000-0000-4000-8000-000000000031', 'Provider Health Workflow', 'Prepare an approval-gated provider health review.', 'provider_health', TRUE, '{"approval_required":true,"automatic_actions":false}'::jsonb),
    ('00000000-0000-4000-8000-000000000032', 'Backup Monitoring Workflow', 'Prepare an approval-gated backup failure investigation.', 'backup', TRUE, '{"approval_required":true,"automatic_actions":false}'::jsonb)
ON CONFLICT (name) DO NOTHING;

INSERT INTO workflow_steps (id, workflow_id, name, step_order, type, configuration, required_approval)
VALUES
    ('00000000-0000-4000-8000-000000000040', '00000000-0000-4000-8000-000000000030', 'Review incident decision', 1, 'approval', '{"read_only":true}'::jsonb, TRUE),
    ('00000000-0000-4000-8000-000000000041', '00000000-0000-4000-8000-000000000030', 'Prepare notification', 2, 'notification', '{"prepared_only":true}'::jsonb, FALSE),
    ('00000000-0000-4000-8000-000000000042', '00000000-0000-4000-8000-000000000031', 'Review provider quality', 1, 'analysis', '{"read_only":true}'::jsonb, FALSE),
    ('00000000-0000-4000-8000-000000000043', '00000000-0000-4000-8000-000000000031', 'Approve provider recommendation', 2, 'approval', '{"read_only":true}'::jsonb, TRUE),
    ('00000000-0000-4000-8000-000000000044', '00000000-0000-4000-8000-000000000032', 'Check backup evidence', 1, 'external_check', '{"prepared_only":true}'::jsonb, FALSE),
    ('00000000-0000-4000-8000-000000000045', '00000000-0000-4000-8000-000000000032', 'Approve notification', 2, 'approval', '{"read_only":true}'::jsonb, TRUE)
ON CONFLICT (id) DO NOTHING;
