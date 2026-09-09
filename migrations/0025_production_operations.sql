-- Production maturity metadata. Productive destructive execution remains
-- disabled; these tables make the policy and recovery boundaries explicit.
ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0);
ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS max_retries INTEGER NOT NULL DEFAULT 3 CHECK (max_retries BETWEEN 0 AND 20);
ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS timeout_seconds INTEGER NOT NULL DEFAULT 60 CHECK (timeout_seconds BETWEEN 1 AND 3600);
ALTER TABLE execution_requests ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS execution_requests_idempotency_idx ON execution_requests(idempotency_key) WHERE idempotency_key IS NOT NULL;
ALTER TABLE execution_requests DROP CONSTRAINT IF EXISTS execution_requests_status_check;
ALTER TABLE execution_requests ADD CONSTRAINT execution_requests_status_check CHECK (status IN ('pending','queued','waiting_approval','approved','starting','running','success','completed','failed','timeout','rollback_required','cancelled'));

CREATE TABLE IF NOT EXISTS connector_permissions (
    connector_id UUID NOT NULL REFERENCES connector_registry(id) ON DELETE CASCADE,
    permission TEXT NOT NULL CHECK (permission IN ('read','execute','destructive')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, permission)
);
INSERT INTO connector_permissions (connector_id,permission,enabled)
SELECT id,'read',TRUE FROM connector_registry ON CONFLICT DO NOTHING;
INSERT INTO connector_permissions (connector_id,permission,enabled)
SELECT id,'execute',FALSE FROM connector_registry ON CONFLICT DO NOTHING;
INSERT INTO connector_permissions (connector_id,permission,enabled)
SELECT id,'destructive',FALSE FROM connector_registry ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS approval_policies (
    risk_level TEXT PRIMARY KEY CHECK (risk_level IN ('info','low','medium','high','critical')),
    required_approvals INTEGER NOT NULL CHECK (required_approvals BETWEEN 0 AND 10),
    approval_timeout INTEGER NOT NULL CHECK (approval_timeout BETWEEN 60 AND 2592000),
    escalation_rule TEXT NOT NULL DEFAULT 'operator_review'
);
INSERT INTO approval_policies VALUES
 ('info',0,86400,'operator_review'),('low',1,86400,'operator_review'),
 ('medium',1,43200,'operator_review'),('high',2,21600,'two_operators'),
 ('critical',2,3600,'two_person_time_window')
ON CONFLICT (risk_level) DO UPDATE SET required_approvals=EXCLUDED.required_approvals,approval_timeout=EXCLUDED.approval_timeout,escalation_rule=EXCLUDED.escalation_rule;

CREATE TABLE IF NOT EXISTS execution_recovery (
    id UUID PRIMARY KEY,
    execution_id UUID NOT NULL REFERENCES execution_requests(id) ON DELETE CASCADE,
    rollback_action TEXT NOT NULL CHECK (char_length(rollback_action) BETWEEN 1 AND 160),
    rollback_status TEXT NOT NULL DEFAULT 'not_required' CHECK (rollback_status IN ('not_required','pending','running','success','failed')),
    rollback_result TEXT CHECK (rollback_result IS NULL OR char_length(rollback_result) <= 4000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS execution_recovery_execution_idx ON execution_recovery(execution_id);

CREATE TABLE IF NOT EXISTS entity_relationships (
    id UUID PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source_type,source_id,relation_type,target_type,target_id)
);
CREATE INDEX IF NOT EXISTS entity_relationships_source_idx ON entity_relationships(source_type,source_id);
