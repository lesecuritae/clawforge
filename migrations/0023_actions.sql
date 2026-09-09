-- Controlled operations registry. Actions are disabled by default and are
-- only metadata until an administrator creates an execution request.
ALTER TABLE connector_capabilities ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'read';
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'connector_capabilities_mode_check') THEN
        ALTER TABLE connector_capabilities ADD CONSTRAINT connector_capabilities_mode_check CHECK (mode IN ('read','execute'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS actions (
    id UUID PRIMARY KEY,
    connector_id UUID REFERENCES connector_registry(id) ON DELETE SET NULL,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    type TEXT NOT NULL CHECK (type IN ('connector_action','backup')),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 4000),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('info','low','medium','high','critical')),
    required_scope TEXT NOT NULL CHECK (required_scope LIKE 'agent:%'),
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS actions_connector_idx ON actions (connector_id, enabled);

INSERT INTO connector_capabilities (connector_id, capability, read_only, mode)
VALUES
 ('00000000-0000-4000-8000-000000000050','container.restart',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000050','container.pull',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000051','repository.workflow_retry',FALSE,'execute')
ON CONFLICT (connector_id, capability) DO UPDATE SET read_only=FALSE, mode='execute';

INSERT INTO actions (id,connector_id,name,type,description,risk_level,required_scope,requires_approval,enabled)
VALUES
 ('00000000-0000-4000-8000-000000000060','00000000-0000-4000-8000-000000000050','docker.restart_container','connector_action','Prepare a container restart request; execution is disabled in v0.9.0.','medium','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000061','00000000-0000-4000-8000-000000000050','docker.pull_image','connector_action','Prepare an image pull request; execution is disabled in v0.9.0.','high','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000062',NULL,'backup.start','backup','Prepare a backup request for an operator; no command is executed.','low','agent:action:read',FALSE,FALSE),
 ('00000000-0000-4000-8000-000000000063','00000000-0000-4000-8000-000000000051','github.retry_workflow','connector_action','Prepare a workflow retry request; execution is disabled in v0.9.0.','medium','agent:action:read',TRUE,FALSE)
ON CONFLICT (id) DO UPDATE SET description=EXCLUDED.description, updated_at=NOW();
