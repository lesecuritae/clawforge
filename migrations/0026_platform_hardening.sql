-- v0.11 production hardening metadata.  Execution remains dry-run until a
-- separately reviewed connector action is enabled by policy.
CREATE TABLE IF NOT EXISTS execution_workers (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    status TEXT NOT NULL DEFAULT 'starting' CHECK (status IN ('starting','healthy','degraded','draining','stopped','failed')),
    capacity INTEGER NOT NULL DEFAULT 1 CHECK (capacity BETWEEN 1 AND 64),
    current_jobs INTEGER NOT NULL DEFAULT 0 CHECK (current_jobs >= 0),
    last_heartbeat_at TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 2000),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS execution_workers_health_idx ON execution_workers(status,last_heartbeat_at DESC);

CREATE TABLE IF NOT EXISTS execution_leases (
    id UUID PRIMARY KEY,
    execution_id UUID NOT NULL UNIQUE REFERENCES execution_requests(id) ON DELETE CASCADE,
    worker_id UUID NOT NULL REFERENCES execution_workers(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','released','expired')),
    leased_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts >= 1),
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 2000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS execution_leases_worker_idx ON execution_leases(worker_id,status,expires_at);
CREATE INDEX IF NOT EXISTS execution_leases_expiry_idx ON execution_leases(status,expires_at);

CREATE TABLE IF NOT EXISTS execution_metrics (
    id BIGSERIAL PRIMARY KEY,
    execution_id UUID REFERENCES execution_requests(id) ON DELETE SET NULL,
    worker_id UUID REFERENCES execution_workers(id) ON DELETE SET NULL,
    status TEXT NOT NULL CHECK (status IN ('success','failed','timeout','cancelled','dry_run')),
    duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS execution_metrics_recorded_idx ON execution_metrics(recorded_at DESC);

CREATE TABLE IF NOT EXISTS role_permissions (
    role TEXT NOT NULL CHECK (role IN ('Viewer','Operator','Approver','Administrator')),
    permission TEXT NOT NULL CHECK (permission IN ('read','approve','execute','manage')),
    PRIMARY KEY (role,permission)
);
INSERT INTO role_permissions(role,permission) VALUES
 ('Viewer','read'),('Operator','read'),('Operator','execute'),
 ('Approver','read'),('Approver','approve'),
 ('Administrator','read'),('Administrator','approve'),('Administrator','execute'),('Administrator','manage')
ON CONFLICT DO NOTHING;

ALTER TABLE admin_users DROP CONSTRAINT IF EXISTS admin_users_role_check;
ALTER TABLE admin_users ADD CONSTRAINT admin_users_role_check CHECK (role IN ('Administrator','Operator','Approver','Viewer'));

-- Register the v0.11 read projections and declarative action names.  The
-- connector_permissions rows for execute/destructive remain disabled.
INSERT INTO connector_capabilities(connector_id,capability,read_only) VALUES
 ('00000000-0000-4000-8000-000000000050','container.images',TRUE),
 ('00000000-0000-4000-8000-000000000050','container.networks',TRUE),
 ('00000000-0000-4000-8000-000000000050','container.volumes',TRUE),
 ('00000000-0000-4000-8000-000000000051','repository.issues',TRUE),
 ('00000000-0000-4000-8000-000000000051','repository.actions',TRUE),
 ('00000000-0000-4000-8000-000000000051','repository.releases',TRUE),
 ('00000000-0000-4000-8000-000000000052','platform.nodes',TRUE),
 ('00000000-0000-4000-8000-000000000052','platform.vms',TRUE),
 ('00000000-0000-4000-8000-000000000052','platform.storage',TRUE)
ON CONFLICT DO NOTHING;

INSERT INTO connector_capabilities(connector_id,capability,read_only,mode) VALUES
 ('00000000-0000-4000-8000-000000000050','container.stop',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000050','container.start',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000052','platform.reboot',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000052','platform.migrate',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000051','repository.workflow_start',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000051','repository.issue_create',FALSE,'execute')
ON CONFLICT (connector_id,capability) DO UPDATE SET read_only=FALSE,mode='execute';

INSERT INTO actions(id,connector_id,name,type,description,risk_level,required_scope,requires_approval,enabled) VALUES
 ('00000000-0000-4000-8000-000000000064','00000000-0000-4000-8000-000000000050','docker.stop_container','connector_action','Prepare a container stop request; execution is disabled by default.','high','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000065','00000000-0000-4000-8000-000000000050','docker.start_container','connector_action','Prepare a container start request; execution is disabled by default.','medium','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000066','00000000-0000-4000-8000-000000000052','proxmox.reboot','connector_action','Prepare a Proxmox reboot request; execution is disabled by default.','critical','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000067','00000000-0000-4000-8000-000000000052','proxmox.migrate','connector_action','Prepare a Proxmox migration request; execution is disabled by default.','high','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000068','00000000-0000-4000-8000-000000000051','github.start_workflow','connector_action','Prepare a workflow start request; execution is disabled by default.','medium','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000069','00000000-0000-4000-8000-000000000051','github.create_issue','connector_action','Prepare an issue request; execution is disabled by default.','low','agent:action:read',TRUE,FALSE)
ON CONFLICT (id) DO NOTHING;
