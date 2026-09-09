-- v0.12 incident intelligence and production operations metadata.
-- This migration is additive: the existing correlation, incident lifecycle,
-- execution, notification and audit tables remain the source of truth.

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT 'Security incident',
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'correlation';

ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_status_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_status_check CHECK
    (status IN ('open','acknowledged','detected','investigating','confirmed','mitigated','resolved','closed'));

ALTER TABLE incident_events
    ADD COLUMN IF NOT EXISTS relation TEXT NOT NULL DEFAULT 'related';

CREATE TABLE IF NOT EXISTS incident_timeline (
    id BIGSERIAL PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    actor TEXT NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 160),
    action TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 160),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS incident_timeline_incident_time_idx
    ON incident_timeline (incident_id, timestamp ASC, id ASC);

CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    source TEXT,
    error_class TEXT,
    infrastructure TEXT,
    time_window_seconds INTEGER NOT NULL DEFAULT 300 CHECK (time_window_seconds BETWEEN 1 AND 86400),
    minimum_severity TEXT NOT NULL DEFAULT 'info' CHECK (minimum_severity IN ('info','low','medium','high','critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alert_groups (
    id UUID PRIMARY KEY,
    group_key TEXT NOT NULL UNIQUE CHECK (char_length(group_key) BETWEEN 1 AND 512),
    source TEXT,
    error_class TEXT,
    infrastructure TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','low','medium','high','critical')),
    confidence SMALLINT NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved','closed')),
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS alert_groups_status_time_idx ON alert_groups(status, last_seen DESC);

CREATE TABLE IF NOT EXISTS correlation_events (
    id UUID PRIMARY KEY,
    alert_group_id UUID NOT NULL REFERENCES alert_groups(id) ON DELETE CASCADE,
    event_id UUID REFERENCES events(event_id) ON DELETE CASCADE,
    source TEXT,
    event_type TEXT,
    error_class TEXT,
    infrastructure TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    relation TEXT NOT NULL DEFAULT 'correlated',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (alert_group_id, event_id)
);
CREATE INDEX IF NOT EXISTS correlation_events_group_time_idx
    ON correlation_events(alert_group_id, occurred_at ASC);

CREATE TABLE IF NOT EXISTS secret_providers (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    provider_type TEXT NOT NULL CHECK (provider_type IN ('docker_secret','environment','vaultwarden','sops','external')),
    status TEXT NOT NULL DEFAULT 'configured' CHECK (status IN ('configured','healthy','degraded','unavailable','disabled')),
    config_ref TEXT NOT NULL CHECK (char_length(config_ref) BETWEEN 1 AND 512),
    last_check TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS secret_references (
    id UUID PRIMARY KEY,
    provider_id UUID NOT NULL REFERENCES secret_providers(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 160),
    reference TEXT NOT NULL CHECK (char_length(reference) BETWEEN 1 AND 512),
    purpose TEXT NOT NULL DEFAULT 'connector',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_resolved_at TIMESTAMPTZ,
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (provider_id, name)
);
CREATE INDEX IF NOT EXISTS secret_references_provider_idx ON secret_references(provider_id, enabled);

INSERT INTO alert_rules(id,name,source,error_class,infrastructure,time_window_seconds,minimum_severity)
VALUES
 ('00000000-0000-4000-8000-000000000070','same source and error window',NULL,NULL,NULL,300,'info')
ON CONFLICT (id) DO NOTHING;

INSERT INTO secret_providers(id,name,provider_type,config_ref)
VALUES
 ('00000000-0000-4000-8000-000000000080','Docker Secrets','docker_secret','/run/secrets')
ON CONFLICT (id) DO NOTHING;

-- Register requested actions without enabling execution. The executor remains
-- dry-run only until a separately reviewed policy enables a specific action.
INSERT INTO connector_capabilities(connector_id,capability,read_only,mode) VALUES
 ('00000000-0000-4000-8000-000000000050','container.rebuild',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000050','container.update_image',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000052','platform.restart_vm',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000052','platform.shutdown_vm',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000052','platform.snapshot_vm',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000051','repository.issue_create',FALSE,'execute'),
 ('00000000-0000-4000-8000-000000000051','repository.workflow_trigger',FALSE,'execute')
ON CONFLICT (connector_id,capability) DO UPDATE SET read_only=FALSE,mode='execute';

INSERT INTO actions(id,connector_id,name,type,description,risk_level,required_scope,requires_approval,enabled) VALUES
 ('00000000-0000-4000-8000-000000000090','00000000-0000-4000-8000-000000000050','docker.rebuild_container','connector_action','Prepare a container rebuild; execution is disabled by default.','high','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000091','00000000-0000-4000-8000-000000000050','docker.update_image','connector_action','Prepare an image update; execution is disabled by default.','high','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000092','00000000-0000-4000-8000-000000000052','proxmox.restart_vm','connector_action','Prepare a VM restart; execution is disabled by default.','high','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000093','00000000-0000-4000-8000-000000000052','proxmox.shutdown_vm','connector_action','Prepare a VM shutdown; execution is disabled by default.','critical','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000094','00000000-0000-4000-8000-000000000052','proxmox.snapshot_vm','connector_action','Prepare a VM snapshot; execution is disabled by default.','medium','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000095','00000000-0000-4000-8000-000000000051','github.create_issue','connector_action','Prepare an issue creation request; execution is disabled by default.','medium','agent:action:read',TRUE,FALSE),
 ('00000000-0000-4000-8000-000000000096','00000000-0000-4000-8000-000000000051','github.trigger_workflow','connector_action','Prepare a workflow trigger request; execution is disabled by default.','medium','agent:action:read',TRUE,FALSE)
ON CONFLICT (name) DO UPDATE SET description=EXCLUDED.description,updated_at=NOW();
