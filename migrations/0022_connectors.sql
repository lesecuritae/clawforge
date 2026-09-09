-- Read-only external infrastructure connector registry.
-- Connector metadata never stores credentials; secrets are injected through
-- Docker Secrets and referenced by the connector implementation.
CREATE TABLE IF NOT EXISTS connector_registry (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    version TEXT NOT NULL CHECK (char_length(version) BETWEEN 1 AND 32),
    connector_type TEXT NOT NULL CHECK (connector_type IN ('docker','github','proxmox')),
    status TEXT NOT NULL DEFAULT 'configured' CHECK (status IN ('configured','healthy','degraded','unavailable','disabled')),
    last_check TIMESTAMPTZ,
    health TEXT NOT NULL DEFAULT 'unknown' CHECK (health IN ('unknown','healthy','degraded','unavailable')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connector_metadata (
    connector_id UUID PRIMARY KEY REFERENCES connector_registry(id) ON DELETE CASCADE,
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 10000),
    read_only BOOLEAN NOT NULL DEFAULT TRUE,
    secret_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connector_health (
    connector_id UUID PRIMARY KEY REFERENCES connector_registry(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown','healthy','degraded','unavailable')),
    checked_at TIMESTAMPTZ,
    latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
    error TEXT CHECK (error IS NULL OR char_length(error) <= 2000),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connector_capabilities (
    connector_id UUID NOT NULL REFERENCES connector_registry(id) ON DELETE CASCADE,
    capability TEXT NOT NULL CHECK (char_length(capability) BETWEEN 1 AND 160),
    read_only BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, capability)
);

CREATE INDEX IF NOT EXISTS connector_registry_status_idx ON connector_registry (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS connector_health_status_idx ON connector_health (status, checked_at DESC);

INSERT INTO connector_registry (id, name, version, connector_type, status, health)
VALUES
    ('00000000-0000-4000-8000-000000000050', 'Docker Connector', '0.8.0', 'docker', 'configured', 'unknown'),
    ('00000000-0000-4000-8000-000000000051', 'GitHub Connector', '0.8.0', 'github', 'configured', 'unknown'),
    ('00000000-0000-4000-8000-000000000052', 'Proxmox Connector Foundation', '0.8.0', 'proxmox', 'configured', 'unknown')
ON CONFLICT (id) DO UPDATE SET version=EXCLUDED.version, updated_at=NOW();

INSERT INTO connector_metadata (connector_id, description, read_only, secret_ref)
VALUES
    ('00000000-0000-4000-8000-000000000050', 'Reads Docker containers, status, health, image versions, and restart counts.', TRUE, NULL),
    ('00000000-0000-4000-8000-000000000051', 'Reads repository status, commits, security alerts, and workflow status.', TRUE, 'github_token'),
    ('00000000-0000-4000-8000-000000000052', 'Read-only foundation for Proxmox authentication and health checks.', TRUE, 'proxmox_token')
ON CONFLICT (connector_id) DO UPDATE SET description=EXCLUDED.description, read_only=TRUE, secret_ref=EXCLUDED.secret_ref, updated_at=NOW();

INSERT INTO connector_health (connector_id, status)
VALUES
    ('00000000-0000-4000-8000-000000000050', 'unknown'),
    ('00000000-0000-4000-8000-000000000051', 'unknown'),
    ('00000000-0000-4000-8000-000000000052', 'unknown')
ON CONFLICT (connector_id) DO NOTHING;

INSERT INTO connector_capabilities (connector_id, capability, read_only)
VALUES
    ('00000000-0000-4000-8000-000000000050', 'container.list', TRUE),
    ('00000000-0000-4000-8000-000000000050', 'container.status', TRUE),
    ('00000000-0000-4000-8000-000000000050', 'container.health', TRUE),
    ('00000000-0000-4000-8000-000000000050', 'container.image_version', TRUE),
    ('00000000-0000-4000-8000-000000000050', 'container.restart_count', TRUE),
    ('00000000-0000-4000-8000-000000000051', 'repository.status', TRUE),
    ('00000000-0000-4000-8000-000000000051', 'repository.commits', TRUE),
    ('00000000-0000-4000-8000-000000000051', 'repository.security_alerts', TRUE),
    ('00000000-0000-4000-8000-000000000051', 'repository.workflow_status', TRUE),
    ('00000000-0000-4000-8000-000000000052', 'platform.health', TRUE)
ON CONFLICT DO NOTHING;
