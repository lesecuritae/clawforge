CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('Open', 'Investigating', 'Resolved', 'Ignored')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    risk_score SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    summary TEXT NOT NULL,
    correlation_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id BIGINT NOT NULL REFERENCES audit_events(id) ON DELETE CASCADE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (incident_id, event_id)
);

CREATE INDEX IF NOT EXISTS incidents_status_time_idx
    ON incidents (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS incidents_correlation_idx
    ON incidents (correlation_key, updated_at DESC);
CREATE INDEX IF NOT EXISTS incident_events_time_idx
    ON incident_events (timestamp DESC);
