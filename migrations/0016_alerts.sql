-- Operational alerts are a read/acknowledge layer above correlated events.
-- Delivery remains delegated to the existing notification service.
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY,
    source TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved', 'suppressed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    delivery_status TEXT NOT NULL DEFAULT 'pending' CHECK (delivery_status IN ('pending', 'sent', 'partial', 'failed', 'not_configured')),
    incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    source_event_id BIGINT REFERENCES audit_events(id) ON DELETE SET NULL,
    summary TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    dedupe_key TEXT NOT NULL UNIQUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS alerts_status_time_idx ON alerts (status, created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_severity_time_idx ON alerts (severity, created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_incident_idx ON alerts (incident_id);

CREATE TABLE IF NOT EXISTS alert_status_history (
    id BIGSERIAL PRIMARY KEY,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS alert_status_history_time_idx
    ON alert_status_history (alert_id, changed_at ASC);
