-- Periodic, sanitized operations snapshots used for historical comparisons.
CREATE TABLE IF NOT EXISTS operations_snapshots (
    id BIGSERIAL PRIMARY KEY,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    overall_status TEXT NOT NULL CHECK (overall_status IN ('ok', 'degraded', 'unavailable', 'critical')),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('info', 'low', 'medium', 'high', 'critical')),
    active_incident_count INTEGER NOT NULL DEFAULT 0 CHECK (active_incident_count >= 0),
    alert_count INTEGER NOT NULL DEFAULT 0 CHECK (alert_count >= 0),
    provider_health JSONB NOT NULL DEFAULT '{}'::jsonb,
    system_health JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS operations_snapshots_captured_idx
    ON operations_snapshots (captured_at DESC);
