-- Persisted, explainable recommendations and declarative rule execution.
-- No table in this migration grants an agent or MCP client write access.
CREATE TABLE IF NOT EXISTS decisions (
    id UUID PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    title TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 240),
    description TEXT NOT NULL CHECK (char_length(description) BETWEEN 1 AND 10000),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 10000),
    recommendation TEXT NOT NULL CHECK (char_length(recommendation) BETWEEN 1 AND 10000),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','dismissed','resolved','expired')),
    related_incident_id UUID REFERENCES incidents(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS decisions_status_time_idx ON decisions (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS decisions_category_time_idx ON decisions (category, created_at DESC);
CREATE INDEX IF NOT EXISTS decisions_incident_idx ON decisions (related_incident_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS rules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 128),
    description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 10000),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    condition JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rule_executions (
    id UUID PRIMARY KEY,
    rule_id UUID NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    event_id UUID REFERENCES events(event_id) ON DELETE SET NULL,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    result JSONB NOT NULL DEFAULT '{}'::jsonb,
    decision_id UUID REFERENCES decisions(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS rule_executions_rule_time_idx ON rule_executions (rule_id, executed_at DESC);
CREATE INDEX IF NOT EXISTS rule_executions_decision_idx ON rule_executions (decision_id, executed_at DESC);

CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY,
    decision_id UUID NOT NULL REFERENCES decisions(id) ON DELETE CASCADE,
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS approvals_decision_idx ON approvals (decision_id, created_at DESC);
CREATE INDEX IF NOT EXISTS approvals_status_idx ON approvals (status, expires_at);

INSERT INTO rules (id, name, description, enabled, severity, condition)
VALUES
    ('00000000-0000-4000-8000-000000000020', 'critical-source-burst', 'Recommend incident review when one source emits more than five critical events in ten minutes.', TRUE, 'high', '{"event_severity_at_least":"critical","source_event_count":{"greater_than":5,"window_seconds":600}}'::jsonb),
    ('00000000-0000-4000-8000-000000000021', 'provider-health-degraded', 'Recommend provider fallback review when a provider reports an unhealthy state.', TRUE, 'high', '{"provider_status_in":["error","degraded","timeout"]}'::jsonb)
ON CONFLICT (name) DO NOTHING;
