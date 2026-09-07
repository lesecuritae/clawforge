CREATE TABLE IF NOT EXISTS incident_analysis (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    summary TEXT NOT NULL,
    observations JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS incident_analysis_incident_time_idx
    ON incident_analysis (incident_id, analyzed_at DESC);
