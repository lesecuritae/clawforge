CREATE TABLE IF NOT EXISTS runtime_status (
    component TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    version TEXT NOT NULL,
    last_started_at TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS runtime_status_heartbeat_idx
    ON runtime_status (last_heartbeat_at DESC);
