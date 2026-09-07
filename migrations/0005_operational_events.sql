ALTER TABLE audit_events
    ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'audit',
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'system',
    ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'info',
    ADD COLUMN IF NOT EXISTS reason TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS audit_events_type_time_idx
    ON audit_events (event_type, recorded_at DESC);
