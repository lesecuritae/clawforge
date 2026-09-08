ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS group_key TEXT,
    ADD COLUMN IF NOT EXISTS confidence SMALLINT NOT NULL DEFAULT 100 CHECK (confidence BETWEEN 0 AND 100),
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS event_count INTEGER NOT NULL DEFAULT 1 CHECK (event_count >= 1);

UPDATE alerts
SET group_key = COALESCE(group_key, CASE WHEN incident_id IS NOT NULL THEN 'incident:' || incident_id::text ELSE dedupe_key END),
    last_seen_at = COALESCE(last_seen_at, created_at)
WHERE group_key IS NULL;

CREATE INDEX IF NOT EXISTS alerts_group_status_idx ON alerts (group_key, status, last_seen_at DESC);
