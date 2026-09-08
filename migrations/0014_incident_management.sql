ALTER TABLE incidents
    DROP CONSTRAINT IF EXISTS incidents_status_check;

UPDATE incidents
SET status = CASE status
    WHEN 'Open' THEN 'detected'
    WHEN 'Investigating' THEN 'investigating'
    WHEN 'Resolved' THEN 'resolved'
    WHEN 'Ignored' THEN 'closed'
    ELSE lower(status)
END;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'incidents_status_check'
          AND conrelid = 'incidents'::regclass
    ) THEN
        ALTER TABLE incidents
            ADD CONSTRAINT incidents_status_check
                CHECK (status IN ('detected', 'investigating', 'confirmed', 'mitigated', 'resolved', 'closed'));
    END IF;
END
$$;

ALTER TABLE incidents
    ADD COLUMN IF NOT EXISTS confidence SMALLINT NOT NULL DEFAULT 0
        CHECK (confidence BETWEEN 0 AND 100),
    ADD COLUMN IF NOT EXISTS candidate_id UUID REFERENCES incident_candidates(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS detected_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS mitigated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;

UPDATE incidents
SET detected_at = COALESCE(detected_at, created_at)
WHERE detected_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS incidents_candidate_unique_idx
    ON incidents (candidate_id)
    WHERE candidate_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS incident_status_history (
    id BIGSERIAL PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    previous_status TEXT,
    new_status TEXT NOT NULL CHECK (new_status IN ('detected', 'investigating', 'confirmed', 'mitigated', 'resolved', 'closed')),
    changed_by TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS incident_status_history_time_idx
    ON incident_status_history (incident_id, changed_at ASC);

CREATE TABLE IF NOT EXISTS incident_notes (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS incident_notes_time_idx
    ON incident_notes (incident_id, created_at ASC);

CREATE TABLE IF NOT EXISTS incident_relations (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL CHECK (relation_type IN ('event', 'indicator', 'event_relationship', 'incident')),
    event_id UUID REFERENCES events(event_id) ON DELETE CASCADE,
    related_event_id UUID REFERENCES events(event_id) ON DELETE CASCADE,
    indicator_id BIGINT REFERENCES indicators(id) ON DELETE SET NULL,
    related_incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    confidence SMALLINT NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (event_id IS NOT NULL OR indicator_id IS NOT NULL OR related_incident_id IS NOT NULL),
    CHECK (relation_type <> 'event_relationship' OR (event_id IS NOT NULL AND related_event_id IS NOT NULL)),
    CHECK (relation_type <> 'incident' OR related_incident_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS incident_relations_event_unique_idx
    ON incident_relations (incident_id, relation_type, event_id, related_event_id)
    WHERE event_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS incident_relations_indicator_unique_idx
    ON incident_relations (incident_id, relation_type, indicator_id)
    WHERE indicator_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS incident_relations_incident_unique_idx
    ON incident_relations (incident_id, relation_type, related_incident_id)
    WHERE related_incident_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS incident_relations_time_idx
    ON incident_relations (incident_id, created_at ASC);

INSERT INTO incident_status_history (incident_id, previous_status, new_status, changed_by, reason, changed_at)
SELECT i.id, NULL, i.status, 'migration', 'initial incident lifecycle state', i.created_at
FROM incidents i
WHERE NOT EXISTS (
    SELECT 1 FROM incident_status_history h WHERE h.incident_id = i.id
);
