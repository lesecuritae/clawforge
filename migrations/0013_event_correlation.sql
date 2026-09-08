CREATE TABLE IF NOT EXISTS incident_candidates (
    id UUID PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'promoted', 'dismissed')),
    correlation_key TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    summary TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS incident_candidates_status_time_idx
    ON incident_candidates (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS incident_candidates_key_time_idx
    ON incident_candidates (correlation_key, last_seen DESC);

CREATE TABLE IF NOT EXISTS incident_candidate_events (
    candidate_id UUID NOT NULL REFERENCES incident_candidates(id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (candidate_id, event_id)
);

CREATE INDEX IF NOT EXISTS incident_candidate_events_event_idx
    ON incident_candidate_events (event_id);

CREATE TABLE IF NOT EXISTS event_relationships (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    related_event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    candidate_id UUID REFERENCES incident_candidates(id) ON DELETE SET NULL,
    relation_type TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (event_id <> related_event_id),
    UNIQUE (event_id, related_event_id, relation_type)
);

CREATE INDEX IF NOT EXISTS event_relationships_related_idx
    ON event_relationships (related_event_id, created_at DESC);
CREATE INDEX IF NOT EXISTS event_relationships_candidate_idx
    ON event_relationships (candidate_id, created_at DESC);
