-- Sanitized knowledge summaries and provider health history for Operations
-- Intelligence. Raw feed payloads and credentials are deliberately absent.
CREATE TABLE IF NOT EXISTS knowledge_entries (
    id BIGSERIAL PRIMARY KEY,
    entry_type TEXT NOT NULL CHECK (entry_type IN ('incident', 'lesson_learned', 'pattern')),
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    related_incident UUID REFERENCES incidents(id) ON DELETE SET NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    UNIQUE (entry_type, related_incident)
);

CREATE INDEX IF NOT EXISTS knowledge_entries_created_idx
    ON knowledge_entries (created_at DESC);
CREATE INDEX IF NOT EXISTS knowledge_entries_type_idx
    ON knowledge_entries (entry_type, created_at DESC);

CREATE TABLE IF NOT EXISTS provider_history (
    id BIGSERIAL PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT,
    quality_score SMALLINT NOT NULL DEFAULT 0 CHECK (quality_score BETWEEN 0 AND 100),
    data_age_seconds DOUBLE PRECISION,
    indicator_count INTEGER NOT NULL DEFAULT 0 CHECK (indicator_count >= 0),
    sync_duration_ms BIGINT NOT NULL DEFAULT 0 CHECK (sync_duration_ms >= 0)
);

CREATE INDEX IF NOT EXISTS provider_history_provider_time_idx
    ON provider_history (provider_id, recorded_at DESC);
