ALTER TABLE providers
    ADD COLUMN IF NOT EXISTS quality_score SMALLINT NOT NULL DEFAULT 0
        CHECK (quality_score BETWEEN 0 AND 100);

ALTER TABLE provider_status
    ADD COLUMN IF NOT EXISTS last_failure_at TIMESTAMPTZ;
