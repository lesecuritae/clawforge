ALTER TABLE asn_records
    ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS registry TEXT NOT NULL DEFAULT '';

ALTER TABLE bgp_events
    ADD COLUMN IF NOT EXISTS previous_asn TEXT,
    ADD COLUMN IF NOT EXISTS new_asn TEXT,
    ADD COLUMN IF NOT EXISTS event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS bgp_events_source_time_idx
    ON bgp_events (source, event_timestamp DESC);

CREATE TABLE IF NOT EXISTS rpki_records (
    id BIGSERIAL PRIMARY KEY,
    prefix TEXT NOT NULL,
    asn TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('Valid', 'Invalid', 'Unknown')),
    event_timestamp TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (prefix, asn, status, event_timestamp, source)
);
CREATE INDEX IF NOT EXISTS rpki_prefix_time_idx
    ON rpki_records (prefix, event_timestamp DESC);
