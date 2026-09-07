CREATE TABLE events (
    event_id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    severity TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    correlation_id TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    dedupe_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE event_consumers (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_heartbeat_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE event_delivery (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    consumer_id UUID NOT NULL REFERENCES event_consumers(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'processed', 'failed', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processing_started_at TIMESTAMPTZ,
    processed_at TIMESTAMPTZ,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (event_id, consumer_id)
);

CREATE INDEX events_type_time_idx ON events (event_type, occurred_at DESC);
CREATE INDEX event_delivery_claim_idx ON event_delivery (consumer_id, status, available_at, created_at);
