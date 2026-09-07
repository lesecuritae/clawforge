CREATE TABLE notification_channels (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('webhook', 'smtp', 'matrix')),
    target TEXT NOT NULL,
    secret_ref TEXT,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_rules (
    id UUID PRIMARY KEY,
    event_type TEXT NOT NULL,
    minimum_severity TEXT NOT NULL DEFAULT 'info',
    channel_id UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (event_type, minimum_severity, channel_id)
);

CREATE TABLE notification_events (
    id UUID PRIMARY KEY,
    source_event_id BIGINT REFERENCES audit_events(id) ON DELETE SET NULL,
    rule_id UUID REFERENCES notification_rules(id) ON DELETE SET NULL,
    channel_id UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    resource TEXT NOT NULL,
    target TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'sent', 'failed', 'suppressed')),
    retry_count INTEGER NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempt_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    error TEXT,
    dedupe_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX notification_events_pending_idx
    ON notification_events (status, available_at, created_at);
CREATE INDEX notification_events_source_idx
    ON notification_events (source_event_id);
CREATE INDEX notification_rules_event_idx
    ON notification_rules (event_type, enabled);
