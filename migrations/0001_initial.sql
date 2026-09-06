CREATE TABLE IF NOT EXISTS providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    interval_seconds BIGINT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS provider_status (
    provider_id TEXT PRIMARY KEY REFERENCES providers(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    last_started_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS indicators (
    id BIGSERIAL PRIMARY KEY,
    value TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    source TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (value, indicator_type, source)
);
CREATE INDEX IF NOT EXISTS indicators_expiry_idx ON indicators (expires_at);
CREATE INDEX IF NOT EXISTS indicators_value_idx ON indicators (value);

CREATE TABLE IF NOT EXISTS asn_records (
    asn TEXT PRIMARY KEY,
    organisation TEXT NOT NULL,
    provider TEXT NOT NULL,
    country TEXT,
    prefixes JSONB NOT NULL DEFAULT '[]'::jsonb,
    network_type TEXT,
    reputation SMALLINT NOT NULL DEFAULT 0 CHECK (reputation BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS bgp_events (
    id BIGSERIAL PRIMARY KEY,
    prefix TEXT NOT NULL,
    origin_asn TEXT NOT NULL,
    status TEXT NOT NULL,
    rpki_status TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    change TEXT,
    fingerprint TEXT NOT NULL UNIQUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS bgp_prefix_idx ON bgp_events (prefix, last_seen DESC);

CREATE TABLE IF NOT EXISTS risk_history (
    id BIGSERIAL PRIMARY KEY,
    indicator_id BIGINT REFERENCES indicators(id) ON DELETE SET NULL,
    indicator TEXT NOT NULL,
    source TEXT NOT NULL,
    score_change SMALLINT NOT NULL,
    reason TEXT NOT NULL,
    risk_score SMALLINT,
    trust_score SMALLINT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS risk_history_indicator_idx ON risk_history (indicator, recorded_at DESC);

CREATE TABLE IF NOT EXISTS trust_history (
    id BIGSERIAL PRIMARY KEY,
    trusted_network_id UUID,
    trust_change SMALLINT NOT NULL,
    reason TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events (recorded_at DESC);

CREATE TABLE IF NOT EXISTS trusted_networks (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    network_type TEXT NOT NULL,
    identifier TEXT NOT NULL,
    networks JSONB NOT NULL DEFAULT '[]'::jsonb,
    node_identities JSONB NOT NULL DEFAULT '[]'::jsonb,
    device_tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    groups_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL CHECK (status IN ('Pending', 'Verified', 'Revoked')),
    created_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS trusted_networks_status_idx ON trusted_networks (status);
