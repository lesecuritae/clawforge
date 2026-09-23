-- Security Event Layer storage (roadmap phase 2, security-events-storage).
-- Additive only: existing events/event_delivery/audit_events remain the
-- general-purpose event backbone and are untouched by this migration. These
-- tables are exclusively for the eleven typed sensor event kinds
-- clawforge-security-events defines (docs/security-events.md).
--
-- Nothing writes here yet: an authenticated ingress endpoint is separate,
-- later work (security-events-ingress), so this migration deliberately
-- grants no runtime database role access to these tables - that grant
-- belongs with the service that will actually write to them, decided when
-- that service exists.

CREATE TABLE IF NOT EXISTS security_sensors (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (char_length(name) BETWEEN 1 AND 160),
    -- Same shape as agent_tokens/api_tokens: storage only ever sees an
    -- already-hashed credential and a short, non-secret prefix for display;
    -- hashing itself is the caller's responsibility (argon2, matching
    -- admin_users/api_tokens elsewhere).
    credential_hash TEXT NOT NULL UNIQUE,
    credential_prefix TEXT NOT NULL CHECK (char_length(credential_prefix) BETWEEN 1 AND 32),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    created_by UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (revoked_at IS NULL OR enabled = FALSE)
);
CREATE INDEX IF NOT EXISTS security_sensors_active_idx
    ON security_sensors (enabled, revoked_at);

CREATE TABLE IF NOT EXISTS security_sensor_audit (
    id BIGSERIAL PRIMARY KEY,
    sensor_id UUID NOT NULL REFERENCES security_sensors(id) ON DELETE CASCADE,
    action TEXT NOT NULL CHECK (action IN ('registered','credential_rotated','enabled','revoked')),
    actor TEXT NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 160),
    reason TEXT NOT NULL DEFAULT '' CHECK (char_length(reason) <= 2000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS security_sensor_audit_sensor_time_idx
    ON security_sensor_audit (sensor_id, created_at ASC);

CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY,
    schema_version SMALLINT NOT NULL DEFAULT 1 CHECK (schema_version >= 1),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'firewall_block','firewall_rule_changed','auth_failure','auth_anomaly',
        'ssh_login_failure','ssh_login_anomaly','http_anomaly','dns_anomaly',
        'port_scan_detected','container_anomaly','container_escape_attempt'
    )),
    sensor_id UUID NOT NULL REFERENCES security_sensors(id),
    -- The sensor's own clock (SensorEnvelope::occurred_at) versus this
    -- server's receipt time - the roadmap's "serverseitige Empfangszeit",
    -- kept distinct so clock-skew checking (security-events-ingress) has
    -- something to compare against.
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    -- Pseudonymized before this row is ever written, exactly like
    -- events.correlation_id/payload already are (storage's
    -- ip_pseudonym_key/sanitize_analysis_value machinery,
    -- incident-correlation-convergence): resource and any IP-shaped
    -- evidence field never reach this table as a raw address. Canonical and
    -- read-safe in the one stored representation, per
    -- docs/security-control-plane-architecture.de.md point 10.
    resource TEXT NOT NULL CHECK (char_length(resource) BETWEEN 1 AND 512),
    -- Sensor-scoped, not globally unique: two different sensors may each
    -- legitimately use dedupe_key "1".
    dedupe_key TEXT NOT NULL CHECK (char_length(dedupe_key) BETWEEN 1 AND 256),
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (sensor_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS security_events_type_time_idx
    ON security_events (event_type, occurred_at DESC);
CREATE INDEX IF NOT EXISTS security_events_sensor_time_idx
    ON security_events (sensor_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS security_events_resource_idx
    ON security_events (resource, occurred_at DESC);
