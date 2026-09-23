-- Phase 4 "Security Engine": persisted, versioned assessments produced by
-- clawforge-security-engine's rules (roadmap: "Assessments, Evidence-
-- Referenzen und Engine-/Regelversion persistieren"). Additive only -
-- existing tables are unchanged.
--
-- An assessment is the output of one rule matching one deterministic
-- tumbling-window bucket for one resource (see security-engine/src/main.rs
-- for why a fixed bucket, not a sliding window, is what makes replay
-- deterministic). dedupe_key is exactly (rule_id, rule_version, resource,
-- bucket_start) turned into one string, enforced unique: replaying the same
-- events through the same rule version can only ever upsert the same row,
-- never create a duplicate - the exit-gate requirement "gleiche Events und
-- Regelversion erzeugen deterministisch dasselbe Assessment; Backfill/Replay
-- erzeugt keine ... doppelten Incidents".
CREATE TABLE security_assessments (
    -- Generated in Rust (Uuid::new_v4()) and bound explicitly, matching
    -- every other table in this schema - no pgcrypto/gen_random_uuid()
    -- dependency.
    id UUID PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    resource TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    summary TEXT NOT NULL,
    event_count INTEGER NOT NULL CHECK (event_count > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
    bucket_start TIMESTAMPTZ NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    incident_id UUID REFERENCES incidents (id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (dedupe_key)
);

CREATE INDEX security_assessments_resource_idx ON security_assessments (resource, bucket_start);
CREATE INDEX security_assessments_rule_idx ON security_assessments (rule_id, bucket_start);

-- Evidence references, not copies (roadmap: "Evidence-Referenzen ...
-- persistieren", not evidence itself - the canonical event already holds
-- the pseudonymized payload, this table only records which events a given
-- assessment was computed from, for later audit/replay comparison).
CREATE TABLE security_assessment_events (
    assessment_id UUID NOT NULL REFERENCES security_assessments (id) ON DELETE CASCADE,
    event_id UUID NOT NULL REFERENCES events (event_id),
    PRIMARY KEY (assessment_id, event_id)
);
