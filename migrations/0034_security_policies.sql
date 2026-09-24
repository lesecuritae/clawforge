-- Phase 5 "Policy Engine" (roadmap), Shadow Mode only: versioned policies
-- and the decisions clawforge-policy-engine derives from them. Additive -
-- existing tables are unchanged.
--
-- No action/adapter/diff columns yet on security_policy_decisions - Phase 6
-- ("Firewall Action Layer") does not exist yet, so there is nothing for a
-- decision to bind to beyond the policy and the evidence it was made from.
-- evidence_hash covers exactly that (policy id/version + evidence snapshot),
-- and gets extended once an action layer exists to bind to as well.
CREATE TABLE security_policies (
    -- Generated in Rust (Uuid::new_v4()) and bound explicitly, matching
    -- every other table in this schema.
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'retired')),
    -- What this policy's decision would require if an action layer existed:
    -- observe (log only), approval (needs the two-person approval the
    -- roadmap asks for), automatic (would run without one). Shadow mode
    -- means none of the three ever actually executes anything right now -
    -- see is_shadow on security_policy_decisions, always TRUE today.
    class TEXT NOT NULL CHECK (class IN ('observe', 'approval', 'automatic')),
    -- Which clawforge-security-engine rule (ssh_bruteforce, http_scan, ...)
    -- this policy evaluates assessments from.
    rule_id TEXT NOT NULL,
    min_severity TEXT NOT NULL CHECK (min_severity IN ('medium', 'high', 'critical')),
    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (name, version)
);

CREATE INDEX security_policies_rule_status_idx ON security_policies (rule_id, status);

CREATE TABLE security_policy_decisions (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES security_policies (id),
    policy_version INTEGER NOT NULL,
    assessment_id UUID NOT NULL REFERENCES security_assessments (id),
    incident_id UUID REFERENCES incidents (id),
    -- clawforge_policy::Decision's own four values, reused rather than a
    -- second decision vocabulary: Observe/Challenge/RateLimit/Block.
    decision TEXT NOT NULL CHECK (decision IN ('observe', 'challenge', 'rate_limit', 'block')),
    risk_score SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    evidence_sources SMALLINT NOT NULL CHECK (evidence_sources > 0),
    -- corroborated = evidence_sources >= 2 (clawforge_policy::decide's own
    -- rule): with only this one rule's behavioral signal as a source today,
    -- always FALSE, which is exactly what keeps Block unreachable until a
    -- second, independent signal (e.g. a future threat-intel corroboration)
    -- exists - the roadmap's phase 4 exit gate ("ein einzelnes Signal
    -- erreicht nie eine Block-Entscheidung") enforced by the same shared
    -- logic, not a separate rule that could drift from it.
    corroborated BOOLEAN NOT NULL,
    rationale TEXT NOT NULL,
    evidence_snapshot JSONB NOT NULL,
    evidence_hash TEXT NOT NULL,
    is_shadow BOOLEAN NOT NULL DEFAULT TRUE,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- (policy_id, policy_version, assessment_id) folded into one string:
    -- replaying the same assessment through the same policy version can
    -- only ever upsert this one row, matching security_assessments' own
    -- dedupe_key discipline.
    dedupe_key TEXT NOT NULL UNIQUE
);

CREATE INDEX security_policy_decisions_assessment_idx ON security_policy_decisions (assessment_id);
CREATE INDEX security_policy_decisions_decided_idx ON security_policy_decisions (decided_at DESC);

-- Seed one active, version-1, observe-class policy per rule
-- clawforge-security-engine currently implements. class=observe (not
-- approval/automatic) is itself a deliberate shadow-mode-appropriate
-- default: even once an action layer exists, these seeded policies would
-- still only log, never gate an approval or run automatically, until a
-- reviewed change explicitly raises one to a stronger class.
INSERT INTO security_policies (id, name, version, status, class, rule_id, min_severity)
VALUES
    ('00000000-0000-4000-9000-000000000001', 'ssh_bruteforce-default', 1, 'active', 'observe', 'ssh_bruteforce', 'medium'),
    ('00000000-0000-4000-9000-000000000002', 'http_anomaly_burst-default', 1, 'active', 'observe', 'http_anomaly_burst', 'medium'),
    ('00000000-0000-4000-9000-000000000003', 'http_scan-default', 1, 'active', 'observe', 'http_scan', 'medium')
ON CONFLICT (id) DO NOTHING;
