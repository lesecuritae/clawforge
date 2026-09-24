-- Additive: whether any event in a security_assessments bucket also
-- matched a threat-intel indicator (today: Spamhaus DROP/EDROP - see
-- PostgresStore::lookup_ip_reputation), computed by
-- clawforge-security-engine and consumed by clawforge-policy-engine as a
-- second, independent evidence source. Before this, every assessment had
-- exactly one evidence source (the behavioral rule itself), which made
-- clawforge_policy::decide()'s Block decision structurally unreachable
-- (requires evidence_sources >= 2, see docs/policy-engine.md) - this
-- column is what makes a second source possible for the first time,
-- still only in Shadow Mode (no action layer exists to execute a Block on).
ALTER TABLE security_assessments
    ADD COLUMN threat_intel_corroborated BOOLEAN NOT NULL DEFAULT FALSE;
