-- Phase 8 "Threat Intelligence" (roadmap): freshness, provenance and
-- confidence per assessment.
--
-- security_assessments.threat_intel_corroborated already existed
-- (migration 0035) as a plain boolean - it answered "did some threat-
-- intel indicator match", but not which provider, how confident that
-- provider's own indicator was, or how recently it was last confirmed
-- (indicators.confidence/last_seen already existed on the source table,
-- they just were never carried through to the assessment that used
-- them). This is what makes the roadmap's own exit gate concrete:
-- "Offline- oder veraltete Feeds reduzieren Confidence ... jede Score-
-- Komponente bleibt erklaerbar" - a reviewer (or clawforge-policy-engine
-- itself) needs the actual source/confidence/age to judge that, not
-- just a bare "true".
ALTER TABLE security_assessments
    ADD COLUMN threat_intel_source TEXT,
    ADD COLUMN threat_intel_confidence SMALLINT
        CHECK (threat_intel_confidence IS NULL OR threat_intel_confidence BETWEEN 0 AND 100),
    ADD COLUMN threat_intel_indicator_last_seen TIMESTAMPTZ;

-- Consistency: the three new columns are either all present (a real hit
-- was recorded) or all absent (no hit) - never a partial state that
-- would let threat_intel_corroborated=true carry no explanation, or
-- threat_intel_corroborated=false carry a source as if it mattered.
ALTER TABLE security_assessments
    ADD CONSTRAINT security_assessments_threat_intel_detail_consistency
    CHECK (
        (threat_intel_source IS NULL AND threat_intel_confidence IS NULL
            AND threat_intel_indicator_last_seen IS NULL)
        OR (threat_intel_source IS NOT NULL AND threat_intel_confidence IS NOT NULL
            AND threat_intel_indicator_last_seen IS NOT NULL)
    );
