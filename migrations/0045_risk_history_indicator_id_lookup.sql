-- The operations summary looks up the latest risk for each indicator by ID.
-- The existing text-indicator index cannot serve that lookup.
CREATE INDEX IF NOT EXISTS risk_history_indicator_id_time_idx
    ON risk_history (indicator_id, recorded_at DESC);
