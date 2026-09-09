CREATE TABLE IF NOT EXISTS execution_requests (
    id UUID PRIMARY KEY,
    action_id UUID NOT NULL REFERENCES actions(id),
    workflow_run_id UUID REFERENCES workflow_runs(id) ON DELETE SET NULL,
    decision_id UUID REFERENCES decisions(id) ON DELETE SET NULL,
    requested_by TEXT NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 160),
    status TEXT NOT NULL CHECK (status IN ('pending','waiting_approval','approved','running','completed','failed','cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    result_summary TEXT CHECK (result_summary IS NULL OR char_length(result_summary) <= 4000),
    error_summary TEXT CHECK (error_summary IS NULL OR char_length(error_summary) <= 4000)
);
CREATE INDEX IF NOT EXISTS execution_requests_status_idx ON execution_requests(status, created_at DESC);
CREATE INDEX IF NOT EXISTS execution_requests_action_idx ON execution_requests(action_id, created_at DESC);
