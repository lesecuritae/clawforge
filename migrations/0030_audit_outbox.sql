-- Audit is the source of truth for privileged mutations. The outbox is
-- written in the same transaction and can be retried independently when the
-- canonical event backbone is temporarily unavailable.
CREATE TABLE IF NOT EXISTS audit_outbox (
    id UUID PRIMARY KEY,
    audit_event_id BIGINT NOT NULL UNIQUE REFERENCES audit_events(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL,
    resource TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error TEXT CHECK (last_error IS NULL OR char_length(last_error) <= 1000)
);
CREATE INDEX IF NOT EXISTS audit_outbox_pending_idx
    ON audit_outbox(created_at) WHERE published_at IS NULL;

CREATE OR REPLACE FUNCTION clawforge_forbid_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION clawforge_forbid_audit_mutation();
