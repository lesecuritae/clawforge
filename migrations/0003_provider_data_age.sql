ALTER TABLE provider_status
    ADD COLUMN IF NOT EXISTS last_data_at TIMESTAMPTZ;
