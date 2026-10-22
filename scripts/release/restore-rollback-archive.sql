-- After a re-upgrade to 1.2.0, copy rows archived by rollback-1.2-to-1.1.sql back.
--   psql -v ON_ERROR_STOP=1 -v arch=clawforge_rollback_YYYYMMDDTHHMMSS -f restore-rollback-archive.sql
-- The archive is kept; drop it manually only after the restored data was checked.
\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
  IF (SELECT max(version) FROM _sqlx_migrations) < 64 THEN
    RAISE EXCEPTION 'restore refused: ledger is below 64';
  END IF;
END $$;
INSERT INTO public.source_network_context SELECT * FROM :"arch".source_network_context ON CONFLICT (pseudonym) DO NOTHING;
COMMIT;
