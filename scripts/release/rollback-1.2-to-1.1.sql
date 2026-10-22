-- Reverse the schema effect of migrations 0059-0064 (release 1.2.0) so that the 1.1.0 migrator
-- again sees ledger 58 / 54 rows, WITHOUT deleting data.
--
--   psql -v ON_ERROR_STOP=1 -v goaway_def_file=/path/old-goaway-enqueue.sql -f rollback-1.2-to-1.1.sql
--
-- Only one table is new in 0059-0064 (source_network_context, 0063). It is MOVED, with its
-- indexes and rows, into a timestamped archive schema; nothing is dropped. Functions that 0059-0064
-- created or replaced are left in place: the 1.1.0 binaries never call them and re-running the
-- 1.2.0 migrations replaces them again. Only the function 0061 REPLACED is restored to its exact
-- 1.1.0 definition (captured from the live database before the upgrade). The execute grants on the
-- new functions are revoked from the runtime roles. The 0061 policy row is left (inert, idempotent).
-- Afterwards run restore-rollback-archive.sql after a re-upgrade to copy archived rows back.
\set ON_ERROR_STOP on
BEGIN;
LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
  IF (SELECT max(version) FROM _sqlx_migrations) <> 64
     OR (SELECT count(*) FROM _sqlx_migrations WHERE version BETWEEN 59 AND 64 AND success) <> 6
     OR (SELECT count(*) FROM _sqlx_migrations WHERE version > 64 OR NOT success) <> 0 THEN
    RAISE EXCEPTION 'rollback refused: ledger is not exactly 1.1.0 (58) + migrations 59..64';
  END IF;
  IF to_regclass('public.source_network_context') IS NULL THEN
    RAISE EXCEPTION 'rollback refused: public.source_network_context is missing';
  END IF;
END $$;

SELECT 'clawforge_rollback_' || to_char(clock_timestamp(), 'YYYYMMDD"T"HH24MISS') AS arch \gset
CREATE SCHEMA :"arch";
REVOKE ALL ON SCHEMA :"arch" FROM PUBLIC;
ALTER TABLE public.source_network_context SET SCHEMA :"arch";
COMMENT ON SCHEMA :"arch" IS 'archive of release 1.2.0 tables moved by rollback-1.2-to-1.1.sql; copy back with restore-rollback-archive.sql';

-- exact 1.1.0 definition of the one function 0061 replaced
\i :goaway_def_file

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT p.oid::regprocedure AS sig FROM pg_proc p
     WHERE p.pronamespace = 'public'::regnamespace
       AND p.proname IN ('clawforge_resolve_incident_source_for_apply','clawforge_policy_bridge_plan',
                         'clawforge_enqueue_policy_bridge_request','clawforge_assessment_event_types',
                         'clawforge_ip_reputation','clawforge_network_context_targets',
                         'clawforge_record_network_context','clawforge_current_source_intel')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM clawforge_api, clawforge_worker, clawforge_correlation, '
                   'clawforge_security_engine, clawforge_policy_engine, clawforge_incidents, clawforge_executor, '
                   'clawforge_backup', r.sig);
  END LOOP;
END $$;

DELETE FROM _sqlx_migrations WHERE version BETWEEN 59 AND 64;
DO $$
BEGIN
  IF (SELECT max(version) FROM _sqlx_migrations) <> 58 OR (SELECT count(*) FROM _sqlx_migrations) <> 54 THEN
    RAISE EXCEPTION 'rollback aborted: ledger is not back at 58 / 54 rows';
  END IF;
END $$;
COMMIT;
SELECT 'archived in schema ' || :'arch' AS result;
