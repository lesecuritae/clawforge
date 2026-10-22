-- Return the ledger from 1.2.2 (migrations 0065 and 0066) to 1.2.1 (ledger 64) so the 1.2.1
-- images accept the database. Nothing is dropped: 0065 only added an index (unused by 1.2.1,
-- harmless) and 0066 only inserted the policy row of rule `ssh_bruteforce_slow` (inert: 1.2.1
-- has no such rule). Re-running the 1.2.2 migrations afterwards finds both present and is a no-op
-- (CREATE INDEX IF NOT EXISTS, INSERT ... ON CONFLICT DO NOTHING).
\set ON_ERROR_STOP on
BEGIN;
LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
  IF (SELECT max(version) FROM _sqlx_migrations) <> 66
     OR (SELECT count(*) FROM _sqlx_migrations WHERE version IN (65, 66) AND success) <> 2
     OR (SELECT count(*) FROM _sqlx_migrations WHERE NOT success) <> 0 THEN
    RAISE EXCEPTION 'rollback refused: ledger is not exactly 1.2.1 (64) + 65 + 66';
  END IF;
END $$;
DELETE FROM _sqlx_migrations WHERE version IN (65, 66);
DO $$
BEGIN
  IF (SELECT max(version) FROM _sqlx_migrations) <> 64 THEN
    RAISE EXCEPTION 'rollback aborted: ledger is not back at 64';
  END IF;
END $$;
COMMIT;
