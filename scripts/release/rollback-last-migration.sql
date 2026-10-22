-- Return the ledger by ONE additive migration so the previous patch image accepts the database:
--   psql -v ON_ERROR_STOP=1 -v top=67 -f rollback-last-migration.sql
-- Only for migrations that create no table/column and change no existing function (0067 only adds
-- a read-only function): nothing is dropped, re-running the migration is a no-op
-- (CREATE OR REPLACE). A migration that creates tables needs an archiving rollback like
-- rollback-1.2-to-1.1.sql instead.
\set ON_ERROR_STOP on
BEGIN;
LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE;
SELECT (max(version) = :top
        AND count(*) FILTER (WHERE version = :top AND success) = 1
        AND count(*) FILTER (WHERE NOT success) = 0) AS ok FROM _sqlx_migrations \gset
-- a refused rollback fails loudly (division by zero) and the transaction is rolled back
SELECT 1 / (CASE WHEN :'ok'::boolean THEN 1 ELSE 0 END) AS rollback_allowed;
DELETE FROM _sqlx_migrations WHERE version = :top;
SELECT 1 / (CASE WHEN max(version) = :top - 1 THEN 1 ELSE 0 END) AS ledger_is_one_below FROM _sqlx_migrations;
COMMIT;
