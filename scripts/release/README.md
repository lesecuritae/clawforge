# Release tooling

| File | Purpose |
|---|---|
| `rehearse-upgrade.sh` | Strict rehearsal of a MINOR upgrade from the fork-lineage production schema (ledger 58): upgrade -> rollback -> old-version migrate -> re-upgrade -> restore. 67 assertions. |
| `rehearse-patch.sh` | Strict rehearsal of a PATCH on a copy of the CURRENT production schema: new migrate, previous image refuses the newer ledger, patch rollback, forward again (36 assertions). |
| `rollback-1.2-to-1.1.sql`, `restore-rollback-archive.sql` | Data-preserving rollback to 1.1.x (the one 1.2-only table is archived, never dropped) and the copy-back after a re-upgrade. |
| `rollback-last-migration.sql` | Ledger one migration down (`-v top=N`) for purely additive migrations (e.g. 0067); refuses unless N is the newest successful migration. `rehearse-patch.sh ... <start-ledger> <top>` rehearses it. |
| `rollback-1.2.2-to-1.2.1.sql` | Ledger 66 -> 64 only; the index and the policy row stay. |
| `check-role-grants.sql` | Must return no rows: every `clawforge_*` SECURITY DEFINER function is executable by some `clawforge_*` role. Asserted in `rehearse-patch.sh` and in the production `verify` phase. |
| `disable-retired-providers.sql` | Disable the registry rows of retired providers (reversible). |

Rehearsals read production only through `pg_dump` (schema and the small tables; the giant relation/event tables are schema-only),
run in a throw-away container on an internal network, and exit non-zero on any failed assertion. They do not prove a full-size restore.

## Production roles script must follow the tag

The `clawforge-db-roles` service mounts `scripts/provision-db-roles.sh` from the production checkout, not from
the release image. A release that adds a grant must install the tagged script there before the db-roles run
(release scripts copy it from the checked-out tag, keep a backup and re-run the service) and `verify` must run
`check-role-grants.sql` plus a scan of the policy-engine log for `permission denied`. Release 1.2.3 skipped
this: the stale production copy lacked `GRANT EXECUTE ON FUNCTION clawforge_assessment_shape`, so the policy
engine could not evaluate and produced no shadow decisions from 2026-10-22 21:34 UTC until the grant was applied
on 2026-10-23 12:52 UTC (no enforcement path was involved; the bridge is off).
