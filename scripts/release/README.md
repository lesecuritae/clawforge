# Release tooling

| File | Purpose |
|---|---|
| `rehearse-upgrade.sh` | Strict rehearsal of a MINOR upgrade from the fork-lineage production schema (ledger 58): upgrade -> rollback -> old-version migrate -> re-upgrade -> restore. 67 assertions. |
| `rehearse-patch.sh` | Strict rehearsal of a PATCH on a copy of the CURRENT production schema: new migrate, previous image refuses the newer ledger, patch rollback, forward again (36 assertions). |
| `rollback-1.2-to-1.1.sql`, `restore-rollback-archive.sql` | Data-preserving rollback to 1.1.x (the one 1.2-only table is archived, never dropped) and the copy-back after a re-upgrade. |
| `rollback-1.2.2-to-1.2.1.sql` | Ledger 66 -> 64 only; the index and the policy row stay. |
| `disable-retired-providers.sql` | Disable the registry rows of retired providers (reversible). |

Rehearsals read production only through `pg_dump` (schema and the small tables; the giant relation/event tables are schema-only),
run in a throw-away container on an internal network, and exit non-zero on any failed assertion. They do not prove a full-size restore.
