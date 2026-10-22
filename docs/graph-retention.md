# Correlation graph retention plan

Status: reviewed procedure and tooling, **nothing applied to production**. Every step that frees
disk space needs an explicit operator decision (see "Decisions that are not ours").

## Measured facts (production, 2026-10-22)

| Table | Size (table + indexes) | Content |
|---|---|---|
| `event_relationships` | ~44 + 45 GB | 99.96 % `shared-source` edges (`pg_stats` most-common value) |
| `incident_relations` | ~48 + 44 GB | 99.47 % copies of `event_relationship` edges |
| `event_delivery` (analyzer consumer) | ~1.58 M rows, growing ~2/s | claimed by nobody, see `docs/event-delivery.md` |

* No foreign key points *into* either graph table, so a table can be swapped without cascades.
* `shared-source` edges join ordinary events that merely came from the same source. They were the
  quadratic write amplification fixed in 1.2.0 and carry no information that a shared-indicator or
  shared-correlation-id edge does not. The correlation window only reads the last hours.
* ~210 k incidents were created mostly by network-inventory events (RouteViews/RIS prefix rows
  published as `bgp_change`, and `asn_change` on every sync). The worker no longer publishes
  those (`fix(worker): network inventory is not a security event`). Existing incidents are
  untouched.

All numbers come from `pg_stats`/`pg_class` and bounded samples; no full scan of the 90 GB tables
was run (heavy diagnostics on them starved PostgreSQL once - keep `statement_timeout` set).

## Procedure (`scripts/ops/graph-retention.sh`)

Nothing is deleted before the archive is proven restorable.

1. **Census** (read-only, bounded): `graph-retention.sh census`.
2. **Build** the kept set as a *copy*: `graph-retention.sh swap event_relationships keep` and
   `graph-retention.sh swap incident_relations cap`. The live table is not touched; the script
   stops after building and counting `<table>_keep`. Run outside the backup window (~22:17-23:30 UTC)
   and with `nice`/low I/O priority so Plex transcodes are not starved.
   * `event_relationships` keeps every edge that is not `shared-source`, plus `shared-source` edges
     of the last 24 h.
   * `incident_relations` keeps every row that is not an `event_relationship` copy, the earliest 100
     copies of each incident (what an incident view can show) and the last 24 h.
3. **Swap** (`... --go`): one short transaction takes `SHARE ROW EXCLUSIVE`, copies the delta written
   during the build, renames `<table>` to `<table>_archive_<stamp>` and `<table>_keep` to `<table>`,
   and restores the usual index names. Writers wait at most 10 s (`lock_timeout`); nothing is lost,
   disk is not freed yet. Rollback: rename the two tables back.
4. **Archive**: `graph-retention.sh archive-dump <archive table> /mnt/plex/seagate22/<dir>`
   (`pg_dump -Fc`, sha256, `pg_restore --list` must list the table data; ~14 TB free there).
5. **Restore proof**: restore the dump into a scratch database and compare row counts with the
   archive table. Record the result in the release status file.
6. **Drop** (`drop-archive <archive table> --verified-archive <dump>`): the only destructive step.
   It refuses without the dump, a matching `.sha256` and table data in the dump. Never run by a
   release or by an automated job.

Index rename gotcha found while testing: the archive stamp must be lowercase, otherwise PostgreSQL
identifier folding breaks the index lookup (the script uses `%Y%m%dt%H%M%Sz`).

Tested on synthetic data only (fixture database). The script has not been run against production.

## Analyzer consumer backlog

Recommendation, in order of preference:

1. Keep `CLAWFORGE_ANALYZER_EVENT_CONSUMER=false` and stop the growth with
   `UPDATE event_consumers SET enabled=false WHERE name='analyzer'` (reversible; `ensure_event_consumer`
   re-enables it when the consumer is started).
2. If the analyzer consumer is wanted later, start it under a **new consumer name** so it begins at a
   cut-off instead of receiving the whole backlog since 2026-09-23.
3. Archive the old delivery rows with the same dump-and-prove procedure before any deletion. Rows are
   never marked consumed to make the backlog look empty.

## Decisions that are not ours

* Approve the keep/cap policies above (or name a different window) before step 3.
* Whether the ~210 k `detected` incidents caused by inventory events are closed, archived or kept.
* Approval of step 6 per table, after the restore proof.
* Whether to disable the analyzer consumer row now (option 1).
