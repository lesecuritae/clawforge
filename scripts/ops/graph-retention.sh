#!/usr/bin/env bash
# Reviewed retention procedure for the two correlation graph tables (docs/graph-retention.md).
#   graph-retention.sh census
#       read-only, bounded: sizes, estimated relation-type mix, newest/oldest sampled rows
#   graph-retention.sh swap <table> <keep|cap> [--go]
#       builds <table>_keep with the rows worth keeping (copy only, the live table is untouched),
#       then - with --go - renames in one short transaction after a final delta copy:
#           <table>        -> <table>_archive_<UTC stamp>   (nothing deleted, disk not yet freed)
#           <table>_keep   -> <table>
#       Without --go it stops after building and verifying <table>_keep.
#   graph-retention.sh archive-dump <archive table> <directory>
#       pg_dump -Fc of one archive table to a directory on another disk + sha256 + pg_restore --list
#   graph-retention.sh drop-archive <archive table> --verified-archive <dump file>
#       the only destructive step: refuses unless the dump exists, has a stored checksum that
#       still matches, and lists its table data. Needs an operator decision; never run by a release.
# Environment: CLAWFORGE_POSTGRES_CONTAINER (default clawforge-postgres-1), POSTGRES_USER/DB.
set -euo pipefail
PGC="${CLAWFORGE_POSTGRES_CONTAINER:-clawforge-postgres-1}"
PGU="${POSTGRES_USER:-clawforge}"; PGD="${POSTGRES_DB:-clawforge}"
psqlx() { docker exec -i "$PGC" psql -U "$PGU" -d "$PGD" -X -At -v ON_ERROR_STOP=1 "$@"; }
die() { echo "ERROR: $*" >&2; exit 1; }
cmd="${1:-}"; shift || true

# Keep predicates (evaluated on the live table). Only these two tables and these two policies exist.
#  event_relationships / keep: every edge that is not a source-only edge, plus source-only edges of the
#    last 24 hours (the correlation window still uses them). The source-only edges between ordinary
#    events were the quadratic write amplification fixed in 1.2.0 and carry no information a
#    shared-indicator / shared-correlation-id edge does not.
#  incident_relations / cap: every row that is not an event_relationship copy, plus the earliest 100
#    event_relationship copies of each incident (what an operator can read in an incident view).
keep_predicate() {
  case "$1:$2" in
    event_relationships:keep) echo "relation_type <> 'shared-source' OR created_at > now() - interval '24 hours'" ;;
    incident_relations:cap) echo "relation_type <> 'event_relationship' OR id IN (SELECT r.id FROM incidents i CROSS JOIN LATERAL (SELECT id FROM incident_relations x WHERE x.incident_id = i.id AND x.relation_type = 'event_relationship' ORDER BY x.created_at, x.id LIMIT 100) r) OR created_at > now() - interval '24 hours'" ;;
    *) die "no reviewed policy '$2' for table '$1'" ;;
  esac
}

case "$cmd" in
census)
  psqlx -c "SET statement_timeout='60s'; SELECT relname, pg_size_pretty(pg_total_relation_size(c.oid)) total, reltuples::bigint est_rows FROM pg_class c WHERE relname IN ('event_relationships','incident_relations','event_delivery','events') AND relkind='r' ORDER BY pg_total_relation_size(c.oid) DESC" | grep -v '^SET$'
  psqlx -c "SELECT tablename||'.'||attname||': '||most_common_vals::text||' '||most_common_freqs::text FROM pg_stats WHERE tablename IN ('event_relationships','incident_relations') AND attname='relation_type'"
  psqlx -c "SET statement_timeout='60s'; SELECT 'event_relationships newest sampled row: '||max(created_at) FROM event_relationships TABLESAMPLE SYSTEM (0.01)" | grep -v '^SET$'
  psqlx -c "SELECT n_tup_ins AS inserts_since_stats_reset, n_dead_tup FROM pg_stat_user_tables WHERE relname='event_relationships'" ;;
swap)
  table="${1:?table}"; policy="${2:?policy}"; shift 2 || true
  GO=0; for a in "$@"; do [ "$a" = "--go" ] && GO=1; done
  pred="$(keep_predicate "$table" "$policy")"
  keep="${table}_keep"; stamp="$(date -u +%Y%m%dt%H%M%Sz)"; archive="${table}_archive_${stamp}"
  [ "$(psqlx -c "select to_regclass('public.$keep') is not null")" = f ] || die "$keep already exists - inspect and drop it by hand first"
  echo "building $keep from $table where: $pred"
  # LIKE ... INCLUDING ALL copies defaults, check constraints and indexes (primary/unique keys included);
  # the kept set is small, so building the indexes before the copy is cheap.
  psqlx -c "SET lock_timeout='5s'" -c "CREATE TABLE $keep (LIKE $table INCLUDING ALL)"
  psqlx -c "SET statement_timeout=0" -c "INSERT INTO $keep SELECT * FROM $table WHERE $pred"
  kept="$(psqlx -c "select count(*) from $keep")"; echo "kept rows: $kept"
  [ "$GO" = 1 ] || { echo "built and verified $keep ($kept rows); not swapped (no --go)"; exit 0; }
  psqlx <<SQL
BEGIN;
SET LOCAL lock_timeout = '10s';
LOCK TABLE $table IN SHARE ROW EXCLUSIVE MODE;
-- rows written while the copy ran
INSERT INTO $keep SELECT t.* FROM $table t WHERE ($pred) AND NOT EXISTS (SELECT 1 FROM $keep k WHERE k.id = t.id);
ALTER TABLE $table RENAME TO $archive;
ALTER TABLE $keep RENAME TO $table;
-- free the index names: the archive keeps its indexes under new names, the kept table takes the usual ones
DO \$\$
DECLARE r record;
BEGIN
  FOR r IN SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename = '$archive' LOOP
    EXECUTE format('ALTER INDEX %I RENAME TO %I', r.indexname, left(r.indexname, 45) || '_a' || substr(md5(r.indexname), 1, 8));
  END LOOP;
  FOR r IN SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename = '$table' AND indexname LIKE '%$keep%' LOOP
    EXECUTE format('ALTER INDEX %I RENAME TO %I', r.indexname, replace(r.indexname, '$keep', '$table'));
  END LOOP;
END \$\$;
COMMIT;
SQL
  echo "SWAPPED: $table now holds the kept rows; every original row is in $archive (disk is freed only by drop-archive after archive-dump)" ;;
archive-dump)
  table="${1:?archive table}"; dir="${2:?directory}"
  case "$table" in *_archive_*) ;; *) die "only <table>_archive_<stamp> tables can be dumped here" ;; esac
  mkdir -p "$dir"; f="$dir/$table.dump"
  docker exec "$PGC" pg_dump -U "$PGU" -d "$PGD" -Fc -t "public.$table" > "$f"
  sha256sum "$f" > "$f.sha256"
  docker exec -i "$PGC" pg_restore --list < "$f" | grep -q "TABLE DATA public $table" || die "dump has no table data"
  echo "archive written: $f $(du -h "$f" | cut -f1); sha256 stored; table data listed" ;;
drop-archive)
  table="${1:?archive table}"; flag="${2:-}"; dump="${3:-}"
  [ "$flag" = "--verified-archive" ] && [ -f "$dump" ] || die "needs --verified-archive <dump file>"
  case "$table" in *_archive_*) ;; *) die "only <table>_archive_<stamp> tables can be dropped here" ;; esac
  sha256sum -c "$dump.sha256" >/dev/null || die "stored checksum does not match the dump"
  docker exec -i "$PGC" pg_restore --list < "$dump" | grep -q "TABLE DATA public $table" || die "dump does not contain $table"
  psqlx -c "DROP TABLE public.$table"; echo "dropped $table (archive: $dump)" ;;
*) echo "usage: $0 census | swap <table> <keep|cap> [--go] | archive-dump <archive table> <dir> | drop-archive <archive table> --verified-archive <dump>"; exit 2 ;;
esac
