#!/usr/bin/env bash
# Strict upgrade rehearsal: production fork schema + ledger -> 1.2.0 -> rollback -> 1.1.0 migrate
# -> 1.2.0 again, on a throw-away PostgreSQL. Production is only READ (pg_dump of schema and of the
# small tables; the five giant relation/event tables are copied schema-only).
#
#   rehearse-upgrade.sh <old-image> <new-image> <old-roles-script> <new-roles-script> <state-dir>
#
# Fails closed: every restore step runs with ON_ERROR_STOP=1, every check is an assertion against an
# explicit expected value, and the exit code is non-zero if any assertion failed. It does NOT claim a
# full-size restore: the giant tables carry no rows in the fixture.
set -uo pipefail
OLD_IMG="$1"; NEW_IMG="$2"; OLD_ROLES="$3"; NEW_ROLES="$4"; D="$5"
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/../.." && pwd)"
PROD=clawforge-postgres-1
C=clawforge-rehearsal-pg; N=clawforge-rehearsal-net
GIANTS=(incident_relations event_relationships event_delivery events audit_events risk_history incident_candidate_events security_events)
CRITICAL=(_sqlx_migrations indicators security_policies actions)
mkdir -p "$D/secrets"; chmod 700 "$D"; chmod 755 "$D/secrets"   # container uid 10001 must traverse the bind-mounted directory
LOG="$D/rehearsal.log"; : > "$LOG"; RESULT="$D/result.json"; FAILS=0; PASSES=0
say(){ echo "$*" | tee -a "$LOG"; }
assert(){ if [ "$2" = "$3" ]; then PASSES=$((PASSES+1)); say "  PASS $1 = $3"; else FAILS=$((FAILS+1)); say "  FAIL $1: got '$2' want '$3'"; fi; }
cleanup(){ docker rm -f "$C" >/dev/null 2>&1; docker network rm "$N" >/dev/null 2>&1; }
finish(){ cleanup; printf '{"passes":%s,"fails":%s,"success":%s}\n' "$PASSES" "$FAILS" "$([ "$FAILS" = 0 ] && echo true || echo false)" > "$RESULT"
  say "RESULT passes=$PASSES fails=$FAILS"; [ "$FAILS" = 0 ]; exit $?; }
abort(){ say "ABORT: $*"; FAILS=$((FAILS+1)); finish; }
trap 'cleanup' EXIT
cleanup

for s in postgres_password database_api_password database_worker_password database_correlation_password database_security_engine_password database_policy_engine_password database_incidents_password database_executor_password database_backup_password; do
  [ -s "$D/secrets/$s" ] || head -c 40 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24 > "$D/secrets/$s"
done
printf 'postgres://clawforge:%s@postgres:5432/clawforge' "$(cat "$D/secrets/postgres_password")" > "$D/secrets/database_url"
chmod 644 "$D"/secrets/*   # throw-away secrets; the non-root migrate image must read them
docker network create --internal "$N" >/dev/null || abort "network"
docker run -d --name "$C" --network "$N" --network-alias postgres -e POSTGRES_USER=clawforge -e POSTGRES_DB=clawforge \
  -e POSTGRES_PASSWORD_FILE=/s/postgres_password -v "$D/secrets:/s:ro" postgres:16-alpine >/dev/null || abort "postgres container"
for i in $(seq 1 60); do docker exec "$C" pg_isready -h 127.0.0.1 -U clawforge >/dev/null 2>&1 && break; sleep 2; done
sleep 4
P(){ docker exec -i "$C" psql -h 127.0.0.1 -U clawforge -d clawforge -v ON_ERROR_STOP=1 -At "$@"; }
PP(){ docker exec -i "$PROD" psql -U clawforge -d clawforge -v ON_ERROR_STOP=1 -At "$@"; }

say "== fixture: schema (strict)"
docker exec "$PROD" pg_dump -U clawforge -d clawforge -s --no-owner --no-privileges | P -q > "$D/schema-restore.log" 2>&1 \
  || abort "schema restore failed: $(tail -3 "$D/schema-restore.log")"
assert schema-restore-errors "$(grep -c ERROR "$D/schema-restore.log")" 0
say "== fixture: data of small tables (strict)"
EXC=(); for t in "${GIANTS[@]}"; do EXC+=(-T "public.$t"); done
docker exec "$PROD" pg_dump -U clawforge -d clawforge -a --disable-triggers "${EXC[@]}" | P -q > "$D/data-restore.log" 2>&1 \
  || abort "data restore failed: $(tail -3 "$D/data-restore.log")"
assert data-restore-errors "$(grep -c ERROR "$D/data-restore.log")" 0
for t in "${CRITICAL[@]}"; do
  assert "rows($t) prod==fixture" "$(P -c "select count(*) from $t")" "$(PP -c "select count(*) from $t")"
done
assert ledger-md5 "$(P -c "select md5(string_agg(version||':'||encode(checksum,'hex'),',' order by version)) from _sqlx_migrations")" \
  "$(PP -c "select md5(string_agg(version||':'||encode(checksum,'hex'),',' order by version)) from _sqlx_migrations")"
assert ledger-0 "$(P -c "select max(version)||'/'||count(*) from _sqlx_migrations")" "58/54"
ROUTE_ROWS="$(P -c "select count(*) from indicators where value like '0.0.0.0/0%' or categories ? 'network-intelligence'")"
say "  info indicators of network-context kind in the copy: $ROUTE_ROWS"
for t in "${GIANTS[@]}"; do assert "giant $t schema present" "$(P -c "select to_regclass('public.$t') is not null")" t; done
# every public base table of prod exists in the fixture
assert table-count "$(P -c "select count(*) from pg_tables where schemaname='public'")" "$(PP -c "select count(*) from pg_tables where schemaname='public'")"

NFILES="$(ls "$REPO"/migrations/*.sql | wc -l)"
NMAX="$(ls "$REPO"/migrations/*.sql | sed -E 's#.*/([0-9]+)_.*#\1#' | sort -n | tail -1 | sed 's/^0*//')"
MIG_OLD(){ docker run --rm --network "$N" -e DATABASE_URL_FILE=/s/database_url -v "$D/secrets:/s:ro" "$OLD_IMG" /usr/local/bin/clawforge-migrate; }
MIG_NEW(){ docker run --rm --network "$N" -e DATABASE_URL_FILE=/s/database_url -v "$D/secrets:/s:ro" "$NEW_IMG" /usr/local/bin/clawforge-migrate; }
ROLES(){ docker run --rm --network "$N" -e PGHOST=postgres -e PGPORT=5432 -e POSTGRES_USER=clawforge -e POSTGRES_DB=clawforge \
  $(for r in api worker correlation security_engine policy_engine incidents executor backup; do echo "-e CLAWFORGE_DATABASE_$(echo $r | tr a-z A-Z)_PASSWORD_SECRET_FILE=/s/database_${r}_password"; done) \
  -e CLAWFORGE_POSTGRES_SECRET_FILE=/s/postgres_password -v "$D/secrets:/s:ro" -v "$1:/r.sh:ro" postgres:16-alpine sh /r.sh; }
LEDGER_SIG(){ P -c "select max(version)||'/'||count(*)||'/'||md5(string_agg(version||':'||encode(checksum,'hex'),',' order by version)) from _sqlx_migrations"; }
priv(){ P -c "select has_function_privilege('$1','$2','EXECUTE')"; }
UPGRADE_CHECKS(){ # $1 = label
  assert "$1 ledger" "$(P -c "select max(version)||'/'||count(*) from _sqlx_migrations where success")" "$NMAX/$NFILES"
  assert "$1 all-ledger-rows-success" "$(P -c "select count(*) from _sqlx_migrations where not success")" 0
  assert "$1 source_network_context in public" "$(P -c "select to_regclass('public.source_network_context') is not null")" t
  assert "$1 resolver exists" "$(P -c "select count(*) from pg_proc where proname='clawforge_resolve_incident_source_for_apply'")" 1
  assert "$1 bridge-plan overloads" "$(P -c "select count(*) from pg_proc where proname='clawforge_policy_bridge_plan'")" 1
  if [ "$ROUTE_ROWS" -ge 1 ]; then
    assert "$1 0.0.0.0/0-style context row does not match 1.2.3.4" "$(P -c "select count(*) from clawforge_ip_reputation('1.2.3.4'::inet)")" 0
  fi
}
GRANT_CHECKS(){ # $1 = label, $2 = expected for the new-function grants (t/f)
  assert "$1 executor may resolve" "$(priv clawforge_executor 'clawforge_resolve_incident_source_for_apply(uuid)')" "$2"
  assert "$1 policy_engine may plan" "$(priv clawforge_policy_engine 'clawforge_policy_bridge_plan(uuid,text,text,integer,uuid,text,integer,boolean,integer)')" "$2"
  assert "$1 worker may list network context" "$(priv clawforge_worker 'clawforge_network_context_targets(integer,integer,integer)')" "$2"
  assert "$1 api may NOT record network context" "$(priv clawforge_api 'clawforge_record_network_context(text,text,cidr,bigint[],text,text,integer,integer,text)')" f
}

say "== phase 0: production-state roles (old script, as deployed today)"
ROLES "$OLD_ROLES" >> "$LOG" 2>&1; assert old-roles-script-exit "$?" 0
OLD_SIG="$(LEDGER_SIG)"
P -c "select pg_get_functiondef(p.oid) from pg_proc p where p.proname='clawforge_enqueue_goaway_shadow_challenge'" > "$D/old-goaway-enqueue.sql"
assert old-goaway-function-count "$(P -c "select count(*) from pg_proc where proname='clawforge_enqueue_goaway_shadow_challenge'")" 1
printf '\n;\n' >> "$D/old-goaway-enqueue.sql"
OLD_GOAWAY_MD5="$(P -c "select md5(pg_get_functiondef(p.oid)) from pg_proc p where p.proname='clawforge_enqueue_goaway_shadow_challenge'")"
assert "1.1.0 migrate on the production-state copy" "$(MIG_OLD >> "$LOG" 2>&1; echo $?)" 0
assert "ledger unchanged by 1.1.0 migrate" "$(LEDGER_SIG)" "$OLD_SIG"

say "== phase 1: upgrade to 1.2.0"
assert "1.2.0 migrate" "$(MIG_NEW >> "$LOG" 2>&1; echo $?)" 0
assert "new roles script (no ops/decision secrets)" "$(ROLES "$NEW_ROLES" >> "$LOG" 2>&1; echo $?)" 0
UPGRADE_CHECKS up1
GRANT_CHECKS up1 t
assert "up1 ops/decision roles cannot log in" "$(P -c "select count(*) from pg_roles where rolname in ('clawforge_operations','clawforge_decision') and rolcanlogin")" 0
assert "up1 runtime roles can log in" "$(P -c "select count(*) from pg_roles where rolname like 'clawforge\\_%' and rolcanlogin")" 8
assert "up1 1.1.0 migrate REFUSES the newer ledger" "$(MIG_OLD >> "$LOG" 2>&1; [ $? -ne 0 ] && echo refused || echo accepted)" refused
UP1_SIG="$(LEDGER_SIG)"
P -c "insert into source_network_context(pseudonym,status,prefix,origin_asns,rpki,source,expires_at) values ('rehearsal-pseudonym','ok','192.0.2.0/24',ARRAY[64500]::bigint[],'valid','ripestat', now()+interval '1 day')"

say "== phase 2: rollback (data preserving)"
docker cp "$HERE/rollback-1.2-to-1.1.sql" "$C:/tmp/rb.sql"; docker cp "$D/old-goaway-enqueue.sql" "$C:/tmp/old.sql"
RB="$(P -v goaway_def_file=/tmp/old.sql -f /tmp/rb.sql 2>>"$LOG")"; assert rollback-exit "$?" 0
echo "$RB" >> "$LOG"
ARCH="$(printf '%s\n' "$RB" | sed -n 's/.*archived in schema //p' | tail -1)"
assert archive-schema-name "$(printf '%s' "$ARCH" | grep -c '^clawforge_rollback_')" 1
assert "archive keeps the row" "$(P -c "select count(*) from \"$ARCH\".source_network_context where pseudonym='rehearsal-pseudonym'")" 1
assert "public.source_network_context moved" "$(P -c "select to_regclass('public.source_network_context') is null")" t
assert "ledger back to 58/54 (same md5 as production)" "$(LEDGER_SIG)" "$OLD_SIG"
assert "1.1.0 goaway function restored byte-exact" "$(P -c "select md5(pg_get_functiondef(p.oid)) from pg_proc p where p.proname='clawforge_enqueue_goaway_shadow_challenge'")" "$OLD_GOAWAY_MD5"
GRANT_CHECKS rolled-back f
assert "1.1.0 migrate accepts the rolled-back database" "$(MIG_OLD >> "$LOG" 2>&1; echo $?)" 0
assert "ledger untouched by 1.1.0 migrate" "$(LEDGER_SIG)" "$OLD_SIG"
assert "rollback refuses to run twice" "$(P -v goaway_def_file=/tmp/old.sql -f /tmp/rb.sql >> "$LOG" 2>&1; [ $? -ne 0 ] && echo refused || echo ran)" refused

say "== phase 3: re-upgrade to 1.2.0 and restore archived data"
assert "1.2.0 migrate again" "$(MIG_NEW >> "$LOG" 2>&1; echo $?)" 0
assert "new roles script again" "$(ROLES "$NEW_ROLES" >> "$LOG" 2>&1; echo $?)" 0
UPGRADE_CHECKS up2
GRANT_CHECKS up2 t
assert "ledger identical to first upgrade" "$(LEDGER_SIG)" "$UP1_SIG"
assert "new table starts empty" "$(P -c "select count(*) from public.source_network_context")" 0
docker cp "$HERE/restore-rollback-archive.sql" "$C:/tmp/restore.sql"
assert "restore script" "$(P -v arch="$ARCH" -f /tmp/restore.sql >> "$LOG" 2>&1; echo $?)" 0
assert "archived row restored" "$(P -c "select count(*) from public.source_network_context where pseudonym='rehearsal-pseudonym' and origin_asns=ARRAY[64500]::bigint[]")" 1
assert "restore is idempotent" "$(P -v arch="$ARCH" -f /tmp/restore.sql >> "$LOG" 2>&1; P -c "select count(*) from public.source_network_context")" 1
assert "archive still present (nothing deleted)" "$(P -c "select count(*) from \"$ARCH\".source_network_context")" 1
finish
