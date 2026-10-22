#!/usr/bin/env bash
# Strict PATCH rehearsal (production already on 1.2.x): copy of the CURRENT production schema + ledger -> new patch -> patch rollback
# -> forward again, on a throw-away PostgreSQL. Production is only READ (pg_dump of schema and of the
# small tables; the five giant relation/event tables are copied schema-only).
#
#   rehearse-patch.sh <previous-patch-image> <new-image> <roles-script> <state-dir> [<start-ledger> [<top-migration>]]
#   default: start 64/60 and the 1.2.2 patch (migrations 65, 66, rollback-1.2.2-to-1.2.1.sql);
#   later patches: e.g. 66/62 and top 67 (rollback-last-migration.sql, additive migrations only)
#
# Fails closed: every restore step runs with ON_ERROR_STOP=1, every check is an assertion against an
# explicit expected value, and the exit code is non-zero if any assertion failed. It does NOT claim a
# full-size restore: the giant tables carry no rows in the fixture.
set -uo pipefail
PREV_IMG="$1"; NEW_IMG="$2"; NEW_ROLES="$3"; D="$4"; START="${5:-64/60}"; TOP="${6:-}"
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
assert ledger-0 "$(P -c "select max(version)||'/'||count(*) from _sqlx_migrations")" "$START"
ROUTE_ROWS="$(P -c "select count(*) from indicators where value like '0.0.0.0/0%' or categories ? 'network-intelligence'")"
say "  info indicators of network-context kind in the copy: $ROUTE_ROWS"
for t in "${GIANTS[@]}"; do assert "giant $t schema present" "$(P -c "select to_regclass('public.$t') is not null")" t; done
# every public base table of prod exists in the fixture
assert table-count "$(P -c "select count(*) from pg_tables where schemaname='public'")" "$(PP -c "select count(*) from pg_tables where schemaname='public'")"

NFILES="$(ls "$REPO"/migrations/*.sql | wc -l)"
NMAX="$(ls "$REPO"/migrations/*.sql | sed -E 's#.*/([0-9]+)_.*#\1#' | sort -n | tail -1 | sed 's/^0*//')"
MIG_PREV(){ docker run --rm --network "$N" -e DATABASE_URL_FILE=/s/database_url -v "$D/secrets:/s:ro" "$PREV_IMG" /usr/local/bin/clawforge-migrate; }
MIG_NEW(){ docker run --rm --network "$N" -e DATABASE_URL_FILE=/s/database_url -v "$D/secrets:/s:ro" "$NEW_IMG" /usr/local/bin/clawforge-migrate; }
ROLES(){ docker run --rm --network "$N" -e PGHOST=postgres -e PGPORT=5432 -e POSTGRES_USER=clawforge -e POSTGRES_DB=clawforge \
  $(for r in api worker correlation security_engine policy_engine incidents executor backup; do echo "-e CLAWFORGE_DATABASE_$(echo $r | tr a-z A-Z)_PASSWORD_SECRET_FILE=/s/database_${r}_password"; done) \
  -e CLAWFORGE_POSTGRES_SECRET_FILE=/s/postgres_password -v "$D/secrets:/s:ro" -v "$1:/r.sh:ro" postgres:16-alpine sh /r.sh; }
LEDGER_SIG(){ P -c "select max(version)||'/'||count(*)||'/'||md5(string_agg(version||':'||encode(checksum,'hex'),',' order by version)) from _sqlx_migrations"; }

say "== phase 0: current production state (roles as deployed, previous patch migrate is a no-op)"
assert "roles script (as deployed) exit" "$(ROLES "$NEW_ROLES" >> "$LOG" 2>&1; echo $?)" 0
START_SIG="$(LEDGER_SIG)"
assert "previous patch image migrate on the production copy" "$(MIG_PREV >> "$LOG" 2>&1; echo $?)" 0
assert "ledger unchanged by it" "$(LEDGER_SIG)" "$START_SIG"
if [ "$START" = "64/60" ]; then assert "ready index absent before (it is built concurrently on production first)" "$(P -c "select count(*) from pg_indexes where indexname='event_delivery_ready_idx'")" 0; fi

say "== phase 1: patch upgrade"
assert "new image migrate" "$(MIG_NEW >> "$LOG" 2>&1; echo $?)" 0
assert "roles script after migrate" "$(ROLES "$NEW_ROLES" >> "$LOG" 2>&1; echo $?)" 0
assert "ledger" "$(P -c "select max(version)||'/'||count(*) from _sqlx_migrations where success")" "$NMAX/$NFILES"
assert "ready index present and valid" "$(P -c "select indisvalid from pg_index where indexrelid=to_regclass('event_delivery_ready_idx')")" t
assert "slow-rule policy present" "$(P -c "select count(*) from security_policies where rule_id='ssh_bruteforce_slow' and status='active'")" 1
if [ -n "$TOP" ]; then assert "assessment-shape function present" "$(P -c "select count(*) from pg_proc where proname='clawforge_assessment_shape'")" 1; fi
assert "previous patch image REFUSES the newer ledger" "$(MIG_PREV >> "$LOG" 2>&1; [ $? -ne 0 ] && echo refused || echo accepted)" refused
UP1_SIG="$(LEDGER_SIG)"

say "== phase 2: patch rollback and forward again"
if [ -n "$TOP" ]; then
  docker cp "$HERE/rollback-last-migration.sql" "$C:/tmp/rb2.sql"; RBV=(-v "top=$TOP")
else
  docker cp "$HERE/rollback-1.2.2-to-1.2.1.sql" "$C:/tmp/rb2.sql"; RBV=()
fi
assert "patch rollback exit" "$(P "${RBV[@]}" -f /tmp/rb2.sql >> "$LOG" 2>&1; echo $?)" 0
assert "ledger back at the start state" "$(LEDGER_SIG)" "$START_SIG"
assert "previous patch image accepts the database again" "$(MIG_PREV >> "$LOG" 2>&1; echo $?)" 0
assert "ledger untouched by the previous image" "$(LEDGER_SIG)" "$START_SIG"
assert "patch rollback refuses to run twice" "$(P "${RBV[@]}" -f /tmp/rb2.sql >> "$LOG" 2>&1; [ $? -ne 0 ] && echo refused || echo ran)" refused
assert "ready index kept (nothing dropped)" "$(P -c "select count(*) from pg_indexes where indexname='event_delivery_ready_idx'")" 1
assert "slow-rule policy row kept" "$(P -c "select count(*) from security_policies where rule_id='ssh_bruteforce_slow'")" 1
assert "forward again" "$(MIG_NEW >> "$LOG" 2>&1; echo $?)" 0
assert "ledger identical to the first upgrade" "$(LEDGER_SIG)" "$UP1_SIG"
finish
