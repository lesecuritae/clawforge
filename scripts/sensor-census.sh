#!/usr/bin/env bash
# Read-only census of what the security sensors actually delivered (acceptance evidence).
#   sensor-census.sh [days]      (default 7) - run on the host that can docker exec into the database
# Reports per sensor: last authenticated delivery, and per day / event type the number of events.
# Every statement is bounded (statement_timeout) and touches security_events by received_at only.
set -euo pipefail
DAYS="${1:-7}"
case "$DAYS" in ''|*[!0-9]*) echo "days must be an integer" >&2; exit 2;; esac
PGC="${CLAWFORGE_POSTGRES_CONTAINER:-clawforge-postgres-1}"
psqlq() { docker exec -i "$PGC" psql -U "${POSTGRES_USER:-clawforge}" -d "${POSTGRES_DB:-clawforge}" -X -At -F ' | ' -v ON_ERROR_STOP=1 "$@"; }
echo "== sensors (enabled, not revoked): name | last delivery | age"
psqlq -c "SET statement_timeout='10s'; SELECT name, COALESCE(last_seen_at::text,'never'), COALESCE(to_char(NOW()-last_seen_at,'DD\"d\" HH24\"h\" MI\"m\"'),'-') FROM security_sensors WHERE enabled AND revoked_at IS NULL ORDER BY name" | grep -v '^SET$'
echo "== events per day: day | sensor | event type | events"
psqlq -c "SET statement_timeout='30s'; SELECT date_trunc('day', e.received_at)::date, s.name, e.event_type, COUNT(*) FROM security_events e JOIN security_sensors s ON s.id=e.sensor_id WHERE e.received_at > NOW() - make_interval(days => $DAYS) GROUP BY 1,2,3 ORDER BY 1,2,3" | grep -v '^SET$'
echo "== http_anomaly status codes (last $DAYS days): status | events | distinct sources"
psqlq -c "SET statement_timeout='30s'; SELECT evidence->>'status_code', COUNT(*), COUNT(DISTINCT resource) FROM security_events WHERE event_type='http_anomaly' AND received_at > NOW() - make_interval(days => $DAYS) GROUP BY 1 ORDER BY 2 DESC" | grep -v '^SET$'
