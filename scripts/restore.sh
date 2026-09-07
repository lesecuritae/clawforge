#!/usr/bin/env bash
set -Eeuo pipefail

dump="${1:?usage: scripts/restore.sh BACKUP.dump}"
test -s "$dump"
docker compose exec -T postgres sh -ec 'cat >/tmp/clawforge-validate.dump; pg_restore --list /tmp/clawforge-validate.dump >/dev/null; rm -f /tmp/clawforge-validate.dump' <"$dump"

docker compose up -d postgres >/dev/null
until docker compose exec -T postgres pg_isready -U "${POSTGRES_USER:-clawforge}" -d "${POSTGRES_DB:-clawforge}" >/dev/null 2>&1; do
  sleep 2
done

docker compose exec -T postgres sh -ec '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  dropdb --if-exists -U "$POSTGRES_USER" -h 127.0.0.1 --maintenance-db postgres "$POSTGRES_DB"
  createdb -U "$POSTGRES_USER" -h 127.0.0.1 "$POSTGRES_DB"
'
cat "$dump" | docker compose exec -T postgres sh -ec '
  export PGPASSWORD="$(cat /run/secrets/postgres_password)"
  pg_restore --exit-on-error --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"
'
echo "restore completed: $dump"
