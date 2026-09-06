#!/usr/bin/env sh
set -eu

container="clawforge-backup-test-$$"
restored="clawforge-backup-restore-$$"
volume="clawforge-backup-volume-$$"
dump="$(mktemp)"
cleanup() {
  docker rm -f "$container" "$restored" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
  rm -f "$dump"
}
trap cleanup EXIT INT TERM

docker volume create "$volume" >/dev/null
docker run -d --name "$container" -e POSTGRES_DB=clawforge_test -e POSTGRES_USER=clawforge -e POSTGRES_PASSWORD=test-password -v "$volume:/var/lib/postgresql/data" postgres:16-alpine >/dev/null
until docker exec "$container" pg_isready -U clawforge -d clawforge_test >/dev/null 2>&1; do sleep 1; done
docker exec "$container" psql -U clawforge -d clawforge_test -c "CREATE TABLE backup_probe (id integer PRIMARY KEY, value text NOT NULL); INSERT INTO backup_probe VALUES (1, 'persisted');" >/dev/null
docker exec "$container" pg_dump -U clawforge -d clawforge_test >"$dump"
docker rm -f "$container" >/dev/null
docker volume rm "$volume" >/dev/null

docker volume create "$volume" >/dev/null
docker run -d --name "$restored" -e POSTGRES_DB=clawforge_test -e POSTGRES_USER=clawforge -e POSTGRES_PASSWORD=test-password -v "$volume:/var/lib/postgresql/data" postgres:16-alpine >/dev/null
until docker exec "$restored" pg_isready -U clawforge -d clawforge_test >/dev/null 2>&1; do sleep 1; done
docker exec -i "$restored" psql -U clawforge -d clawforge_test <"$dump" >/dev/null
value="$(docker exec "$restored" psql -U clawforge -d clawforge_test -Atc "SELECT value FROM backup_probe WHERE id=1")"
[ "$value" = "persisted" ]
echo "backup/restore integrity: ok"
