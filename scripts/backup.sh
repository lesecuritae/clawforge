#!/usr/bin/env bash
set -Eeuo pipefail

backup_dir="${1:-${CLAWFORGE_BACKUP_DIR:-./backups}}"
mkdir -p "$backup_dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dump="$backup_dir/clawforge-${stamp}.dump"

docker compose exec -T postgres sh -ec \
  'export PGPASSWORD="$(cat /run/secrets/postgres_password)"; pg_dump --format=custom --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  >"$dump"
docker compose exec -T postgres sh -ec 'cat >/tmp/clawforge-validate.dump; pg_restore --list /tmp/clawforge-validate.dump >/dev/null; rm -f /tmp/clawforge-validate.dump' <"$dump"

retention_days="${CLAWFORGE_BACKUP_RETENTION_DAYS:-14}"
find "$backup_dir" -type f -name 'clawforge-*.dump' -mtime "+${retention_days}" -delete
printf '%s\n' "$dump"
