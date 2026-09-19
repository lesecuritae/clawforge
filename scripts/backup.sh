#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

backup_dir="${1:-${CLAWFORGE_BACKUP_DIR:-./backups}}"
[ ! -L "$backup_dir" ] || { echo "backup directory must not be a symlink: $backup_dir" >&2; exit 1; }
mkdir -p "$backup_dir"
chmod 700 "$backup_dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
tmp="$(mktemp "$backup_dir/clawforge-${stamp}.XXXXXX.dump.tmp")"
dump="${tmp%.tmp}"
cleanup() { [ -z "${tmp:-}" ] || rm -f "$tmp"; }
trap cleanup EXIT INT TERM

docker compose exec -T postgres sh -ec \
  'export PGPASSWORD="$(cat /run/secrets/postgres_password)"; pg_dump --format=custom --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  >"$tmp"
docker compose exec -T postgres sh -ec 'cat >/tmp/clawforge-validate.dump; pg_restore --list /tmp/clawforge-validate.dump >/dev/null; rm -f /tmp/clawforge-validate.dump' <"$tmp"
chmod 600 "$tmp"
mv "$tmp" "$dump"
tmp=""

retention_days="${CLAWFORGE_BACKUP_RETENTION_DAYS:-14}"
find "$backup_dir" -type f -name 'clawforge-*.dump' -mtime "+${retention_days}" -delete
printf '%s\n' "$dump"
