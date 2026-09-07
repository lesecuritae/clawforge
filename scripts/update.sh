#!/usr/bin/env bash
set -Eeuo pipefail

backup="$(./scripts/backup.sh "${CLAWFORGE_BACKUP_DIR:-./backups}")"
api_image="$(docker compose config --images | awk '/clawforge-api$/ {print; exit}')"
worker_image="$(docker compose config --images | awk '/clawforge-worker$/ {print; exit}')"
old_api="$(docker compose images -q clawforge-api 2>/dev/null | head -n1 || true)"
old_worker="$(docker compose images -q clawforge-worker 2>/dev/null | head -n1 || true)"

rollback() {
  echo "update failed; restoring previous images and database" >&2
  docker compose down --remove-orphans >/dev/null 2>&1 || true
  if [ -n "$old_api" ] && [ -n "$api_image" ]; then docker image tag "$old_api" "$api_image"; fi
  if [ -n "$old_worker" ] && [ -n "$worker_image" ]; then docker image tag "$old_worker" "$worker_image"; fi
  ./scripts/restore.sh "$backup"
  docker compose up -d --no-build
}
trap rollback ERR

docker compose up -d --build
for attempt in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:${CLAWFORGE_API_PORT:-8080}/ready" >/dev/null; then
    trap - ERR
    echo "update completed; backup: $backup"
    exit 0
  fi
  sleep 2
done
echo "readiness timeout" >&2
exit 1
