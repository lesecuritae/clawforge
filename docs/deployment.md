# Deployment

Clawforge runs as API, worker, frontend, PostgreSQL, and scheduled backup Compose services. `clawforge-analyzer` is isolated behind the `analysis` profile; Redis is optional under the `cache` profile and is not required for correctness. The analyzer stays on the internal backend network and can be enabled with `docker compose --profile analysis up -d`.

1. Copy `.env.example` to `.env`.
2. Create private secret files from `secrets/*.example` and set the corresponding `CLAWFORGE_*_SECRET_FILE` variables in `.env`.
3. Start with `docker compose up -d --build`.
4. Verify `/health`, `/ready`, and `/version` with `curl`.

The API image runs database migrations before listening. The readiness endpoint reports the PostgreSQL connection and applied migration count. Stop safely with `docker compose down`; preserve the named PostgreSQL volume for normal upgrades.

Before upgrades, run a logical backup:

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > backup.sql
```

The repository includes `scripts/test-backup-restore.sh`, which exercises a real PostgreSQL container, dump, volume removal, restore, and integrity query.
