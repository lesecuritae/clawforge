# Deployment

Clawforge runs as three Compose services: `clawforge-api`, `clawforge-worker`, and PostgreSQL. Redis is optional under the `cache` profile and is not required for correctness.

1. Copy `.env.example` to `.env`.
2. Create private secret files from `secrets/*.example` and set `CLAWFORGE_POSTGRES_SECRET_FILE` and `CLAWFORGE_DATABASE_URL_SECRET_FILE` in `.env`.
3. Start with `docker compose up -d --build`.
4. Verify `curl http://127.0.0.1:8080/health` and `/ready`.

The API image runs database migrations before listening. The readiness endpoint reports the PostgreSQL connection and applied migration count. Stop safely with `docker compose down`; preserve the named PostgreSQL volume for normal upgrades.

Before upgrades, run a logical backup:

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > backup.sql
```

The repository includes `scripts/test-backup-restore.sh`, which exercises a real PostgreSQL container, dump, volume removal, restore, and integrity query.
