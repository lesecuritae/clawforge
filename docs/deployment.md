# Deployment

Clawforge runs as API, worker, event backbone, notifier, frontend, PostgreSQL,
and scheduled backup Compose services. `clawforge-analyzer` is isolated behind
the `analysis` profile; Redis is optional under the `cache` profile and is not
required for correctness.

## Published release images

The v1.0 Compose file supports published GHCR images and local builds. The
production release registry is:

```text
ghcr.io/lesecuritae/clawforge-<service>
```

Published services are `api`, `mcp`, `frontend`, `correlation`, `incidents`,
`worker`, and `executor`. Internal events and notifier services use the same
release source in the standard Compose deployment.

```sh
cp .env.example .env
# keep the immutable release tag for production
CLAWFORGE_IMAGE_TAG=v1.0.0
docker compose pull
docker compose up -d
```

Use `docker compose build && docker compose up -d` for a local build. The
published images carry OCI title, description, version, revision, source, and
Apache-2.0 license labels. GitHub Actions publishes linux/amd64 and linux/arm64
when tests and security checks pass. Use `v1.0.0` or `1.0.0` in production;
`1.0` and `latest` are convenience tags.

## Fresh installation

1. Install Docker Engine and the Docker Compose plugin.
2. Copy `.env.example` to `.env` and configure the image tag and ports.
3. Create private secret files from `secrets/*.example`; never commit them.
4. Run `docker compose pull && docker compose up -d` (or build locally).
5. Verify the API with `curl http://127.0.0.1:8080/health` and
   `curl http://127.0.0.1:8080/ready`.
6. Verify `curl http://127.0.0.1:8080/version` and MCP health from the internal
   network at `http://clawforge-mcp:8090/health`.

The API applies sqlx migrations before listening. `/ready` reports the
PostgreSQL connection and applied migration count. Stop safely with
`docker compose down`; preserve the named PostgreSQL volume for upgrades.

## Upgrade from v0.x

1. Create and verify a PostgreSQL backup.
2. Set `CLAWFORGE_IMAGE_TAG=v1.0.0`.
3. Pull the release images and restart Compose:

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > backup-before-v1.sql
docker compose pull
docker compose up -d
```

The API applies forward migrations before becoming ready. Wait for `/ready`,
then verify incident data, audit history, provider status, frontend access,
MCP health, and MCP discovery. Do not delete the PostgreSQL volume during an
ordinary upgrade. Use the documented restore procedure for rollback.

## Backups and profiles

Before upgrades, run the documented logical backup and retention workflow in
[backup.md](backup.md). The repository includes
`scripts/test-backup-restore.sh`, which exercises a real PostgreSQL container,
dump, volume removal, restore, and integrity query.

Enable optional services explicitly:

```sh
docker compose --profile analysis up -d
docker compose --profile cache up -d
docker compose --profile observability up -d
```

The analyzer remains isolated and receives only sanitized incident context.
Redis is a lock/cache helper; PostgreSQL remains the source of truth.
