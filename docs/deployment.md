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
./scripts/init-secrets.sh
./scripts/validate-secrets.sh --bootstrap
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
3. Run `./scripts/init-secrets.sh`, supply optional provider credentials, and
   run `./scripts/validate-secrets.sh --bootstrap`. Generated private files are ignored by
   Git and use `0600` permissions; checked-in example values are never runtime
   defaults. `init-secrets.sh` also generates `secrets/analyzer_ip_hmac_key`:
   with IP anonymization on (`CLAWFORGE_ANALYZER_ANONYMIZE_IPS`, the default),
   this key turns a raw IP into a stable, non-reversible pseudonym before it
   is ever persisted, instead of the fixed placeholder every IP used to
   collapse into (which broke correlation and could fuse unrelated events
   together). Without this key configured, api/worker/correlation/incidents/executor
   refuse to persist or reveal an IP rather than fall back to that unsafe
   placeholder.
4. Run `docker compose pull && docker compose up -d` (or build locally).
5. Temporarily recreate the API with `compose.bootstrap.yml`, complete the
   one-time administrator bootstrap, recreate the API from `compose.yml`, and
   delete `secrets/admin_bootstrap_token`.
6. Verify the API with `curl http://127.0.0.1:8080/health` and
   `curl http://127.0.0.1:8080/ready`.
7. To use MCP, replace `mcp_agent_api_token` with an issued read-only Agent API
   token and start `docker compose --profile agent up -d clawforge-mcp`. Then
   verify its internal health endpoint at `http://clawforge-mcp:8090/health`.
   The Streamable HTTP transport only accepts `localhost`/`127.0.0.1`/`::1`
   `Host` headers by default (DNS-rebinding protection, not authentication).
   A client outside `clawforge-mcp`'s own network namespace — the common case,
   since MCP clients such as OpenClaw run as a separate process or host — is
   refused with `403 Forbidden: Host header is not allowed` until you add its
   connecting authority to `CLAWFORGE_MCP_ALLOWED_HOSTS`. This setting only
   widens the Host allowlist; `mcp_auth_token` remains the actual access
   control and every request still needs it.

   `backend` is `internal: true` by design, so `docker compose`'s `ports:`
   mechanism cannot actually publish a host port for a container on it (the
   binding is accepted and recorded but silently never forwards traffic).
   `clawforge-mcp` therefore gets a fixed address on `backend`
   (`CLAWFORGE_MCP_BACKEND_IP`, default `10.77.77.90`) instead. A client
   running on the same Docker host — OpenClaw's usual deployment — reaches it
   directly over the bridge network at `http://10.77.77.90:8090/mcp`; set
   `CLAWFORGE_MCP_ALLOWED_HOSTS=10.77.77.90:8090` to match (already the
   default in `.env.example`). Change `CLAWFORGE_BACKEND_SUBNET` first if
   `10.77.77.0/24` collides with another Docker network on the host.

The one-shot `clawforge-migrate` service applies sqlx migrations with the
database owner. `clawforge-db-roles` then idempotently provisions separate,
least-privilege accounts for the API, worker, correlation, incidents,
executor, and backup services. Runtime services cannot execute DDL and refuse
to start against a stale or newer schema. `/ready` reports the PostgreSQL
connection and applied migration count. Stop safely with `docker compose
down`; preserve the named PostgreSQL volume for upgrades.

## Upgrade from v0.x

1. Create and verify a PostgreSQL backup.
2. Set `CLAWFORGE_IMAGE_TAG=v1.0.0`.
3. Pull the release images and restart Compose:

```sh
docker compose exec -T postgres pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" > backup-before-v1.sql
docker compose pull
docker compose up -d
```

The migration and role-provisioning jobs must complete successfully before the
runtime services start. Wait for `/ready`,
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
docker compose --profile agent up -d clawforge-mcp
docker compose --profile sensors up -d clawforge-linux-sensor clawforge-haproxy-sensor clawforge-docker-sensor
```

The analyzer remains isolated and receives only sanitized incident context.
Redis is a lock/cache helper; PostgreSQL remains the source of truth.
`sensors` needs its sensor registered and its credential in place first -
see [sensors.md](sensors.md).
