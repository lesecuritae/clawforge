# Installation

Clawforge requires Docker Compose v2 and a Docker Engine with named-volume and
secret support. PostgreSQL is the production database; the API and worker images
run as UID/GID `10001`; the Nginx frontend runs as UID/GID `101`.

1. Copy `.env.example` to `.env`.
2. Run `./scripts/init-secrets.sh`. It creates untracked secret files with
   directory mode `0700` and file mode `0600` without overwriting existing
   values. Add real credentials to the optional provider files when needed.
3. Run `./scripts/validate-secrets.sh --bootstrap` for a fresh installation.
   Deployment fails closed when a required
   file is missing, weak, duplicated, world-readable, or still contains a
   known placeholder.
4. Start the base stack with `docker compose up -d --build`.
5. Wait for `curl --fail http://127.0.0.1:8080/ready` and inspect `/version`.

The base stack does not mount the one-time administrator bootstrap credential.
For a fresh database, temporarily recreate only the API with the bootstrap
overlay:

```sh
docker compose -f compose.yml -f compose.bootstrap.yml up -d clawforge-api
# POST the one-time token to /admin/auth/bootstrap, then remove it from runtime:
docker compose up -d --force-recreate clawforge-api
rm secrets/admin_bootstrap_token
./scripts/validate-secrets.sh
```

The optional MCP service is behind the `agent` profile. First replace
`secrets/mcp_agent_api_token` with a scoped, read-only token issued by the
Agent API, then run `docker compose --profile agent up -d clawforge-mcp`.

Feed and network jobs are disabled by default. Enable them deliberately in
`.env`; a feed is always passed through the risk and policy boundaries.
