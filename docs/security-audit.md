# Clawforge Security Audit

## Scope and environment

The controlled audit was run on the local Docker Compose deployment in
`/srv/docker/clawforge` on 2026-09-08. It covered the API, Agent API v1,
MCP adapter, PostgreSQL, worker, event/correlation/incident services, notifier,
frontend, backup service, Compose networks, and the repository contents.
The deployment exposes the API on `127.0.0.1:8080` (configurable), the
frontend on `127.0.0.1:3000` (configurable), and keeps the MCP endpoint on the
internal `backend` network. The MCP endpoint is
`http://clawforge-mcp:8090/mcp`; no MCP host port is published.

The tests used the configured local read-only Agent/MCP test credentials only
for verification. Credential values are stored in ignored Docker Secret files
and are not included in this report.

## Test coverage

### Authentication and authorization

- Agent API access without a token returned `401` with no data.
- Invalid bearer credentials returned `401` with no data.
- A valid token without the requested scope returned `403` with no data.
- The configured token was checked against a resource outside its scope.
- MCP requests without a token and with an invalid token were rejected before
  tool discovery or upstream access.
- Agent tokens are hashed, scoped, expiring, revocable, and audited. MCP has a
  separate service token and remains read-only.

### Input and response handling

- Invalid query values and bounded pagination are covered by API tests.
- Malformed incident identifiers are authenticated first and return the
  generic `400 invalid incident identifier` response. Parser details are not
  exposed.
- Agent and MCP responses use redaction and bounded result sizes. Raw feed
  payloads, credentials, internal service tokens, database URLs, and secret
  fields are excluded by tests and repository scans.
- No write-capable MCP tool or direct MCP database access exists.

### Containers and network

- Application containers run as UID/GID `10001`, use read-only filesystems,
  drop all capabilities, set `no-new-privileges`, and use bounded PID/tmpfs
  limits.
- PostgreSQL and internal services are on the internal Compose backend
  network. Only the API and frontend ports are published by default.
- Compose health checks passed for all enabled services; `/ready` reported all
  18 migrations applied and current.
- Secret values are mounted through Docker Secrets. No secret files are
  tracked by Git.

### Dependency and web checks

- `npm audit --omit=dev` reported zero vulnerabilities.
- Nginx sends CSP, `X-Content-Type-Options`, `X-Frame-Options`, Referrer
  Policy, and Permissions Policy headers.
- `docker compose config`, image builds, health checks, API smoke tests, MCP
  authentication tests, frontend tests/build, and the Rust test/lint suite
  passed.
- `cargo audit` found one medium advisory (`RUSTSEC-2023-0071`) in the
  lockfile's optional `sqlx-mysql` dependency. Clawforge enables only
  `sqlx-postgres` (`default-features = false`), so the vulnerable MySQL path is
  not compiled or reachable. RustSec reports no fixed upgrade for that
  advisory; CI must keep the audit visible and revisit it when an upstream fix
  is released.

## Findings and fixes

### Fixed: alert aggregation failure with an empty alert table

The Operations Summary returned `503 operations alerts unavailable` when the
alert table was empty because aggregate values were decoded without an
explicit PostgreSQL `bigint` contract. The query now uses explicit, non-null
`bigint` values and typed tuple decoding. A live request now returns `200` with
zero-valued alert groups.

### Fixed: malformed Agent API incident IDs exposed parser details

The incident detail, timeline, and relations handlers used typed UUID path
extractors. An invalid unauthenticated path could therefore expose a framework
parser message. These handlers now authenticate first, parse a string through a
generic validator, and return only `400 invalid incident identifier`.

## Remaining controlled risks

- The optional `sqlx-mysql` lockfile advisory must be monitored until an
  upstream fixed release is available; the production build uses PostgreSQL
  only.
- TLS termination, WAF policy, and external network exposure remain deployment
  responsibilities; the Compose defaults bind the API/frontend ports for the
  local host and do not configure public TLS.
- A full OpenClaw/OpenRouter live test requires operator-supplied external
  credentials and was not repeated as part of this local security audit.

## Reproduction commands

```text
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm --prefix frontend test
npm --prefix frontend run build
docker compose config --quiet
docker compose up -d --build
curl http://127.0.0.1:8080/ready
docker compose ps
```

The audit is controlled and read-only: it creates no production incidents,
alerts, provider data, or policy changes.
