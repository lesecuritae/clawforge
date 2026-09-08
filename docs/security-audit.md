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
  advisory. Binary-level `cargo audit bin` scans of the API and MCP release
  binaries recovered their production dependency sets and reported no
  advisories. CI must keep both checks visible and revisit the lockfile result
  when an upstream fix is released.

## Application security audit (2026-09-08)

The active application audit repeated authentication, authorization, input,
MCP, container, frontend, and dependency checks against the running Compose
deployment. It also exercised malformed IDs, unknown query fields, bounded and
extreme pagination values, wrong-scope tokens, foreign resource IDs, rate
limits, MCP discovery, invalid MCP credentials, and redaction behavior.

### Findings fixed during this audit

- **Unauthenticated legacy intelligence and network reads (high):** the
  unversioned `/intelligence/*` and `/network/*` read routes accepted requests
  without authentication. They now require a valid bearer token, a read role,
  and an audit record, matching the protected API surface. Unauthenticated
  probes now return `401` without data.
- **Unbounded MCP request bodies (medium):** the MCP adapter previously had a
  response-size guard but no request-size guard. Streamable HTTP requests are
  now limited to 256 KiB and oversized authenticated requests return `413`.
- **Framework parser diagnostics (medium):** malformed UUID paths and extreme
  query values returned Axum's parser text before authentication could produce
  the stable API envelope. A global rejection sanitizer now returns only
  `400 invalid request` for framework path/query failures.
- **Host port exposure (medium):** the Compose defaults published API and
  frontend ports on every host interface. Defaults now bind both ports to
  `127.0.0.1`; an operator must explicitly set host bind variables to expose
  them externally.

### Active results

- Missing, invalid, expired, revoked, and wrong-scope credentials produced
  `401`/`403` envelopes without response data. Scope escalation and access to
  foreign incident IDs were denied.
- MCP discovery and all registered tools remain read-only. Invalid credentials
  are rejected before upstream access; malformed parameters and oversized
  requests are bounded and sanitized. The MCP adapter contains no SQL, SQLx,
  database URL, or direct Event Backbone access.
- Frontend source checks found no `dangerouslySetInnerHTML`, `innerHTML`,
  `eval`, token logging, or raw-payload rendering. API `401` responses trigger
  session handling, and sensitive values are not part of the rendered models.
- Compose inspection confirmed non-root application containers, read-only
  filesystems, dropped capabilities, `no-new-privileges`, internal backend
  networking, loopback-only default host ports, and secret-file mounts limited
  to ignored example-backed files.

The complete regression commands and the final re-test results are recorded
below after the fixes were applied.

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

### Fixed: unauthenticated legacy intelligence and network reads

The legacy intelligence and network handlers now authenticate bearer tokens,
enforce the existing read roles, and emit audit events. This closes the only
unauthenticated data-read path found by the active audit without changing the
underlying intelligence, risk, trust, or event logic.

### Fixed: missing MCP request-size bound

The MCP Streamable HTTP adapter now rejects request bodies larger than 256 KiB
before they reach tool dispatch. The limit complements the existing 1 MiB
response bound and prevents oversized-parameter resource exhaustion.

### Fixed: framework parser detail disclosure

The API now normalizes Axum path/query extractor failures into the same generic
error envelope used by application validation. Inputs and parser internals are
not echoed to unauthenticated callers.

### Fixed: default host exposure

Compose now uses `CLAWFORGE_API_HOST` and `CLAWFORGE_FRONTEND_HOST`, both
defaulting to `127.0.0.1`. Public exposure is an explicit deployment choice.

## Remaining controlled risks

- The optional `sqlx-mysql` lockfile advisory must be monitored until an
  upstream fixed release is available; the production build uses PostgreSQL
  only. A lockfile-only finding cannot be removed without replacing SQLx or
  changing the database layer, while the compiled production binaries are
  clean.
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
