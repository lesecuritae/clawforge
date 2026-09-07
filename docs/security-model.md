# Security model

The worker is an ingestion and scoring service. A feed error, a single indicator, or a single ASN/BGP/RPKI signal cannot trigger a block. The policy boundary remains downstream of risk scoring and requires corroboration before a block decision.

`/health` checks that the process and runtime configuration are valid. `/ready` additionally checks PostgreSQL and verifies that the applied sqlx migration set is complete. `/version` reports the application release and schema state. Database and provider credentials use Compose secret files by default; `.env` and non-example secret files are ignored by Git.

Trusted infrastructure is administrator-registered and must be `Verified`. Tailscale, NetBird, VLAN, VPN, IP ranges, ASNs, and prefixes do not receive trust from their technology name. Risk history and audit events remain append-oriented so feed and trust decisions can be explained later.

## API rate limits

The API applies an in-process global bucket and an endpoint bucket keyed by a hashed bearer token. Unauthenticated login and bootstrap requests are keyed by the connection address; raw tokens and addresses are never written to audit details. `/health` and `/ready` are exempt for orchestration probes.

The default endpoint windows are five login attempts per minute, three bootstrap attempts per hour, ten export requests per minute, 120 reads per minute, and 60 writes per minute. Administrator, Operator, and Viewer credentials receive role-specific read/write/export limits. A rejected request returns `429 Too Many Requests`, `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers. Each rejection creates an `api_rate_limit_exceeded` audit event.
