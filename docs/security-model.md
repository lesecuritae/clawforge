# Security model

The worker is an ingestion and scoring service. A feed error, a single indicator, or a single ASN/BGP/RPKI signal cannot trigger a block. The policy boundary remains downstream of risk scoring and requires corroboration before a block decision.

`/health` checks that the process and runtime configuration are valid. `/ready` additionally checks PostgreSQL and verifies that the applied sqlx migration set is complete. `/version` reports the application release and schema state. Database and provider credentials use Compose secret files by default; `.env` and non-example secret files are ignored by Git.

Trusted infrastructure is administrator-registered and must be `Verified`. Tailscale, NetBird, VLAN, VPN, IP ranges, ASNs, and prefixes do not receive trust from their technology name. Risk history and audit events remain append-oriented so feed and trust decisions can be explained later.

## API rate limits

The API applies an in-process global bucket and an endpoint bucket keyed by a hashed bearer token. Unauthenticated login and bootstrap requests are keyed by the connection address; raw tokens and addresses are never written to audit details. `/health` and `/ready` are exempt for orchestration probes.

The default endpoint windows are five login attempts per minute, three bootstrap attempts per hour, ten export requests per minute, 120 reads per minute, and 60 writes per minute. Administrator, Operator, and Viewer credentials receive role-specific read/write/export limits. A rejected request returns `429 Too Many Requests`, `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers. Each rejection creates an `api_rate_limit_exceeded` audit event.

## Internal events

The event backbone accepts only structured, filtered payloads. Keys containing
raw feeds, secrets, tokens, passwords, or API keys are removed before an event
is persisted. Event and consumer endpoints require an internal Docker Secret
service token; administrative event reads require an Administrator or Operator
credential. Delivery retries are bounded and dead-lettered without triggering
security actions.

## Agent and alert boundaries

Agent API v1 and the Rust MCP adapter are read-only. Agent tokens carry
explicit scopes and the MCP service has no database or Event Backbone access;
it can only forward redacted API responses. Each successful agent read is
audited, while credentials and raw payloads are never returned.

High and critical operational events may create an advisory alert record with
source, severity, lifecycle status and delivery status. Alerts do not change
risk, trust or policy and do not execute remediation. Acknowledgement,
resolution and suppression are role-protected and audited. Notification
delivery remains an independent, optional concern.
