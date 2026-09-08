# Architecture

Clawforge is split into transport, collection, intelligence, scoring, policy, and storage boundaries. Providers produce normalized indicators and network observations. The risk and trust engines calculate bounded scores and reasons. The policy crate is the only place that can translate an assessment into an action, and it requires corroborating signals for a block decision.

The Rust workspace is intentionally a new implementation rather than a line-by-line Python port. KorbKlar namespaces, runtime code, and supermarket-specific behavior are excluded.

## Current phase

The API connects to PostgreSQL, runs sqlx migrations, and exposes health/readiness, intelligence, network, trust, incident, alert, and Prometheus metrics endpoints. The worker runs a Tokio lifecycle loop with provider and network jobs, retry/backoff, status persistence, risk consumption, typed audit events, and optional Redis run locking. The separate `clawforge-correlation` service consumes the existing event delivery stream, derives bounded event relationships, and stores incident candidates without changing backbone events or taking policy actions. The separate `clawforge-incidents` service promotes open candidates into lifecycle-managed incidents and preserves event/indicator relations. High-impact operational events create advisory alert records; delivery remains delegated to the existing notification service and status changes are audited. The MCP adapter is stateless, read-only, and consumes only Agent API v1. Jobs remain disabled by default and no provider event performs a block action.

## Data flow

```text
provider -> normalizer -> indicator/network store -> risk + trust -> policy -> response
```

Network providers use the same boundary for ASN, BGP, and RPKI data. Their normalized records are persisted in PostgreSQL and converted into evaluated evidence before policy handling. Network providers never perform blocking actions themselves.

Raw feeds do not reach an LLM or a blocking action. The optional `clawforge-analyzer` service receives only the API's sanitized incident context through an internal API and stores structured explanations. It cannot change risk, trust, policy, providers, or permissions.

## Event backbone

Canonical events are persisted in `events` and fanned out through
`event_consumers` and `event_delivery`. The event service and notifier use
internal service tokens, retry failed deliveries with backoff, and move
repeated failures to a dead-letter state. Event payloads are filtered before
storage; consumers cannot change risk, trust, policy, or provider state.


## v0.4 Intelligence explanation layer

The Agent API v1 now exposes stored incident reconstruction, historical operations
trends, a redacted security briefing, and a service/provider dependency graph.
The MCP adapter maps these four read-only resources without direct storage access;
all new scopes are checked by both adapter and API. The dashboard renders the
same contracts and never performs new risk or correlation calculations.
