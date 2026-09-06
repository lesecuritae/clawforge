# Architecture

Clawforge is split into transport, collection, intelligence, scoring, policy, and storage boundaries. Providers produce normalized indicators and network observations. The risk and trust engines calculate bounded scores and reasons. The policy crate is the only place that can translate an assessment into an action, and it requires corroborating signals for a block decision.

The Rust workspace is intentionally a new implementation rather than a line-by-line Python port. KorbKlar namespaces, runtime code, and supermarket-specific behavior are excluded.

## Current phase

The API starts with `/health` and `/ready`, connects to PostgreSQL, and runs sqlx migrations. The worker starts a Tokio lifecycle loop and records database health. Provider adapters, feed scheduling, and the intelligence consumer are extension points for subsequent phases; no provider is automatically enabled in this scaffold.

## Data flow

```text
provider -> normalizer -> indicator/network store -> risk + trust -> policy -> response
```

Raw feeds do not reach an LLM or a blocking action. An LLM, when added, receives evaluated evidence and explanations only.
