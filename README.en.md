<div align="center">
  <img src="assets/branding/clawforge-horizontal.svg" width="600" alt="Clawforge Security Platform logo">
  <h1>Clawforge Security Platform</h1>
  <p><strong>Security intelligence for observable, policy-driven protection.</strong></p>
</div>

[🇩🇪 Deutsch](README.de.md) · [🇬🇧 English](README.en.md)

![Clawforge Security Platform](assets/branding/rebranding-announcement.png)

Clawforge is an independent Rust security-intelligence platform. It combines threat-intelligence feeds, network data, risk and trust scoring, incidents, alerts, PostgreSQL persistence, Agent API v1, and a read-only MCP adapter for OpenClaw. No single feed can directly block traffic.

## Included

- Provider adapters for ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar, and Spamhaus
- Indicator validation, normalization, deduplication, and expiry handling
- Explainable Risk Engine with multi-signal protection
- PostgreSQL persistence with sqlx migrations, provider status, and risk history
- Trusted Infrastructure as an explicitly registered trust signal
- Health/readiness, intelligence, network, trust, and Prometheus metrics API endpoints with graceful shutdown
- Read-only Agent API v1 and scoped MCP tools with redaction, timeouts, and an OpenClaw contract

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
curl http://127.0.0.1:8080/version
```

Feed synchronization is disabled by default. Authenticated providers require private Docker secret files. See [docs/configuration.md](docs/configuration.md), [docs/providers.md](docs/providers.md), [docs/production.md](docs/production.md), [docs/openclaw-integration.md](docs/openclaw-integration.md), [docs/openclaw-architecture.md](docs/openclaw-architecture.md), and [docs/openclaw-config.example.json](docs/openclaw-config.example.json) for configuration and operations.

## Layout

- `api/` — Axum REST API
- `worker/` — Tokio worker and feed scheduler
- `intelligence/` — providers and normalized intelligence data
- `risk/` — risk and trust evaluation
- `storage/` — PostgreSQL/sqlx boundary
- `migrations/` — sqlx migrations
- `docs/` — architecture, operations, and security model

See [docs/architecture.md](docs/architecture.md) for the architecture. The project is released under the [Apache License 2.0](LICENSE).
