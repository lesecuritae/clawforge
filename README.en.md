<div align="center">
  <img src="assets/branding/clawforge-horizontal.svg" width="600" alt="Clawforge Security Platform logo">
  <h1>Clawforge Security Platform</h1>
  <p><strong>Security intelligence for observable, policy-driven protection.</strong></p>
</div>

[🇩🇪 Deutsch](README.de.md) · [🇬🇧 English](README.en.md)

![Clawforge Security Platform](assets/branding/rebranding-announcement.png)

Clawforge is an independent Rust security-intelligence platform. It combines threat-intelligence feeds, network data, risk and trust scoring, PostgreSQL persistence, and a policy boundary. The current version consists of an Axum API and a Tokio worker. No single feed can directly block traffic.

## Included

- Provider adapters for ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar, and Spamhaus
- Indicator validation, normalization, deduplication, and expiry handling
- Explainable Risk Engine with multi-signal protection
- PostgreSQL persistence with sqlx migrations, provider status, and risk history
- Trusted Infrastructure as an explicitly registered trust signal
- `/health` and `/ready` API endpoints with graceful shutdown

## Quick start

```bash
cp .env.example .env
docker compose up -d --build
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```

Feed synchronization is disabled by default. Authenticated providers require `THREATFOX_AUTH_KEY`, `URLHAUS_AUTH_KEY`, and `MALWAREBAZAAR_AUTH_KEY`. See [docs/configuration.md](docs/configuration.md), [docs/providers.md](docs/providers.md), and [docs/deployment.md](docs/deployment.md) for configuration and operations.

## Layout

- `api/` — Axum REST API
- `worker/` — Tokio worker and feed scheduler
- `intelligence/` — providers and normalized intelligence data
- `risk/` — risk and trust evaluation
- `storage/` — PostgreSQL/sqlx boundary
- `migrations/` — sqlx migrations
- `docs/` — architecture, operations, and security model

See [docs/architecture.md](docs/architecture.md) for the architecture. The project is released under the [Apache License 2.0](LICENSE).
