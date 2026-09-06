# Clawforge

Clawforge is an independent Rust security-intelligence service. This repository is the new implementation boundary; the KorbKlar Python prototype is reference material only and is not a runtime dependency.

The initial workspace contains the API, worker, intelligence domain, risk engine, policy boundary, and PostgreSQL storage crates. The first migration creates provider, indicator, ASN, BGP, risk/trust history, audit, and trusted-network tables.

## Start locally with Docker

```sh
cp .env.example .env
# set a private POSTGRES_PASSWORD in .env
docker compose up --build
curl http://localhost:8080/health
```

The worker currently provides the runtime lifecycle and database health loop. Feed adapters and scheduled synchronization are migrated incrementally; no new provider is enabled by this scaffold and no feed can block traffic directly.

## Layout

- `api/`: Axum REST entry point
- `worker/`: Tokio worker lifecycle and future feed scheduler
- `intelligence/`: provider-independent normalized domain types
- `risk/`: bounded risk/trust calculation
- `policy/`: multi-signal decision boundary
- `storage/`: PostgreSQL/sqlx abstraction and migrations
- `migrations/`: sqlx migration files
- `docs/`: architecture, security, runtime, and migration notes

See [docs/architecture.md](docs/architecture.md) for the migration plan.
