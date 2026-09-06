# Runtime and operations

`compose.yml` runs `clawforge-api`, `clawforge-worker`, and PostgreSQL. Redis is present only under the optional `cache` profile. Both application services wait for PostgreSQL health and use the same sqlx migration set. See [deployment.md](deployment.md) and [configuration.md](configuration.md) for operations.

Configuration is supplied through environment variables. Keep `.env` and database credentials outside version control. PostgreSQL's named volume is the primary persistence layer; take a database dump before upgrades and preserve the configuration and trusted-network registry together.

For a PostgreSQL integration test, set `CLAWFORGE_TEST_DATABASE_URL` to an isolated PostgreSQL 16 container and run the ignored storage test. The backup/restore script validates a real dump and restore cycle.
