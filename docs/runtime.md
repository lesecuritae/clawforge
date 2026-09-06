# Runtime and operations

`compose.yml` runs `clawforge-api`, `clawforge-worker`, and PostgreSQL. Redis is present only under the optional `cache` profile. Both application services wait for PostgreSQL health and run the same sqlx migration set.

Configuration is supplied through environment variables. Keep `.env` and database credentials outside version control. PostgreSQL's named volume is the primary persistence layer; take a database dump before upgrades and preserve the configuration and trusted-network registry together.

For a PostgreSQL integration test, set `CLAWFORGE_TEST_DATABASE_URL` to an isolated PostgreSQL 16 container and run the ignored storage test. The host in this environment does not include a Rust toolchain, so compilation is intended to run in the Docker builder or a Rust-enabled CI runner.
