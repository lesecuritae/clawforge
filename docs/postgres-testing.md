# PostgreSQL testing

Storage integration tests should run against an isolated PostgreSQL test container rather than SQLite. A CI job can start `postgres:16-alpine`, wait for `pg_isready`, set `CLAWFORGE_TEST_DATABASE_URL`, and execute:

```sh
cargo test -p clawforge-storage --test postgres -- --ignored
```

The migration set is applied on connect, so restart and persistence checks use the same schema path as the runtime services.
