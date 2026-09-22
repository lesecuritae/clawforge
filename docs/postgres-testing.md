# PostgreSQL testing

Storage integration tests run against an isolated PostgreSQL test container
rather than SQLite. The repository helper migrates the database, provisions
all runtime roles, and executes both persistence and permission-boundary tests:

```sh
./scripts/test-postgres.sh
```

The suite proves that runtime connections cannot migrate, service roles cannot
read or mutate unrelated domains, audit rows remain append-only, and the backup
role cannot write.
