# Feed providers

The `clawforge-intelligence` crate defines the provider lifecycle:

```text
fetch -> validate -> normalize -> store -> risk consumer
```

Prepared phase‑1 adapters are ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar, and Spamhaus DROP. Each has its own provider ID, endpoint, interval, confidence, timeout, and authentication setting. The adapter normalizes IPs, URLs, hashes, and network prefixes into the shared indicator model and deduplicates values within a synchronization run.

ThreatFox, URLhaus, and MalwareBazaar use their API-key variables (`THREATFOX_AUTH_KEY`, `URLHAUS_AUTH_KEY`, and `MALWAREBAZAAR_AUTH_KEY`). Feodo Tracker and Spamhaus use public endpoints as configured. The URLhaus API currently rejects unauthenticated requests; treating the key as required makes that failure explicit before a sync starts. Public availability and provider terms may change, so the worker records HTTP, rate-limit, timeout, and validation failures in `provider_status` and applies exponential backoff.

No provider result directly blocks traffic. Indicators are persisted, sent to the risk consumer, and retained with first-seen, last-seen, expiry, source, confidence, and reason data.

Run `scripts/test-provider-smoke.sh` for bounded live endpoint checks. It tests the public Feodo and Spamhaus feeds and checks the authenticated ThreatFox, URLhaus, and MalwareBazaar APIs when their environment keys are available. It does not start the scheduler or write to PostgreSQL.
