# Feed providers

The `clawforge-intelligence` crate defines the provider lifecycle:

```text
fetch -> validate -> normalize -> store -> risk consumer
```

Prepared phase‑1 adapters are ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar, Spamhaus DROP, Spamhaus EDROP, and Spamhaus ASN-DROP. Each has its own provider ID, endpoint, interval, confidence, timeout, and authentication setting. The adapter normalizes IPs, URLs, hashes, network prefixes, and ASNs into the shared indicator model and deduplicates values within a synchronization run.

ThreatFox, URLhaus, and MalwareBazaar read credentials from the Docker secret files configured by `CLAWFORGE_THREATFOX_SECRET_FILE`, `CLAWFORGE_URLHAUS_SECRET_FILE`, and `CLAWFORGE_MALWAREBAZAAR_SECRET_FILE`. Direct environment values remain available for isolated local smoke tests only. Feodo Tracker and Spamhaus use public endpoints as configured. The URLhaus API currently rejects unauthenticated requests; treating the key as required makes that failure explicit before a sync starts. Public availability and provider terms may change, so the worker records HTTP, rate-limit, timeout, and validation failures in `provider_status` and applies exponential backoff.

Spamhaus DROP and EDROP use the published prefix feeds. EDROP may legally respond with a merge notice instead of prefixes; that response is accepted as a valid empty synchronization. ASN-DROP uses the official newline-delimited JSON endpoint (`asndrop.json`) and stores numeric ASN records as `AS<number>` indicators.

No provider result directly blocks traffic. Indicators are persisted, sent to the risk consumer, and retained with first-seen, last-seen, expiry, source, confidence, and reason data. Provider status records the last successful sync, last error, next run, runtime, indicator count, and newest indicator timestamp so data age is queryable as `NOW() - last_data_at`.

Network providers and their PostgreSQL/Risk Engine integration are documented in [network-intelligence.md](network-intelligence.md).

Run `scripts/test-provider-smoke.sh` for bounded live endpoint checks. It tests the public Feodo and Spamhaus DROP/EDROP/ASN feeds and checks the authenticated ThreatFox, URLhaus, and MalwareBazaar APIs when their environment keys are available. It does not start the scheduler or write to PostgreSQL. The script sets `CLAWFORGE_ENABLE_FEEDS=true` only for the validation process; credentials are never printed or persisted.
