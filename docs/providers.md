# Feed providers

The `clawforge-intelligence` crate defines the provider lifecycle:

```text
fetch -> validate -> normalize -> store -> risk consumer
```

Prepared phase‑1 adapters are ThreatFox, URLhaus, Feodo Tracker, MalwareBazaar, and Spamhaus DROP. Each has its own provider ID, endpoint, interval, confidence, timeout, and optional authentication variable. The adapter normalizes IPs, URLs, and hashes into the shared indicator model and deduplicates values within a synchronization run.

ThreatFox and MalwareBazaar use their API-key variables. URLhaus, Feodo Tracker, and Spamhaus use their public endpoints as configured. Public availability and provider terms may change, so the worker records HTTP and validation failures in `provider_status` and applies exponential backoff.

No provider result directly blocks traffic. Indicators are persisted, sent to the risk consumer, and retained with first-seen, last-seen, expiry, source, confidence, and reason data.
