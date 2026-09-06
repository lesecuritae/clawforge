# Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | unset | PostgreSQL connection URL; takes precedence over the file form |
| `DATABASE_URL_FILE` | unset | Secret-file alternative used by API and worker |
| `CLAWFORGE_API_BIND` | `0.0.0.0:8080` | API listen address |
| `CLAWFORGE_API_PORT` | `8080` | Host port in Compose |
| `CLAWFORGE_WORKER_POLL_SECONDS` | `60` | Scheduler tick interval, with a five-second minimum |
| `CLAWFORGE_ENABLE_FEEDS` | `false` | Enables the prepared phase‑1 feed jobs |
| `THREATFOX_AUTH_KEY` | unset | ThreatFox API key, required when feeds are enabled |
| `URLHAUS_AUTH_KEY` | unset | URLhaus API key, required by the current API |
| `MALWAREBAZAAR_AUTH_KEY` | unset | MalwareBazaar API key, required when feeds are enabled |
| `RUST_LOG` | `info` | Structured log filter |

Feed jobs remain disabled until `CLAWFORGE_ENABLE_FEEDS=true`. Provider intervals are defined by the adapter and are clamped to a safe minimum. Credentials are read from environment variables and never stored in indicators.
