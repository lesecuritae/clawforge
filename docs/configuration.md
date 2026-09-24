# Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | unset | PostgreSQL connection URL for isolated local tests; used only when the file form is not configured |
| `DATABASE_URL_FILE` | unset | Preferred fail-closed secret-file form; Compose mounts a different URL for every database-backed service |
| `CLAWFORGE_DATABASE_URL_SECRET_FILE` | `./secrets/database_url` | Database-owner URL used only by the one-shot migration service |
| `CLAWFORGE_DATABASE_<SERVICE>_URL_SECRET_FILE` | `./secrets/database_<service>_url` | Restricted runtime URL for `API`, `WORKER`, `CORRELATION`, `INCIDENTS`, or `EXECUTOR` |
| `CLAWFORGE_DATABASE_<SERVICE>_PASSWORD_SECRET_FILE` | `./secrets/database_<service>_password` | Matching credential used only by the idempotent role provisioner; application services receive the URL only, while backup receives its read-only password for `pg_dump` |
| `CLAWFORGE_API_BIND` | `0.0.0.0:8080` | API listen address |
| `CLAWFORGE_API_HOST` | `127.0.0.1` | Host bind address in Compose; set explicitly before exposing the API |
| `CLAWFORGE_API_PORT` | `8080` | Host port in Compose |
| `CLAWFORGE_FRONTEND_HOST` | `127.0.0.1` | Frontend host bind address in Compose |
| `CLAWFORGE_FRONTEND_PORT` | `3000` | Frontend host port in Compose |
| `CLAWFORGE_WORKER_POLL_SECONDS` | `60` | Scheduler tick interval, with a five-second minimum |
| `CLAWFORGE_ENABLE_FEEDS` | `false` | Enables the prepared phase‑1 feed jobs |
| `CLAWFORGE_ENABLE_NETWORK` | `false` | Enables ASN, BGP, and RPKI network-provider jobs |
| `CLAWFORGE_THREATFOX_SECRET_FILE` | `./secrets/threatfox_auth_key` | Docker secret file mounted as the ThreatFox credential |
| `CLAWFORGE_URLHAUS_SECRET_FILE` | `./secrets/urlhaus_auth_key` | Docker secret file mounted as the URLhaus credential |
| `CLAWFORGE_MALWAREBAZAAR_SECRET_FILE` | `./secrets/malwarebazaar_auth_key` | Docker secret file mounted as the MalwareBazaar credential |
| `CLAWFORGE_ANALYZER_PROVIDER` | `mock` | Optional analyzer provider (`mock` or an OpenAI-compatible provider name) |
| `CLAWFORGE_ANALYZER_MODEL` | `offline` | Model identifier passed to the analyzer provider |
| `CLAWFORGE_ANALYZER_BASE_URL` | unset | OpenAI-compatible `/chat/completions` base URL for non-mock providers |
| `CLAWFORGE_ANALYZER_SECRET_FILE` | `./secrets/analyzer_token` | Internal API token shared by API and analyzer |
| `CLAWFORGE_ANALYZER_API_KEY_SECRET_FILE` | `./secrets/analyzer_api_key` | Optional provider API key Docker Secret |
| `CLAWFORGE_ANALYZER_TIMEOUT_SECONDS` | `30` | Provider request timeout |
| `CLAWFORGE_ANALYZER_ANONYMIZE_IPS` | `true` | Removes identifying IP values from analysis payloads by default |
| `CLAWFORGE_ANALYZER_EVENT_CONSUMER` | `false` | Optional analyzer consumption of `incident.created` events |
| `CLAWFORGE_ANALYZER_EVENT_POLL_SECONDS` | `10` | Optional analyzer event polling interval |
| `CLAWFORGE_NOTIFIER_SECRET_FILE` | `./secrets/notifier_token` | Internal API token shared by the notifier and API; the value is mounted as a Docker Secret |
| `CLAWFORGE_OPERATIONS_SECRET_FILE` | `./secrets/operations_token` | Dedicated producer token for bounded backup/health operational events; cannot consume queues |
| `CLAWFORGE_NOTIFIER_POLL_SECONDS` | `5` | Notification queue polling interval |
| `CLAWFORGE_NOTIFIER_TIMEOUT_SECONDS` | `15` | Webhook and notification request timeout |
| `CLAWFORGE_NOTIFIER_ALLOWED_HOSTS` | empty | Exact comma-separated outbound DNS allowlist; empty disables notification egress |
| `CLAWFORGE_NOTIFICATION_WEBHOOK_SECRET_FILE` | `./secrets/notifier_webhook_auth` | Optional bearer credential selected only by secret ID `webhook_auth` |
| `CLAWFORGE_NOTIFICATION_MATRIX_SECRET_FILE` | `./secrets/notifier_matrix_auth` | Optional bearer credential selected only by secret ID `matrix_auth` |
| `CLAWFORGE_NOTIFICATION_SMTP_SECRET_FILE` | `./secrets/notifier_smtp_password` | Optional SMTP password selected only by secret ID `smtp_password` |
| `CLAWFORGE_EVENTS_SECRET_FILE` | `./secrets/events_token` | Internal event-backbone service token |
| `CLAWFORGE_EVENTS_POLL_SECONDS` | `5` | Event-backbone polling interval |
| `CLAWFORGE_INCIDENT_POLL_SECONDS` | `5` | Candidate-to-incident promotion interval |
| `CLAWFORGE_RIPESTAT_RESOURCE` | `AS3333` | ASN resource for RIPEstat |
| `CLAWFORGE_HACKERTARGET_RESOURCE` | `3333` | ASN resource for HackerTarget ASlookup (replaced BGPView - `api.bgpview.io` stopped resolving entirely) |
| `CLAWFORGE_PEERINGDB_RESOURCE` | `3333` | ASN resource for PeeringDB |
| `CLAWFORGE_CAIDA_RESOURCE` | `3333` | ASN resource for CAIDA AS Rank |
| `CLAWFORGE_TEAM_CYMRU_RESOURCE` | `8.8.8.8` | IP lookup resource for Team Cymru |
| `CLAWFORGE_RIPE_RIS_RESOURCE` | `AS3333` | ASN resource for RIPE RIS |
| `CLAWFORGE_ROUTEVIEWS_RESOURCE` | `203.0.113.0/24` | Prefix resource for RouteViews |
| `CLAWFORGE_BGPSTREAM_RESOURCE` | `203.0.113.0/24` | Prefix/query resource for BGPStream |
| `CLAWFORGE_RPKI_RESOURCE` | `203.0.113.0/24` | Prefix resource for RPKI validation |
| `REDIS_URL` | unset | Optional Redis URL used only for the scheduler lock |
| `CLAWFORGE_SCHEDULER_LOCK_KEY` | `clawforge:scheduler:lock` | Redis lock key for one active worker run |
| `CLAWFORGE_BACKUP_INTERVAL_SECONDS` | `86400` | Automated PostgreSQL backup interval |
| `CLAWFORGE_BACKUP_RETENTION_DAYS` | `14` | Backup rotation period |
| `CLAWFORGE_BACKUP_DIR` | `./backups` | Directory for operator-managed backup scripts |
| `RUST_LOG` | `info` | Structured log filter |

Feed jobs remain disabled until `CLAWFORGE_ENABLE_FEEDS=true`. Provider intervals are defined by the adapter and are clamped to a safe minimum. Credentials are read from Docker secret files and never stored in indicators, provider status, risk history, metrics, or logs.

All Compose secret-file variables are required explicitly by `.env`; the
checked-in `.example` files are documentation only. When a `_FILE` variable is
configured, a missing, unreadable, or empty file is an error and never falls
back to the corresponding plain environment variable. Run
`./scripts/init-secrets.sh` and `./scripts/validate-secrets.sh --bootstrap`
before first startup. After deleting the one-time bootstrap file, use
`./scripts/validate-secrets.sh` for normal operations.

Network jobs remain disabled until `CLAWFORGE_ENABLE_NETWORK=true`. Their lookup resources can be set with the provider-specific `CLAWFORGE_*_RESOURCE` variables; network observations are persisted and passed through the risk engine without direct blocking.
