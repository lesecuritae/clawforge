# Security model

The worker is an ingestion and scoring service. A feed error, a single indicator, or a single ASN/BGP/RPKI signal cannot trigger a block. The policy boundary remains downstream of risk scoring and requires corroboration before a block decision.

`/health` checks that the process and runtime configuration are valid. `/ready` additionally checks PostgreSQL and verifies that the applied sqlx migration set is complete. `/version` reports the application release and schema state. Database and provider credentials use Compose secret files by default; `.env` and non-example secret files are ignored by Git.

Trusted infrastructure is administrator-registered and must be `Verified`. Tailscale, NetBird, VLAN, VPN, IP ranges, ASNs, and prefixes do not receive trust from their technology name. Risk history and audit events remain append-oriented so feed and trust decisions can be explained later.
