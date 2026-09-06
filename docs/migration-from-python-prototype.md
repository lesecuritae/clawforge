# Migration from the Python prototype

The former implementation in KorbKlar established the concepts for providers, feed synchronization, risk scoring, ASN/BGP/RPKI context, and trusted infrastructure. It remains a reference and is not copied as executable code.

The Rust implementation keeps those boundaries while removing supermarket-specific namespaces and runtime assumptions. Migration is staged: domain types and scoring first, PostgreSQL schema and service lifecycle next, then provider adapters and the consumer. Provider credentials and trusted registrations must be re-entered through the future administration path; secrets are never imported from source files.
