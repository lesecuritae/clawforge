# Incident Analysis Layer

`clawforge-analyzer` is an optional service. It is not part of the risk or policy engine and has no direct database access. The service is reachable only on the Compose backend network and communicates with the API using the internal analyzer token.

The flow is:

1. An authenticated Operator or Administrator calls `POST /incidents/{id}/analysis/request`.
2. The API builds a sanitized incident payload and sends it to the analyzer's internal `/analyze` endpoint.
3. The analyzer invokes the configured provider and returns a structured summary.
4. The analyzer submits the result to the protected API storage endpoint.
5. The API stores the result in `incident_analysis` and records an audit event.

The default provider is `mock`, which supports offline operation and tests. Set `CLAWFORGE_ANALYZER_PROVIDER` to an OpenAI-compatible provider name and configure `CLAWFORGE_ANALYZER_BASE_URL`, `CLAWFORGE_ANALYZER_MODEL`, and the optional API-key Docker Secret for a remote or local model. The provider abstraction does not require a fixed vendor.

The payload boundary removes fields containing raw feed data, secrets, tokens, passwords, or API keys. IP values are anonymized by default; set `CLAWFORGE_ANALYZER_ANONYMIZE_IPS=false` only when that is explicitly required for an internal deployment. The analyzer output is validated and cannot contain instructions to block, grant trust, change policies, activate providers, or change permissions.

Stored fields are `incident_id`, `provider`, `model`, `timestamp`, `confidence`, `summary`, `observations`, and `recommendations`. Provider errors and timeouts return an error to the requestor and do not change risk, trust, or policy state.
