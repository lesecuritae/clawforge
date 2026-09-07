# Incident Management

Clawforge correlates stored intelligence events into incidents. Correlation uses the event resource (for example an IP, prefix, ASN, or trusted-network identifier) and joins events into an open or investigating incident. A new incident starts with Open; its lifecycle is Open, Investigating, Resolved, or Ignored.

Threat indicators, BGP changes, RPKI invalid results, ASN changes, trusted-network changes, and provider errors can create or update an incident. Risk contributions are bounded at 100 and the highest observed severity is retained. A single feed still cannot produce a block action.

The API is protected by the administration bearer authentication:

- GET /incidents
- GET /incidents/{id}
- GET /incidents/{id}/events
- GET /incidents/{id}/analysis
- POST /incidents/{id}/status

Administrators and operators may change status. Every status change is written to audit_events.

The analysis endpoint returns structured incident data, event types, sources, and stored analysis results. Operators and administrators can request an optional analysis through `POST /incidents/{id}/analysis/request` when `clawforge-analyzer` is enabled. The analyzer receives a sanitized payload through the internal network and stores only structured `incident_analysis` results through the protected internal API.

The analyzer defaults to an offline mock provider. OpenAI-compatible APIs, local models, and OpenRouter can be selected with the same provider configuration; no vendor is required. Secrets are mounted from Docker Secrets, raw feed fields are removed, and IP values are anonymized by default. Analysis is explanatory only: it cannot block, grant trust, change policies, activate providers, or change permissions. Analyzer failures and requests are recorded in `audit_events`.
