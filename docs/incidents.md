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

The analysis endpoint returns structured incident data, event types, sources, and a safe explanation. This is the complete input boundary for a future LLM summarizer. The LLM has no tool or endpoint for blocking, changing policies, activating providers, or granting trust.
