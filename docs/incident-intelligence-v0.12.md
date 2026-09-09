# Clawforge v0.12.0 Incident Intelligence

## Incident Management Core

Migration `0027_incidents.sql` adds an append-only incident timeline, source
and title projections, and keeps the existing correlation and lifecycle
history tables as the source of truth. The API and Agent API expose only
sanitized incident fields and preserve the existing `agent:incident:read`
scope. The MCP adapter exposes `get_incident_details` as an alias for the
existing read-only incident detail tool.

The lifecycle remains compatible with earlier releases. `open` is accepted as
the public alias for the existing `detected` state and status history remains
forward-only. No incident endpoint changes risk, trust, policy, or execution
state.

## Alert correlation

`alert_rules`, `alert_groups`, and `correlation_events` store declarative
grouping metadata. Rules contain source, error class, infrastructure, severity,
and a bounded time window; they contain no scripts. Correlation records are
deduplicated by group and event and can be linked to an incident.

## Connector action registry

Docker, Proxmox, and GitHub action names are registered for future controlled
operations. Every row is disabled and approval-gated. The executor remains
`CLAWFORGE_EXECUTOR_DRY_RUN=true`; no connector mutation, shell command, or
automatic remediation is enabled by this release.

## Secret provider metadata

`secret_providers` and `secret_references` store provider type and references
only. Supported reference types are Docker Secrets, environment references,
Vaultwarden, SOPS, and external providers. Secret values are never persisted;
runtime injection continues to use Docker Secret files or environment
references. Vaultwarden and SOPS are metadata integrations until a separately
reviewed resolver is enabled.

## Operations dashboard and notifications

Existing incident, execution, connector-health, and notification views remain
the read-only operations surface. Incident status and note changes append a
sanitized timeline record, while the existing notification worker handles
configured webhook, SMTP, and Matrix deliveries. No automatic action is
triggered by an alert or incident.

## Upgrade

Start the normal Compose stack to apply `0027_incidents.sql` and the small
`0028_incident_status_compatibility.sql` follow-up. The migrations are safe on
an existing v0.11 database and create only additive tables, indexes, metadata
columns, compatibility constraints, and disabled action registrations. Verify `/ready` reports
the current migration and run the documented backup/restore test before
enabling production traffic.
