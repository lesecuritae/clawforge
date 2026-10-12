# Operations summary incident projection

`load_operations_summary` previously used the detailed `list_incidents` query,
which computes historical event counts and sources for every selected incident.
Neither field contributes to `operations_summary_data`: risk assessment,
correlation confidence, attention points and recommended checks consume only
incident ID, status, severity, confidence, risk score and summary.

For a large history this caused the summary read to spend its time aggregating
relations instead of returning its bounded high-level response. The old detailed
query also joined history tables before aggregation. The existing detailed-read
correction avoids that multiplication, but calculating every selected incident's
history remains unnecessary for this endpoint.

The operations loader now uses `list_operations_incident_views`: a six-field
projection from `incidents`, ordered by updated_at descending, with the existing
1–500 clamp and the unchanged requested limit of 500. It includes resolved and
closed incidents in the same latest-500 selection; existing summary logic still
chooses active incidents. This preserves bounded count semantics rather than
silently counting all incidents or selecting active incidents first.

The detailed incident listing, contexts and timelines retain their history
fields and implementation. Agent/admin operations authorization, response schema,
redaction, firewall policy and database privileges are unchanged. No migration or
index is required.

Regression checks compare the entire summary JSON produced from detailed versus
projected incident inputs, including all six supported statuses and oversized
history metadata. An isolated PostgreSQL test checks exact projection equality,
latest ordering, lower/upper limit clamps and real least-privilege access: the
reader can SELECT incidents and the migration ledger, cannot SELECT incident
history, and cannot mutate incidents.

The bounded query was also executed read-only with EXPLAIN ANALYZE on the existing
database. Only incidents was accessed; 500 rows returned in approximately 95ms.
This validates this query, not all other queries required by operations/summary.
End-to-end API/MCP summary latency must still pass after a reviewed release.

## Worker decision projection

The worker now uses `list_decision_incident_views` with the same latest-500
selection plus an exact event count: distinct legacy incident-events plus
distinct nonnull direct incident-relation event UUIDs. Duplicate direct rows
with different related IDs count once; relationship-only events and NULL event
UUIDs count zero. Sources/history payloads are not needed by DecisionEngine.
The existing incident-relation event index has incident_id,relation_type as its
prefix, so the direct-event filter avoids scanning unrelated relationship history.
No maintained candidate count is substituted: its definition differs.

Tests compare complete DecisionDraft values and exact database counts against
detailed incident reads, exercising duplicate related IDs, NULL rows, inactive
statuses, risk metadata, legacy events and an events-table-denied read role.
The bounded decision query returned 500 rows read-only in approximately 3.47s
on the observed database. Other worker scheduler/snapshot/decision dependencies
remain separate runtime gates; initial process heartbeat alone is insufficient.
