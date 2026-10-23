#!/usr/bin/env sh
set -eu

read_secret() {
  name="$1"
  path="$2"
  [ -f "$path" ] || { echo "missing $name secret: $path" >&2; exit 1; }
  value="$(tr -d '\r\n' <"$path")"
  case "$value" in
    ''|*[!A-Za-z0-9._~-]*)
      echo "$name must contain only URL-safe password characters" >&2
      exit 1
      ;;
  esac
  [ "${#value}" -ge 16 ] || { echo "$name must contain at least 16 characters" >&2; exit 1; }
  printf '%s' "$value"
}

# The projection reader roles are used by tests and by an optional learning
# integration only. Without their secret they are created without a login so the
# grants below stay valid and no password has to be invented.
read_optional_secret() {
  [ -f "$2" ] || return 0
  read_secret "$1" "$2"
}

PGPASSWORD="$(read_secret postgres_password "${CLAWFORGE_POSTGRES_SECRET_FILE:-/run/secrets/postgres_password}")"
export PGPASSWORD
api_password="$(read_secret database_api_password "${CLAWFORGE_DATABASE_API_PASSWORD_SECRET_FILE:-/run/secrets/database_api_password}")"
worker_password="$(read_secret database_worker_password "${CLAWFORGE_DATABASE_WORKER_PASSWORD_SECRET_FILE:-/run/secrets/database_worker_password}")"
correlation_password="$(read_secret database_correlation_password "${CLAWFORGE_DATABASE_CORRELATION_PASSWORD_SECRET_FILE:-/run/secrets/database_correlation_password}")"
security_engine_password="$(read_secret database_security_engine_password "${CLAWFORGE_DATABASE_SECURITY_ENGINE_PASSWORD_SECRET_FILE:-/run/secrets/database_security_engine_password}")"
policy_engine_password="$(read_secret database_policy_engine_password "${CLAWFORGE_DATABASE_POLICY_ENGINE_PASSWORD_SECRET_FILE:-/run/secrets/database_policy_engine_password}")"
incidents_password="$(read_secret database_incidents_password "${CLAWFORGE_DATABASE_INCIDENTS_PASSWORD_SECRET_FILE:-/run/secrets/database_incidents_password}")"
executor_password="$(read_secret database_executor_password "${CLAWFORGE_DATABASE_EXECUTOR_PASSWORD_SECRET_FILE:-/run/secrets/database_executor_password}")"
operations_password="$(read_optional_secret database_operations_password "${CLAWFORGE_DATABASE_OPERATIONS_PASSWORD_SECRET_FILE:-/run/secrets/database_operations_password}")"
decision_password="$(read_optional_secret database_decision_password "${CLAWFORGE_DATABASE_DECISION_PASSWORD_SECRET_FILE:-/run/secrets/database_decision_password}")"
backup_password="$(read_secret database_backup_password "${CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE:-/run/secrets/database_backup_password}")"

# Only passed when the secret exists; the value is restricted to URL-safe characters.
optional_password_args=""
[ -z "$operations_password" ] || optional_password_args="$optional_password_args --set operations_password=$operations_password"
[ -z "$decision_password" ] || optional_password_args="$optional_password_args --set decision_password=$decision_password"

# shellcheck disable=SC2086
psql \
  --host "${PGHOST:-postgres}" \
  --port "${PGPORT:-5432}" \
  --username "${POSTGRES_USER:-clawforge}" \
  --dbname "${POSTGRES_DB:-clawforge}" \
  --set ON_ERROR_STOP=1 \
  --set database_name="${POSTGRES_DB:-clawforge}" \
  --set api_password="$api_password" \
  --set worker_password="$worker_password" \
  --set correlation_password="$correlation_password" \
  --set security_engine_password="$security_engine_password" \
  --set policy_engine_password="$policy_engine_password" \
  --set incidents_password="$incidents_password" \
  --set executor_password="$executor_password" \
  $optional_password_args \
  --set backup_password="$backup_password" <<'SQL'
BEGIN;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

SELECT 'CREATE ROLE clawforge_api' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_api') \gexec
SELECT 'CREATE ROLE clawforge_worker' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_worker') \gexec
SELECT 'CREATE ROLE clawforge_correlation' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_correlation') \gexec
SELECT 'CREATE ROLE clawforge_security_engine' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_security_engine') \gexec
SELECT 'CREATE ROLE clawforge_policy_engine' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_policy_engine') \gexec
SELECT 'CREATE ROLE clawforge_incidents' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_incidents') \gexec
SELECT 'CREATE ROLE clawforge_executor' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_executor') \gexec
SELECT 'CREATE ROLE clawforge_operations' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_operations') \gexec
SELECT 'CREATE ROLE clawforge_decision' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_decision') \gexec
SELECT 'CREATE ROLE clawforge_backup' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_backup') \gexec

ALTER ROLE clawforge_api LOGIN PASSWORD :'api_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64;
ALTER ROLE clawforge_worker LOGIN PASSWORD :'worker_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 32;
ALTER ROLE clawforge_correlation LOGIN PASSWORD :'correlation_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_security_engine LOGIN PASSWORD :'security_engine_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_policy_engine LOGIN PASSWORD :'policy_engine_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_incidents LOGIN PASSWORD :'incidents_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_executor LOGIN PASSWORD :'executor_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
\if :{?operations_password}
ALTER ROLE clawforge_operations LOGIN PASSWORD :'operations_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
\else
ALTER ROLE clawforge_operations NOLOGIN PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\endif
\if :{?decision_password}
ALTER ROLE clawforge_decision LOGIN PASSWORD :'decision_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
\else
ALTER ROLE clawforge_decision NOLOGIN PASSWORD NULL NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\endif
ALTER ROLE clawforge_backup LOGIN PASSWORD :'backup_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;

GRANT CONNECT ON DATABASE :"database_name" TO clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_policy_engine, clawforge_incidents, clawforge_executor, clawforge_backup, clawforge_operations, clawforge_decision;
GRANT USAGE ON SCHEMA public TO clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_policy_engine, clawforge_incidents, clawforge_executor, clawforge_backup, clawforge_operations, clawforge_decision;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_policy_engine, clawforge_incidents, clawforge_executor, clawforge_backup, clawforge_operations, clawforge_decision;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_policy_engine, clawforge_incidents, clawforge_executor, clawforge_backup, clawforge_operations, clawforge_decision;

-- The API is the authenticated administrative boundary. It may mutate the
-- application schema, but migration metadata and append-only audit rows remain
-- protected by PostgreSQL itself.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO clawforge_api;
-- Routing context is written only through the worker's verified function (0063).
REVOKE INSERT, UPDATE, DELETE ON TABLE source_network_context FROM clawforge_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_api;
REVOKE INSERT, UPDATE, DELETE ON TABLE _sqlx_migrations FROM clawforge_api;
REVOKE UPDATE, DELETE ON TABLE audit_events FROM clawforge_api;
REVOKE DELETE ON TABLE audit_outbox FROM clawforge_api;
-- Learning content and review records are immutable; only reviewed status changes update revisions.
REVOKE UPDATE, DELETE ON TABLE learning_lessons, learning_records FROM clawforge_api;
REVOKE UPDATE, DELETE ON TABLE learning_revisions FROM clawforge_api;
GRANT UPDATE(status,last_verified) ON TABLE learning_revisions TO clawforge_api;
-- Trust roots are provisioned only by the database owner/CI importer.
REVOKE INSERT, UPDATE, DELETE ON TABLE learning_actor_tokens, learning_curator_grants, learning_verified_evidence FROM clawforge_api;
-- API can inspect journal generations, but only the executor owns transitions.
REVOKE INSERT, UPDATE, DELETE ON TABLE firewall_action_intents FROM clawforge_api;
REVOKE UPDATE, DELETE ON TABLE firewall_action_receipts FROM clawforge_api;

-- incident_relations: list_incidents (called from evaluate_decisions on
-- every worker tick) joins it to compute each incident's event_sources/
-- event_count - a real gap found live (never caught before because
-- clawforge-worker had never actually been run against a least-privilege
-- role in this deployment; no existing real-Postgres test exercised this
-- read path under the worker role either, only negative privilege checks).
GRANT SELECT ON TABLE _sqlx_migrations,
  alerts, incidents, incident_relations, providers, provider_status,
  runtime_status, knowledge_entries, events, rules, decisions, workflows,
  workflow_steps, workflow_runs, approvals, notification_rules,
  notification_channels, event_consumers, security_assessments,
  security_policy_decisions
  TO clawforge_worker;
GRANT SELECT, INSERT, UPDATE ON TABLE
  providers, provider_status, provider_history, provider_sync_requests,
  indicators, risk_history, rpki_records, asn_records, bgp_events,
  trusted_networks, trust_history, alerts, alert_status_history,
  incidents, incident_events, incident_candidates, incident_candidate_events,
  events, event_delivery, decisions, rule_executions, workflow_runs,
  workflow_audit_log, approvals, operations_snapshots, runtime_status,
  audit_events, audit_outbox, notification_events
  TO clawforge_worker;
GRANT DELETE ON TABLE indicators TO clawforge_worker;
-- Routing context for suspicious sources (migration 0063): the worker has the egress
-- and may only list targets and record verified results through these functions.
GRANT EXECUTE ON FUNCTION clawforge_network_context_targets(INTEGER, INTEGER, INTEGER) TO clawforge_worker;
GRANT EXECUTE ON FUNCTION clawforge_record_network_context(TEXT, TEXT, CIDR, BIGINT[], TEXT, TEXT, INTEGER, INTEGER, TEXT) TO clawforge_worker;
GRANT DELETE ON TABLE security_policy_decisions, security_assessments TO clawforge_worker;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_worker;
REVOKE UPDATE ON TABLE audit_events FROM clawforge_worker;

GRANT SELECT ON TABLE _sqlx_migrations, events, event_consumers,
  event_delivery, event_relationships, incident_candidates,
  incident_candidate_events, runtime_status TO clawforge_correlation;
GRANT INSERT, UPDATE ON TABLE event_consumers, event_delivery,
  event_relationships, incident_candidates, incident_candidate_events,
  runtime_status TO clawforge_correlation;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_correlation;

-- security-engine reads canonical events (published by
-- record_security_event for every sensor-produced security event) as its
-- own independent named consumer on the same event_delivery fan-out
-- clawforge_correlation uses - the two never see or affect each other's
-- delivery rows. It reuses the incident_candidates path (persist_correlation)
-- for incident creation/escalation instead of a second one, hence the same
-- incident_candidates/incident_candidate_events/event_relationships grants
-- as clawforge_correlation, plus its own security_assessments tables.
GRANT SELECT ON TABLE _sqlx_migrations, events, event_consumers,
  event_delivery, event_relationships, incident_candidates,
  incident_candidate_events, incidents, runtime_status,
  security_assessments, security_assessment_events TO clawforge_security_engine;
GRANT INSERT, UPDATE ON TABLE event_consumers, event_delivery,
  event_relationships, incident_candidates, incident_candidate_events,
  runtime_status, security_assessments TO clawforge_security_engine;
GRANT INSERT ON TABLE security_assessment_events TO clawforge_security_engine;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_security_engine;

-- policy-engine (Shadow Mode only, roadmap phase 5) reads security_policies
-- (never writes them - a policy is authored/versioned separately, this
-- service only evaluates active ones) and security_assessments, and writes
-- its own security_policy_decisions. No access to events/event_delivery at
-- all: unlike security-engine, this service does not consume the canonical
-- event bus, it polls already-persisted assessments directly.
GRANT SELECT ON TABLE _sqlx_migrations, security_policies, security_assessments,
  security_policy_decisions, incidents, runtime_status TO clawforge_policy_engine;
GRANT INSERT, UPDATE ON TABLE security_policy_decisions, runtime_status
  TO clawforge_policy_engine;
GRANT EXECUTE ON FUNCTION clawforge_enqueue_goaway_shadow_challenge(UUID)
  TO clawforge_policy_engine;
-- Independent corroboration (migration 0061): event families only, never payloads.
GRANT EXECUTE ON FUNCTION clawforge_assessment_event_types(UUID) TO clawforge_policy_engine;
-- Behaviour counts of one assessment (migration 0067): numbers only, never usernames or paths.
GRANT EXECUTE ON FUNCTION clawforge_assessment_shape(UUID, TEXT[]) TO clawforge_policy_engine;
-- Retention that keeps the evidence behind real execution requests (migration 0070): the worker cannot read execution_requests itself.
GRANT EXECUTE ON FUNCTION clawforge_delete_expired_security_assessments(TIMESTAMPTZ) TO clawforge_worker;
-- Current reputation/routing view of one pseudonymized source (migration 0063).
GRANT EXECUTE ON FUNCTION clawforge_current_source_intel(TEXT) TO clawforge_policy_engine;
-- Policy -> execution bridge (migration 0060): the only path by which this role
-- can create an execution request; every call is re-validated in the database.
GRANT EXECUTE ON FUNCTION clawforge_policy_bridge_plan(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN, INTEGER)
  TO clawforge_policy_engine;
GRANT EXECUTE ON FUNCTION clawforge_enqueue_policy_bridge_request(UUID, TEXT, TEXT, INTEGER, UUID, TEXT, INTEGER, BOOLEAN, INTEGER, INTEGER, INTEGER, JSONB, TEXT)
  TO clawforge_policy_engine;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_policy_engine;

-- Promotion also backfills alerts.incident_id for alerts that were created
-- before their candidate was promoted, and announces new incidents on the
-- event bus and notification queue (publish_event/enqueue_notification_event
-- in storage/src/lib.rs's promote_incident_candidates) - hence the grants on
-- alerts, events, event_consumers, event_delivery, notification_rules,
-- notification_channels, and notification_events below.
GRANT SELECT ON TABLE _sqlx_migrations, incident_candidates,
  incident_candidate_events, incidents, incident_events, incident_relations,
  incident_status_history, event_relationships, indicators, runtime_status,
  alerts, events, event_consumers, notification_rules, notification_channels
  TO clawforge_incidents;
GRANT INSERT, UPDATE ON TABLE incident_candidates, incidents,
  incident_events, incident_relations, incident_status_history, runtime_status,
  alerts
  TO clawforge_incidents;
GRANT INSERT ON TABLE events, event_delivery, notification_events
  TO clawforge_incidents;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_incidents;

GRANT SELECT ON TABLE _sqlx_migrations, actions, execution_requests,
  execution_approvals, execution_leases, execution_workers,
  execution_metrics, audit_events, audit_outbox, events, event_consumers,
  event_delivery, runtime_status TO clawforge_executor;
GRANT INSERT, UPDATE ON TABLE execution_requests, execution_leases,
  execution_workers, execution_metrics, audit_events, audit_outbox, events,
  event_delivery, runtime_status TO clawforge_executor;
-- Append-only Action Receipt log (see FirewallActionReceiptInput's own doc
-- comment) - insert-only for individual rows (the executor never updates
-- one), plus SELECT for the mass-block budget's own aggregate COUNT(*)
-- query (recent_real_firewall_apply_count) - that is a count, never a
-- row-by-row read-back of past receipts.
GRANT INSERT, SELECT ON TABLE firewall_action_receipts TO clawforge_executor;
-- Recovery journal: prepare and complete an intent; retain every row for audit.
GRANT SELECT, INSERT, UPDATE ON TABLE firewall_action_intents TO clawforge_executor;
-- Revalidate context-bound distinct approvals at dispatch; never grant approval writes.
GRANT SELECT ON TABLE execution_approvals, approval_policies TO clawforge_executor;
GRANT EXECUTE ON FUNCTION clawforge_lock_quarantine_approval(UUID) TO clawforge_executor;
GRANT EXECUTE ON FUNCTION clawforge_resolve_incident_source_for_apply(UUID) TO clawforge_executor;
-- Kill-switch intent queue (migration 0042): the executor's sweep reads
-- pending rows and marks them processed once rolled back - it never
-- inserts one itself (clawforge-api does that, via its own blanket
-- grant), so no INSERT here.
GRANT SELECT, UPDATE ON TABLE firewall_kill_switch_requests TO clawforge_executor;
-- Concurrency-budget reservation table (migration 0043): the executor
-- both reserves (INSERT) and releases (DELETE) its own slots, plus reads
-- (SELECT) the live count - clawforge_api never touches this table at
-- all (it only ever records kill-switch *intent*, never a real apply).
GRANT INSERT, SELECT, DELETE ON TABLE firewall_inflight_operations TO clawforge_executor;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_executor;
REVOKE UPDATE ON TABLE audit_events FROM clawforge_executor;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO clawforge_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_backup;


-- Bounded incident projection readers (operations summary / worker decisions).
-- operations: incidents + migration ledger only; no incident history, no mutation.
GRANT SELECT ON TABLE _sqlx_migrations, incidents TO clawforge_operations;
-- decision: incidents + direct relation/event counts; events table denied, no mutation.
GRANT SELECT ON TABLE _sqlx_migrations, incidents, incident_relations, incident_events TO clawforge_decision;
COMMIT;
SQL

echo "database runtime roles provisioned"
