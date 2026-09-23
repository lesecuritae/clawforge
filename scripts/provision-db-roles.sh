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

PGPASSWORD="$(read_secret postgres_password "${CLAWFORGE_POSTGRES_SECRET_FILE:-/run/secrets/postgres_password}")"
export PGPASSWORD
api_password="$(read_secret database_api_password "${CLAWFORGE_DATABASE_API_PASSWORD_SECRET_FILE:-/run/secrets/database_api_password}")"
worker_password="$(read_secret database_worker_password "${CLAWFORGE_DATABASE_WORKER_PASSWORD_SECRET_FILE:-/run/secrets/database_worker_password}")"
correlation_password="$(read_secret database_correlation_password "${CLAWFORGE_DATABASE_CORRELATION_PASSWORD_SECRET_FILE:-/run/secrets/database_correlation_password}")"
security_engine_password="$(read_secret database_security_engine_password "${CLAWFORGE_DATABASE_SECURITY_ENGINE_PASSWORD_SECRET_FILE:-/run/secrets/database_security_engine_password}")"
incidents_password="$(read_secret database_incidents_password "${CLAWFORGE_DATABASE_INCIDENTS_PASSWORD_SECRET_FILE:-/run/secrets/database_incidents_password}")"
executor_password="$(read_secret database_executor_password "${CLAWFORGE_DATABASE_EXECUTOR_PASSWORD_SECRET_FILE:-/run/secrets/database_executor_password}")"
backup_password="$(read_secret database_backup_password "${CLAWFORGE_DATABASE_BACKUP_PASSWORD_SECRET_FILE:-/run/secrets/database_backup_password}")"

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
  --set incidents_password="$incidents_password" \
  --set executor_password="$executor_password" \
  --set backup_password="$backup_password" <<'SQL'
BEGIN;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

SELECT 'CREATE ROLE clawforge_api' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_api') \gexec
SELECT 'CREATE ROLE clawforge_worker' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_worker') \gexec
SELECT 'CREATE ROLE clawforge_correlation' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_correlation') \gexec
SELECT 'CREATE ROLE clawforge_security_engine' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_security_engine') \gexec
SELECT 'CREATE ROLE clawforge_incidents' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_incidents') \gexec
SELECT 'CREATE ROLE clawforge_executor' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_executor') \gexec
SELECT 'CREATE ROLE clawforge_backup' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='clawforge_backup') \gexec

ALTER ROLE clawforge_api LOGIN PASSWORD :'api_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 64;
ALTER ROLE clawforge_worker LOGIN PASSWORD :'worker_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 32;
ALTER ROLE clawforge_correlation LOGIN PASSWORD :'correlation_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_security_engine LOGIN PASSWORD :'security_engine_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_incidents LOGIN PASSWORD :'incidents_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_executor LOGIN PASSWORD :'executor_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;
ALTER ROLE clawforge_backup LOGIN PASSWORD :'backup_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;

GRANT CONNECT ON DATABASE :"database_name" TO clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_incidents, clawforge_executor, clawforge_backup;
GRANT USAGE ON SCHEMA public TO clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_incidents, clawforge_executor, clawforge_backup;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_incidents, clawforge_executor, clawforge_backup;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM clawforge_api, clawforge_worker, clawforge_correlation, clawforge_security_engine, clawforge_incidents, clawforge_executor, clawforge_backup;

-- The API is the authenticated administrative boundary. It may mutate the
-- application schema, but migration metadata and append-only audit rows remain
-- protected by PostgreSQL itself.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO clawforge_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_api;
REVOKE INSERT, UPDATE, DELETE ON TABLE _sqlx_migrations FROM clawforge_api;
REVOKE UPDATE, DELETE ON TABLE audit_events FROM clawforge_api;
REVOKE DELETE ON TABLE audit_outbox FROM clawforge_api;

GRANT SELECT ON TABLE _sqlx_migrations,
  alerts, incidents, providers, provider_status, runtime_status,
  knowledge_entries, events, rules, decisions, workflows, workflow_steps,
  workflow_runs, approvals, notification_rules, notification_channels,
  event_consumers
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
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_executor;
REVOKE UPDATE ON TABLE audit_events FROM clawforge_executor;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO clawforge_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO clawforge_backup;

COMMIT;
SQL

echo "database runtime roles provisioned"
