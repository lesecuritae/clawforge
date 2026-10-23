-- Read-only measurement of the attack-shape evidence on REAL production data. No writes, bounded by
-- statement_timeout; run as the owner or the operations role:
--   docker exec -i clawforge-postgres-1 psql -U clawforge -d clawforge -At -f - < scripts/ops/shape-evidence-report.sql
-- Counts come from shadow policy decisions (evidence_snapshot.attack_shape) and from the sensor's
-- invalid-user verdict coverage. It does not label anything as attack or legitimate: a rate here is an
-- observed frequency, not a false-positive rate. Compare windows only after real time has passed.
SET statement_timeout = '60s';
\echo == verdict coverage of ssh_login_failure events per day (absent = sensor without the verdict)
SELECT date_trunc('day', created_at)::date AS day,
       count(*) FILTER (WHERE payload ->> 'invalid_user' = 'true')  AS invalid_user,
       count(*) FILTER (WHERE payload ->> 'invalid_user' = 'false') AS existing_account,
       count(*) FILTER (WHERE payload ->> 'invalid_user' IS NULL)   AS verdict_absent
  FROM events
 WHERE event_type = 'ssh_login_failure' AND created_at > now() - interval '7 days'
 GROUP BY 1 ORDER BY 1;
\echo == shadow decisions by shape kind and decision (last 7 days)
SELECT date_trunc('day', decided_at)::date AS day,
       coalesce(evidence_snapshot -> 'attack_shape' ->> 'kind', 'none') AS shape_kind,
       decision, corroborated, count(*) AS decisions
  FROM security_policy_decisions
 WHERE is_shadow AND decided_at > now() - interval '7 days'
 GROUP BY 1, 2, 3, 4 ORDER BY 1, 2, 3, 4;
\echo == decisions where the invalid-account shape was the only shape evidence
SELECT count(*) AS invalid_account_probe_decisions,
       count(*) FILTER (WHERE (evidence_snapshot -> 'attack_shape' ->> 'distinct_usernames')::int < (evidence_snapshot -> 'attack_shape' ->> 'min_usernames')::int) AS below_enumeration_threshold
  FROM security_policy_decisions
 WHERE is_shadow AND evidence_snapshot -> 'attack_shape' ->> 'kind' = 'invalid_account_probe';
