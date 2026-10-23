-- Read-only evidence for the 24 h attack-shape observation. One JSON document on a line starting with
-- RESULT_JSON; parameters: -v w_start=<timestamptz> -v w_end=<timestamptz>. Wrapped by
-- scripts/shape-observation-evaluate.py in BEGIN READ ONLY with statement/lock timeouts; writes nothing.
WITH p AS (SELECT :'w_start'::timestamptz AS s, :'w_end'::timestamptz AS e),
hrs AS (SELECT generate_series(date_trunc('hour', p.s) + interval '1 hour', date_trunc('hour', p.e) - interval '1 hour', interval '1 hour') AS h FROM p),
ssh AS (SELECT date_trunc('hour', ev.created_at) AS h, count(*) AS n,
               count(*) FILTER (WHERE ev.payload ? 'invalid_user') AS with_verdict,
               count(*) FILTER (WHERE ev.payload ->> 'invalid_user' = 'true') AS invalid
          FROM events ev, p WHERE ev.event_type = 'ssh_login_failure' AND ev.created_at >= p.s AND ev.created_at < p.e GROUP BY 1),
asm AS (SELECT date_trunc('hour', a.created_at) AS h, count(*) AS n FROM security_assessments a, p
         WHERE a.created_at >= p.s AND a.created_at < p.e GROUP BY 1),
dec AS (SELECT date_trunc('hour', d.decided_at) AS h, count(*) AS n FROM security_policy_decisions d, p
         WHERE d.is_shadow AND d.decided_at >= p.s AND d.decided_at < p.e GROUP BY 1),
sshdec AS (SELECT d.* FROM security_policy_decisions d, p
            WHERE d.is_shadow AND d.decided_at >= p.s AND d.decided_at < p.e AND d.evidence_snapshot ->> 'rule_id' LIKE 'ssh%'),
kinds AS (SELECT coalesce(evidence_snapshot -> 'attack_shape' ->> 'kind', 'none') AS kind,
                 coalesce(evidence_snapshot ->> 'evidence_basis', 'unknown') AS basis, decision, corroborated, count(*) AS n
            FROM sshdec GROUP BY 1, 2, 3, 4),
probe AS (SELECT count(*) AS decisions, count(DISTINCT evidence_snapshot ->> 'resource') AS sources,
                 min((evidence_snapshot -> 'attack_shape' ->> 'distinct_invalid_usernames')::int) AS min_invalid,
                 max((evidence_snapshot -> 'attack_shape' ->> 'distinct_invalid_usernames')::int) AS max_invalid,
                 count(*) FILTER (WHERE evidence_snapshot ->> 'evidence_basis' = 'attack_shape') AS newly_corroborated
            FROM sshdec WHERE evidence_snapshot -> 'attack_shape' ->> 'kind' = 'invalid_account_probe')
SELECT 'RESULT_JSON ' || jsonb_build_object(
  'window', jsonb_build_object('start', p.s, 'end', p.e),
  'full_hours', (SELECT coalesce(jsonb_agg(jsonb_build_object(
        'hour', hrs.h, 'ssh_events', coalesce(ssh.n, 0), 'assessments', coalesce(asm.n, 0), 'decisions', coalesce(dec.n, 0)) ORDER BY hrs.h), '[]'::jsonb)
      FROM hrs LEFT JOIN ssh ON ssh.h = hrs.h LEFT JOIN asm ON asm.h = hrs.h LEFT JOIN dec ON dec.h = hrs.h),
  'ssh_events', (SELECT jsonb_build_object('total', coalesce(sum(n), 0), 'with_verdict', coalesce(sum(with_verdict), 0), 'invalid_user', coalesce(sum(invalid), 0)) FROM ssh),
  'ssh_decisions', (SELECT jsonb_build_object('total', count(*), 'with_attack_shape_snapshot', count(*) FILTER (WHERE evidence_snapshot ? 'attack_shape')) FROM sshdec),
  'decisions_by_shape_basis', (SELECT coalesce(jsonb_agg(jsonb_build_object('shape_kind', kind, 'basis', basis, 'decision', decision, 'corroborated', corroborated, 'count', n) ORDER BY n DESC), '[]'::jsonb) FROM kinds),
  'invalid_account_probe', (SELECT to_jsonb(probe) FROM probe),
  'assessments_in_window', (SELECT count(*) FROM security_assessments a, p WHERE a.created_at >= p.s AND a.created_at < p.e),
  'undecided_assessments_with_active_policy', (SELECT count(*) FROM security_assessments a
        WHERE a.created_at > now() - interval '36 hours'
          AND NOT EXISTS (SELECT 1 FROM security_policy_decisions d WHERE d.assessment_id = a.id)
          AND EXISTS (SELECT 1 FROM security_policies pp WHERE pp.rule_id = a.rule_id AND pp.status = 'active')),
  'delivery_backlog_security_engine', (SELECT count(*) FROM event_delivery ed JOIN event_consumers c ON c.id = ed.consumer_id
        JOIN events ev2 ON ev2.event_id = ed.event_id
        WHERE c.name = 'security-engine' AND ed.status IN ('pending', 'failed') AND ev2.created_at < p.e),
  'policy_engine', (SELECT jsonb_build_object('state', state, 'heartbeat_age_seconds', extract(epoch FROM now() - last_heartbeat_at)::int)
        FROM runtime_status WHERE component = 'policy-engine'),
  'ssh_sensor_age_seconds', (SELECT extract(epoch FROM now() - last_seen_at)::int FROM security_sensors WHERE name = 'srv19680-ssh' AND revoked_at IS NULL),
  'schema_version', (SELECT max(version) FROM _sqlx_migrations WHERE success)
)::text FROM p;
