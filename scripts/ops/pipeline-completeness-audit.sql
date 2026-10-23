-- Read-only audit of the detection pipeline on REAL data: does every event burst that meets a rule's
-- threshold have its assessment, and does every recent assessment have a policy decision? Recomputes the
-- expected windows from the events table itself (independent of the engines) with the two staggered grids
-- (offset 0 and half a window). It labels nothing as attack or legitimate.
--   docker exec -i clawforge-postgres-1 psql -U clawforge -d clawforge -At -f - < scripts/ops/pipeline-completeness-audit.sql
-- Expected on a healthy system: every "missing" and "without any decision" line is 0. Rule versions
-- before the grid change (1.2.0, 2026-10-21) did not have the shifted grid: the HTTP window starts at 22 Oct.
SET statement_timeout = '120s';
\echo == ssh_bruteforce (threshold 5 / 300 s), last 24 h (events older than 10 min)
WITH g AS (SELECT 0 AS off UNION ALL SELECT 150),
ev AS (SELECT correlation_id c, occurred_at t FROM events
        WHERE event_type = 'ssh_login_failure' AND occurred_at > now() - interval '24 hours' AND occurred_at < now() - interval '10 minutes'),
b AS (SELECT c, to_timestamp(floor((extract(epoch FROM t) - g.off) / 300) * 300 + g.off) AS bs, count(*) n
        FROM ev, g GROUP BY 1, g.off, 2 HAVING count(*) >= 5),
a AS (SELECT resource, bucket_start, event_count FROM security_assessments
        WHERE rule_id = 'ssh_bruteforce' AND bucket_start > now() - interval '26 hours')
SELECT 'expected windows', count(*) FROM b
UNION ALL SELECT 'missing assessment', count(*) FROM b WHERE NOT EXISTS (SELECT 1 FROM a WHERE a.resource = b.c AND a.bucket_start = b.bs)
UNION ALL SELECT 'event_count differs from recomputed (cap 1000)', count(*) FROM b JOIN a ON a.resource = b.c AND a.bucket_start = b.bs WHERE a.event_count <> LEAST(b.n, 1000);
\echo == http_anomaly_burst (>= 10 client-attributable / 300 s) and http_scan (>= 8 distinct paths), since 2026-10-22
WITH g AS (SELECT 0 AS off UNION ALL SELECT 150),
ev AS (SELECT correlation_id c, occurred_at t, payload ->> 'path' p,
              COALESCE((CASE WHEN payload ->> 'status_code' ~ '^[0-9]{3}$' THEN (payload ->> 'status_code')::int END), 0) s
         FROM events WHERE event_type = 'http_anomaly' AND occurred_at > '2026-10-22 00:00+00' AND occurred_at < now() - interval '10 minutes'),
burst AS (SELECT c, to_timestamp(floor((extract(epoch FROM t) - g.off) / 300) * 300 + g.off) bs FROM ev, g WHERE s < 500 GROUP BY 1, 2, g.off HAVING count(*) >= 10),
scan AS (SELECT c, to_timestamp(floor((extract(epoch FROM t) - g.off) / 300) * 300 + g.off) bs FROM ev, g WHERE s < 500 GROUP BY 1, 2, g.off HAVING count(DISTINCT p) >= 8),
a AS (SELECT rule_id, resource, bucket_start FROM security_assessments WHERE bucket_start > '2026-10-22 00:00+00' AND rule_id IN ('http_anomaly_burst', 'http_scan'))
SELECT 'burst expected', count(*) FROM burst
UNION ALL SELECT 'burst missing', count(*) FROM burst b WHERE NOT EXISTS (SELECT 1 FROM a WHERE a.rule_id = 'http_anomaly_burst' AND a.resource = b.c AND a.bucket_start = b.bs)
UNION ALL SELECT 'scan expected', count(*) FROM scan
UNION ALL SELECT 'scan missing', count(*) FROM scan b WHERE NOT EXISTS (SELECT 1 FROM a WHERE a.rule_id = 'http_scan' AND a.resource = b.c AND a.bucket_start = b.bs);
\echo == policy stage: assessments created 10 min .. 24 h ago
WITH a AS (SELECT id, rule_id FROM security_assessments WHERE created_at > now() - interval '24 hours' AND created_at < now() - interval '10 minutes')
SELECT 'assessments', count(*) FROM a
UNION ALL SELECT 'without any decision although an active policy exists for the rule', count(*) FROM a
          WHERE NOT EXISTS (SELECT 1 FROM security_policy_decisions d WHERE d.assessment_id = a.id)
            AND EXISTS (SELECT 1 FROM security_policies p WHERE p.rule_id = a.rule_id AND p.status = 'active')
UNION ALL SELECT 'corroborated decisions with fewer than 2 evidence sources', count(*) FROM security_policy_decisions
          WHERE decided_at > now() - interval '24 hours' AND corroborated AND evidence_sources < 2
UNION ALL SELECT 'block decisions that are not corroborated', count(*) FROM security_policy_decisions
          WHERE decided_at > now() - interval '24 hours' AND decision = 'block' AND NOT corroborated;
