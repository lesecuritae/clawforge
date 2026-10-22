-- Policy for the long-window SSH rule `ssh_bruteforce_slow` (security-engine rule v1: at least
-- 15 failed logins from one source within an hour, the pace the five-minute rule cannot see).
-- Same class and floor as the other rules: it records and explains; enforcement still needs the
-- independent-evidence and approval gates, and an `observe` policy enforces nothing.
INSERT INTO security_policies (id, name, version, status, class, rule_id, min_severity)
VALUES ('00000000-0000-4000-9000-000000000005', 'ssh_bruteforce_slow-default', 1, 'active',
        'observe', 'ssh_bruteforce_slow', 'medium')
ON CONFLICT (id) DO NOTHING;
