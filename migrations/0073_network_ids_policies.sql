-- Seed policies for the two new network-ids correlation rules (security-engine
-- rule v1), following the same convention as every other rule's default seed
-- (migrations 0034, 0061, 0066): 'observe' class and 'medium' floor. Without
-- this, assessments for these rules accumulate in the undecided backlog with
-- no policy decision ever recorded, even though the security-engine itself
-- already creates incident candidates independently via persist_correlation.
-- An 'observe' policy records and explains; enforcement still needs the
-- independent-evidence and approval gates on top of this.
INSERT INTO security_policies (id, name, version, status, class, rule_id, min_severity)
VALUES
    ('00000000-0000-4000-9000-000000000006', 'network_ids_high_priority_alert-default', 1,
     'active', 'observe', 'network_ids_high_priority_alert', 'medium'),
    ('00000000-0000-4000-9000-000000000007', 'network_ids_alert_burst-default', 1,
     'active', 'observe', 'network_ids_alert_burst', 'medium')
ON CONFLICT (id) DO NOTHING;
