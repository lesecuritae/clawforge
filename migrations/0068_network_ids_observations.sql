-- Passive IDS observations only; no policy, permissions or action defaults change.
ALTER TABLE security_events DROP CONSTRAINT security_events_event_type_check;
ALTER TABLE security_events ADD CONSTRAINT security_events_event_type_check CHECK (event_type IN (
    'firewall_block','firewall_rule_changed','auth_failure','auth_anomaly',
    'ssh_login_failure','ssh_login_anomaly','http_anomaly','dns_anomaly',
    'port_scan_detected','container_anomaly','container_escape_attempt',
    'container_lifecycle_changed','network_ids_alert'
));
