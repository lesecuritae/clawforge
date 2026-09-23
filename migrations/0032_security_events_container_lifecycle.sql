-- Adds container_lifecycle_changed to security_events.event_type (roadmap
-- phase 3, Docker sensor). Additive: no other column or table changes.
-- Kept as its own event type rather than folding into
-- container_anomaly/container_escape_attempt, which are for runtime
-- behavioral anomalies, not routine lifecycle/image/network configuration
-- change - see clawforge-security-events' module doc comment.

ALTER TABLE security_events DROP CONSTRAINT security_events_event_type_check;
ALTER TABLE security_events ADD CONSTRAINT security_events_event_type_check CHECK (event_type IN (
    'firewall_block','firewall_rule_changed','auth_failure','auth_anomaly',
    'ssh_login_failure','ssh_login_anomaly','http_anomaly','dns_anomaly',
    'port_scan_detected','container_anomaly','container_escape_attempt',
    'container_lifecycle_changed'
));
