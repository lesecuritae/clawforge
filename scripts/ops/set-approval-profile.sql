-- Owner-role configuration of the approval profile (migration 0071). Not reachable from the application.
-- Opt in (single operator), one designated Administrator account and the listed incident-source actions only:
--   psql -v ON_ERROR_STOP=1 -v mode=single_operator -v operator=<admin-username> \
--        -v actions=nftables.block_incident_source -v note='sole owner, canary' -f set-approval-profile.sql
-- Back to the multi-person default:
--   psql -v ON_ERROR_STOP=1 -v mode=multi_person -f set-approval-profile.sql
-- Allowed actions are limited by a CHECK to the four *.block_incident_source actions; quarantine can never be listed.
-- Every change is written to audit_events (action approval_profile_changed).
\if :{?mode}
\else
  \echo 'set -v mode=single_operator|multi_person'
  \quit 1
\endif
BEGIN;
UPDATE approval_profile
   SET mode = :'mode',
       operator_user_id = CASE WHEN :'mode' = 'single_operator'
           THEN (SELECT id FROM admin_users WHERE username = :'operator' AND role = 'Administrator' AND enabled) ELSE NULL END,
       allowed_actions = CASE WHEN :'mode' = 'single_operator' THEN string_to_array(:'actions', ',') ELSE '{}'::TEXT[] END,
       note = COALESCE(:'note', '')
 WHERE singleton;
SELECT mode, operator_user_id IS NOT NULL AS has_operator, allowed_actions FROM approval_profile;
COMMIT;
