-- Every SECURITY DEFINER function of the product (clawforge_*) must be executable by at least one
-- clawforge_* role. Returns the names of orphaned functions: EXPECT NO ROWS. A function nobody may call
-- is the signature of a roles script that was not updated together with its migration (1.2.3: the
-- policy engine could not call clawforge_assessment_shape and silently produced no decisions).
--   psql -At -f check-role-grants.sql
SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public' AND p.prosecdef AND p.proname LIKE 'clawforge_%'
   AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname LIKE 'clawforge\_%' AND has_function_privilege(r.rolname, p.oid, 'EXECUTE'))
 ORDER BY 1;
