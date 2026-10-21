-- Narrow, just-in-time read path for security_ip_resolutions.
--
-- Until now the table was written for every security event but nothing could
-- read it, so a pseudonymized incident-source block could never be applied for
-- real. The executor must not receive blanket SELECT on the table (it would be
-- a raw-IP log reader), so this SECURITY DEFINER function releases exactly one
-- address, only while the caller's own execution request is being dispatched:
--
--   * the request is in status 'starting' (just claimed by the executor),
--   * its action is one of the real incident-source block actions,
--   * its target is an unresolved incident_source and NOT simulation_only,
--   * the stored resolution has not expired,
--   * the stored address is a single host (full-length prefix).
--
-- Anything else returns no row. The address is never written to a receipt by
-- the caller; the caller records an audit event with the pseudonym only.
CREATE OR REPLACE FUNCTION clawforge_resolve_incident_source_for_apply(p_execution_id UUID)
RETURNS TABLE (pseudonym TEXT, raw_ip TEXT)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT r.pseudonym, host(r.raw_ip)
      FROM execution_requests e
      JOIN actions a ON a.id = e.action_id
      JOIN security_ip_resolutions r
        ON r.pseudonym = e.approval_context -> 'target' ->> 'pseudonym'
     WHERE e.id = p_execution_id
       AND e.status = 'starting'
       AND a.name IN ('nftables.block_incident_source',
                      'haproxy.block_incident_source',
                      'haproxy_ratelimit.block_incident_source',
                      'firewall.block_incident_source')
       AND e.approval_context -> 'target' ->> 'kind' = 'incident_source'
       AND (e.approval_context -> 'target' -> 'simulation_only') IS DISTINCT FROM 'true'::jsonb
       AND r.expires_at > NOW()
       AND masklen(r.raw_ip) = CASE family(r.raw_ip) WHEN 4 THEN 32 ELSE 128 END
$$;

REVOKE ALL ON FUNCTION clawforge_resolve_incident_source_for_apply(UUID) FROM PUBLIC;
