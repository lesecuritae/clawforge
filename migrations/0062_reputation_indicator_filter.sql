-- Network-context providers (RouteViews, RIPE RIS, RIPEstat, ...) store what they
-- observe as indicators tagged 'network-intelligence'. They describe routing, not
-- reputation, yet the reputation lookup matched every indicator: production held a
-- RouteViews row 0.0.0.0/0 (confidence 70) that matched EVERY IPv4 address and
-- marked thousands of assessments as threat-intel corroborated.
--
-- One filtered lookup is now the only definition of "this address is listed":
--   * indicators of the network-context providers never count, and
--   * a prefix must be plausibly specific (at least /8 for IPv4, /16 for IPv6),
--     so a default or near-default route can never match everything.
-- Same ordering as before: highest confidence, then most recently confirmed.
CREATE OR REPLACE FUNCTION clawforge_ip_reputation(p_ip INET)
RETURNS TABLE (source TEXT, confidence SMALLINT, last_seen TIMESTAMPTZ)
LANGUAGE sql
STABLE
AS $$
    SELECT i.source, i.confidence, i.last_seen
      FROM indicators i
     WHERE i.expires_at > NOW()
       AND NOT (i.categories ? 'network-intelligence')
       AND ( (i.indicator_type = 'Ip' AND i.value = host(p_ip))
          OR (i.indicator_type = 'Prefix'
              AND masklen(i.value::cidr) >= CASE family(i.value::cidr) WHEN 4 THEN 8 ELSE 16 END
              AND p_ip <<= i.value::cidr) )
     ORDER BY i.confidence DESC, i.last_seen DESC
     LIMIT 1
$$;
