-- Current reputation and routing context for a pseudonymized source, evaluated
-- inside the database so the raw address never leaves it.
--
-- Until now a source counted as "listed" only if a feed listed it at the moment
-- its events were ingested: a listing that arrived later was ignored, a delisting
-- or an expired indicator was not noticed, and ASN reputation could not be used at
-- all because nothing mapped an address to its origin ASN.
--
--   source_network_context          routing context (announced prefix, origin ASNs,
--                                   RPKI summary) per source, fetched by the worker
--                                   from a public keyless API for suspicious sources
--                                   only, with TTL, retry and backoff bookkeeping.
--   clawforge_network_context_targets   worker: which sources still need context.
--   clawforge_record_network_context    worker: store a result, re-verified here.
--   clawforge_current_source_intel      policy / resolver: the current view.
--
-- Routing facts are context. They never make a source "listed"; only a reputation
-- indicator does (the address itself, or its origin ASN on the ASN-DROP list).

CREATE TABLE source_network_context (
    pseudonym TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('ok', 'unrouted', 'failed', 'skipped')),
    prefix CIDR,
    origin_asns BIGINT[] NOT NULL DEFAULT ARRAY[]::BIGINT[],
    rpki TEXT NOT NULL DEFAULT 'not_checked'
        CHECK (rpki IN ('valid', 'invalid', 'mixed', 'unknown', 'not_checked')),
    source TEXT NOT NULL CHECK (source IN ('ripestat')),
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_error TEXT CHECK (last_error IS NULL OR last_error ~ '^[a-z0-9_ :-]{1,120}$'),
    CHECK (cardinality(origin_asns) <= 16),
    CHECK (status <> 'ok' OR (prefix IS NOT NULL AND cardinality(origin_asns) BETWEEN 1 AND 16)),
    CHECK (status <> 'unrouted' OR (prefix IS NULL AND cardinality(origin_asns) = 0))
);
CREATE INDEX source_network_context_expiry_idx ON source_network_context (expires_at);
-- Reachable only through the functions below; no role gets table privileges.

-- Which suspicious sources still need routing context. Only sources with a recent,
-- sufficiently confident assessment and an unexpired single-host resolution, never
-- more than 50 at once, most suspicious first. Executable by the worker role only.
CREATE OR REPLACE FUNCTION clawforge_network_context_targets(
    p_limit INTEGER,
    p_assessment_max_age_seconds INTEGER,
    p_min_confidence INTEGER
) RETURNS TABLE (pseudonym TEXT, raw_ip TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT r.pseudonym, host(r.raw_ip)
      FROM security_ip_resolutions r
      JOIN LATERAL (SELECT max(a.confidence) AS best
                      FROM security_assessments a
                     WHERE a.resource = r.pseudonym
                       AND a.last_seen > NOW() - make_interval(secs => p_assessment_max_age_seconds)) s
        ON s.best >= p_min_confidence
     WHERE r.expires_at > NOW()
       AND masklen(r.raw_ip) = CASE family(r.raw_ip) WHEN 4 THEN 32 ELSE 128 END
       AND p_assessment_max_age_seconds BETWEEN 60 AND 604800
       AND p_min_confidence BETWEEN 1 AND 100
       AND NOT EXISTS (
            SELECT 1 FROM source_network_context c
             WHERE c.pseudonym = r.pseudonym
               AND ((c.status <> 'failed' AND c.expires_at > NOW()) OR c.next_attempt_at > NOW()))
     ORDER BY s.best DESC, r.pseudonym
     LIMIT LEAST(GREATEST(p_limit, 0), 50)
$$;

-- Store one lookup result. The database re-verifies what it can: the source must
-- have an unexpired resolution, and the announced prefix must contain that very
-- address. A failure keeps previously stored good context and only schedules the
-- next attempt (exponential backoff, never shorter than the upstream Retry-After).
CREATE OR REPLACE FUNCTION clawforge_record_network_context(
    p_pseudonym TEXT,
    p_status TEXT,
    p_prefix CIDR,
    p_origin_asns BIGINT[],
    p_rpki TEXT,
    p_source TEXT,
    p_ttl_seconds INTEGER,
    p_retry_after_seconds INTEGER,
    p_error TEXT
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    res RECORD;
    prior RECORD;
    expiry TIMESTAMPTZ;
    delay INTEGER;
    min_len INTEGER;
BEGIN
    IF p_status NOT IN ('ok', 'unrouted', 'failed', 'skipped') OR p_source <> 'ripestat' THEN
        RETURN FALSE;
    END IF;
    SELECT raw_ip, expires_at INTO res
      FROM security_ip_resolutions
     WHERE pseudonym = p_pseudonym AND expires_at > NOW()
       AND masklen(raw_ip) = CASE family(raw_ip) WHEN 4 THEN 32 ELSE 128 END;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    SELECT * INTO prior FROM source_network_context WHERE pseudonym = p_pseudonym;

    IF p_status = 'failed' THEN
        delay := GREATEST(COALESCE(p_retry_after_seconds, 0), 0);
        delay := GREATEST(delay, LEAST(3600, 30 * (2 ^ LEAST(COALESCE(prior.attempts, 0), 7))::INTEGER));
        INSERT INTO source_network_context
            (pseudonym, status, source, expires_at, attempts, next_attempt_at, last_error)
        VALUES (p_pseudonym, 'failed', p_source, NOW(), 1,
                NOW() + make_interval(secs => delay), left(p_error, 120))
        ON CONFLICT (pseudonym) DO UPDATE
           SET attempts = source_network_context.attempts + 1,
               next_attempt_at = NOW() + make_interval(secs => delay),
               last_error = left(p_error, 120);
        RETURN TRUE;
    END IF;

    IF p_ttl_seconds IS NULL OR p_ttl_seconds < 60 OR p_ttl_seconds > 86400 THEN
        RETURN FALSE;
    END IF;
    expiry := LEAST(NOW() + make_interval(secs => p_ttl_seconds), res.expires_at);
    IF p_status = 'ok' THEN
        -- (computed before the IF: plpgsql ends a condition at the first THEN token)
        min_len := CASE WHEN p_prefix IS NULL THEN 0 WHEN family(p_prefix) = 4 THEN 8 ELSE 16 END;
        IF p_prefix IS NULL
           OR masklen(p_prefix) < min_len
           OR NOT (res.raw_ip <<= p_prefix)
           OR p_origin_asns IS NULL OR cardinality(p_origin_asns) NOT BETWEEN 1 AND 16
           OR EXISTS (SELECT 1 FROM unnest(p_origin_asns) a WHERE a IS NULL OR a < 1 OR a > 4294967295)
           OR p_rpki NOT IN ('valid', 'invalid', 'mixed', 'unknown', 'not_checked') THEN
            RETURN FALSE;
        END IF;
    ELSE
        p_prefix := NULL;
        p_origin_asns := ARRAY[]::BIGINT[];
        p_rpki := 'not_checked';
    END IF;
    INSERT INTO source_network_context
        (pseudonym, status, prefix, origin_asns, rpki, source, fetched_at, expires_at,
         attempts, next_attempt_at, last_error)
    VALUES (p_pseudonym, p_status, p_prefix, p_origin_asns, p_rpki, p_source, NOW(), expiry,
            0, NOW(), NULL)
    ON CONFLICT (pseudonym) DO UPDATE
       SET status = EXCLUDED.status, prefix = EXCLUDED.prefix, origin_asns = EXCLUDED.origin_asns,
           rpki = EXCLUDED.rpki, source = EXCLUDED.source, fetched_at = EXCLUDED.fetched_at,
           expires_at = EXCLUDED.expires_at, attempts = 0, next_attempt_at = NOW(), last_error = NULL;
    RETURN TRUE;
END;
$$;

-- The current view of one source: reputation of the address itself, reputation of
-- its origin ASN (ASN-DROP style lists only), and the routing context. Everything
-- is looked up now against unexpired indicators, so a listing that arrived after
-- the events is seen and a removed or expired one disappears. 'resolved' is false
-- when the source has no unexpired single-host resolution: the caller then has no
-- current view and must fall back deliberately, not assume "not listed".
CREATE OR REPLACE FUNCTION clawforge_current_source_intel(p_pseudonym TEXT)
RETURNS TABLE (
    resolved BOOLEAN,
    ip_listed BOOLEAN, ip_source TEXT, ip_confidence SMALLINT, ip_last_seen TIMESTAMPTZ,
    asn_listed BOOLEAN, asn_source TEXT, asn BIGINT, asn_confidence SMALLINT, asn_last_seen TIMESTAMPTZ,
    context_status TEXT, prefix_text TEXT, origin_asns BIGINT[], rpki TEXT, context_fetched_at TIMESTAMPTZ,
    bgp_anomaly BOOLEAN
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    addr INET;
    ip_hit RECORD;
    asn_hit RECORD;
    ctx RECORD;
    anomaly BOOLEAN := FALSE;
BEGIN
    SELECT raw_ip INTO addr
      FROM security_ip_resolutions
     WHERE pseudonym = p_pseudonym AND expires_at > NOW()
       AND masklen(raw_ip) = CASE family(raw_ip) WHEN 4 THEN 32 ELSE 128 END;
    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, FALSE, NULL::TEXT, NULL::SMALLINT, NULL::TIMESTAMPTZ,
            FALSE, NULL::TEXT, NULL::BIGINT, NULL::SMALLINT, NULL::TIMESTAMPTZ,
            NULL::TEXT, NULL::TEXT, NULL::BIGINT[], NULL::TEXT, NULL::TIMESTAMPTZ, FALSE;
        RETURN;
    END IF;

    SELECT * INTO ip_hit FROM clawforge_ip_reputation(addr);
    SELECT * INTO ctx FROM source_network_context c
     WHERE c.pseudonym = p_pseudonym AND c.status = 'ok' AND c.expires_at > NOW();
    SELECT i.source AS source, i.confidence AS confidence, i.last_seen AS last_seen, o.asn AS asn
      INTO asn_hit
      FROM unnest(COALESCE(ctx.origin_asns, ARRAY[]::BIGINT[])) AS o(asn)
      JOIN indicators i ON i.indicator_type = 'Asn' AND i.value = 'AS' || o.asn::TEXT
     WHERE i.expires_at > NOW() AND NOT (i.categories ? 'network-intelligence')
     ORDER BY i.confidence DESC, i.last_seen DESC
     LIMIT 1;
    IF ctx.status IS NOT NULL THEN
        anomaly := EXISTS (
            SELECT 1 FROM bgp_events b
             WHERE lower(b.status) = 'anomalous' AND b.last_seen > NOW() - INTERVAL '24 hours'
               AND b.prefix ~ '^[0-9a-fA-F:.]{2,45}/[0-9]{1,3}$'
               AND addr <<= (CASE WHEN b.prefix ~ '^[0-9a-fA-F:.]{2,45}/[0-9]{1,3}$'
                                  THEN b.prefix::CIDR END)
               AND masklen(b.prefix::CIDR) >= CASE family(b.prefix::CIDR) WHEN 4 THEN 8 ELSE 16 END);
    END IF;

    RETURN QUERY SELECT TRUE,
        ip_hit.source IS NOT NULL, ip_hit.source, ip_hit.confidence, ip_hit.last_seen,
        asn_hit.source IS NOT NULL, asn_hit.source, asn_hit.asn, asn_hit.confidence, asn_hit.last_seen,
        ctx.status, ctx.prefix::TEXT, ctx.origin_asns, ctx.rpki, ctx.fetched_at, anomaly;
END;
$$;

REVOKE ALL ON FUNCTION clawforge_network_context_targets(INTEGER, INTEGER, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION clawforge_record_network_context(TEXT, TEXT, CIDR, BIGINT[], TEXT, TEXT, INTEGER, INTEGER, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION clawforge_current_source_intel(TEXT) FROM PUBLIC;
