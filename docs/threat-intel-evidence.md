# Reputation and routing evidence for source decisions

Status: implemented and tested in isolation (migrations 0062-0064). Nothing here
enables a block, a deployment or a data transfer by itself: the bridge is off by
default, and the routing-context worker is off by default.

## What counts as "listed"

A source is **listed** only if an unexpired *reputation* indicator names its address
(an `Ip` or a `Prefix` of at least /8 IPv4 or /16 IPv6) or its origin ASN (an `Asn`
indicator from an ASN-DROP style list). Indicators written by the routing-context
providers (RouteViews, RIPE RIS, RIPEstat, HackerTarget, PeeringDB, CAIDA, Team Cymru,
BGPStream, RPKI validator; category `network-intelligence`) describe the network, not
its reputation, and never count. Migration 0062 fixed a production defect where a
RouteViews `0.0.0.0/0` row matched every IPv4 address (read-only counts at the time:
3308 of 7793 assessments marked corroborated through it, 1240 shadow block decisions).

Free feeds already ingested by the worker (unchanged): Spamhaus DROP, EDROP and
ASN-DROP (hourly), abuse.ch Feodo; ThreatFox, URLhaus and MalwareBazaar need an
authentication key that this deployment does not have. Their licence terms are the
operator's to check; nothing new is fetched from them.

## The current view of a source

`clawforge_current_source_intel(pseudonym)` evaluates, inside the database and against
unexpired indicators *now*: is the address listed, is its origin ASN listed, what is
its routing context, is a BGP anomaly flagged for a covering prefix. It needs an
unexpired single-host `security_ip_resolutions` row; without one there is no current
view (not the same as "not listed"). So:

| Event | Effect on the next decision |
| --- | --- |
| Feed lists the address after the attack events | counts (basis `threat_intel_ip`) |
| Feed removes or lets the indicator expire | no longer counts, even if the ingest-time snapshot said "listed" |
| Origin ASN appears on the ASN list, routing context known | counts (basis `threat_intel_asn`) |
| Routing context only (RPKI invalid, multi-origin, BGP anomaly) | **never counts**; recorded in the decision snapshot and shown to approvers |
| Indicator below the confidence floor or not reconfirmed within the staleness limit | does not count |
| Source from a routing-context provider, or a default-route-wide prefix | does not count |
| No resolution (older than its TTL) | fallback to the ingest-time snapshot, and only from a real reputation source |

An ASN or routing observation never blocks an ASN or a prefix; at most it corroborates
one source's own behaviour, and the block (if any) is the single address.

## Routing context (off by default)

`CLAWFORGE_ENABLE_IP_CONTEXT=true` makes the worker ask RIPEstat's public, keyless Data
API (`network-info`, `rpki-validation`, identified by `sourceapp`) for the announced
prefix, origin ASN(s) and RPKI validity of sources that already produced a confident
assessment. **Enabling it sends those source addresses to RIPE NCC.** Bounds:

* only sources the database names as targets (recent assessment with at least
  `CLAWFORGE_IP_CONTEXT_MIN_CONFIDENCE`, within `..._ASSESSMENT_MAX_AGE_SECONDS`, live
  resolution, no fresh context); both are required, no defaults; at most `..._BATCH`
  (default 5, max 20, hard 50) per cycle;
* never a non-public address (loopback, private, link-local, CGNAT/Tailscale,
  multicast, documentation-adjacent special ranges, non-global IPv6): recorded as
  skipped without a request;
* one request at a time, spaced `..._SPACING_MILLIS` (default 2000, minimum 1000);
* HTTP 429: the whole loop pauses for `Retry-After` (bounded to one hour, 60 s if absent)
  and the source is not asked again before then; other failures back off per source
  exponentially in the database (30 s doubling, cap one hour); a refused result backs off
  the same way instead of being retried every cycle;
* responses are untrusted: size-capped while streaming, redirects refused, envelope must
  be `ok`/200, the prefix must contain the queried address and must not be implausibly
  wide, ASNs must be plain numbers; anything else is an error, never a partial result;
* the database re-verifies every stored result (live resolution, prefix contains the
  address, bounded values, TTL capped by the resolution's own expiry); a failure keeps
  previously stored good context.

I could not read RIPEstat's usage page from this environment (the fetch tool was not
permitted), so the bounds above are conservative choices, not a quoted limit; the response
shapes were checked against three live requests. Check the current usage terms before
enabling it.

## Policy and bridge

* The policy engine uses the current view for corroboration (basis in the rationale and
  `evidence_snapshot`, plus `routing_context`), then the independence rules of
  `behavior-validation.md`.
* The bridge (0064) requires, for `propose`/`automatic` (and by default for `simulate`),
  that the address or its origin ASN is currently listed with at least
  `CLAWFORGE_POLICY_BRIDGE_MIN_INTEL_CONFIDENCE` (required, 1-100) and reconfirmed within
  the evidence age. The immutable approval context records which listing counted, the
  routing facts, and the parameters used.
* **Dispatch-time revalidation:** when the executor claims such a request, the resolver
  releases the address only if the same condition still holds. A listing removed between
  approval and apply therefore cancels the apply before anything reaches the host.
* Management and own-network protection, TTL ceiling, budgets, dry-run and live
  authorization are unchanged; the address is still blocked as a single host with a TTL.

## Operator decisions that remain

Which sources to trust at which confidence (the three settings above), whether to enable
the routing-context worker (third-party transfer), the first bridge mode and rule, and the
release/deploy of migrations 0062-0064 (additive; ledger 61 -> 64 after 0062 ships).

## Retired providers and missing keys

`bgpview_asn` and `bgpstream` are no longer run by any code. `scripts/release/disable-retired-providers.sql` disables their registry rows (reversible, nothing deleted). `ThreatFox`, `URLhaus` and `MalwareBazaar` need an abuse.ch Auth-Key: with an empty secret file they report `provider configuration is missing: ..._AUTH_KEY` on every run and do not call the service. Put the key into the configured secret file; nothing in the code or the database invents one.

## Limits

BGP anomaly flags exist only for prefixes the BGP providers are configured to monitor; a
missing flag is not evidence of a clean route. RIPEstat answers describe the current
announcement, not history. RPKI `unknown`/`not_checked` is common and means nothing.
