# Network intelligence

Clawforge keeps network context separate from threat feeds. The network provider boundary normalizes ASN, BGP, and RPKI responses into `NetworkBatch` values before persistence and risk evaluation. No network provider can block traffic directly.

The ASN adapters are RIPEstat, BGPView, PeeringDB, CAIDA AS Rank, and Team Cymru. The routing adapters are RIPE RIS, RouteViews, and BGPStream. `RpkiProvider` consumes ROA validation results and preserves `Valid`, `Invalid`, and `Unknown` states. Each adapter has a bounded HTTP timeout, response validation, source identifier, confidence, and configurable lookup resource.

Set `CLAWFORGE_ENABLE_NETWORK=true` to run the network jobs. The default resources are conservative examples and should be replaced with operator-selected ASN or prefix values. Provider-specific resource variables are `CLAWFORGE_RIPESTAT_RESOURCE`, `CLAWFORGE_BGPVIEW_RESOURCE`, `CLAWFORGE_PEERINGDB_RESOURCE`, `CLAWFORGE_CAIDA_RESOURCE`, `CLAWFORGE_TEAM_CYMRU_RESOURCE`, `CLAWFORGE_RIPE_RIS_RESOURCE`, `CLAWFORGE_ROUTEVIEWS_RESOURCE`, `CLAWFORGE_BGPSTREAM_RESOURCE`, and `CLAWFORGE_RPKI_RESOURCE`. A complete endpoint can be supplied with the corresponding `CLAWFORGE_<PROVIDER>_ENDPOINT` override.

ASN records retain name, organisation, country, registry, prefixes, network type, reputation, and first/last seen timestamps. BGP changes retain prefix, previous and new origin ASN, event time, source, route status, and RPKI state. Repeated changes are deduplicated by prefix, origin transition, and source. RPKI records are deduplicated by prefix, ASN, status, timestamp, and source.

Network evidence reaches the risk engine through the same bounded assessment path as threat indicators. RPKI `Valid` receives a trust adjustment, `Invalid` adds risk, anomalous BGP events are strong risk signals, and hosting/cloud ASN context is explanatory and bounded. Verified trusted infrastructure remains the only source of the infrastructure trust bonus.
