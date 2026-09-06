# Security model

- A single feed, ASN, BGP event, or RPKI result cannot independently block.
- Trusted infrastructure is administrator-registered and must be `Verified`; technology names alone do not create trust.
- Tailscale, NetBird, VLAN, VPN, IP ranges, ASNs, and prefixes are represented as registration types, with identifier, node, and CIDR matching available to the trust engine.
- Risk scores are bounded to 0–100 and retain reasons. Trust adjustments are bounded and do not erase contradictory behavior or threat evidence.
- PostgreSQL stores audit events, risk history, trust history, provider status, and indicator expiry data.
- LLM integration is analysis-only; it cannot enable providers, change policy, or block traffic.
