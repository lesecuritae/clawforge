# Firewall Action Layer (preflight/render only)

Roadmap phase 6 ("Firewall Action Layer"), first increment.
`clawforge-firewall-agent` is a library crate (no running service yet -
see "What's deliberately not built yet" below) defining the typed adapter
contract the roadmap asks for, and one concrete adapter: `NftablesAdapter`.

## No apply path exists yet, on purpose

`FirewallAdapter::render` builds the exact `nft` command lines a real
apply *would* run and returns them in a `FirewallActionReceipt` - it never
invokes `nft` in any mutating form. There is no function in this crate
capable of changing a host's firewall state at all. This matches the
roadmap's own "zunächst vollständig im Dry-Run" literally: not a flag that
defaults to safe (`clawforge-executor` already has one,
`CLAWFORGE_EXECUTOR_DRY_RUN`, hardcoded `true` - refuses to start
otherwise), but the absence of any mutating capability in the source
itself.

## One exclusive table, one pre-provisioned set - never a free-form rule

The roadmap is specific: "exklusive Clawforge-Tabelle/-Chain ...
ausschließlich ein vorprovisioniertes Set verwalten". This adapter never
renders `nft add rule` at all - an operator provisions exactly one rule
ahead of time, out of band (e.g. `... ip saddr @blocklist drop`), and this
adapter only ever adds or removes *elements* of the named set
(`blocklist`) within Clawforge's own table (`inet clawforge`). A bug here
can at most toggle membership of one address in one set; it cannot inject
a new rule, touch another table, or affect anything the operator did not
already provision by hand.

## Command construction, not string interpolation

Every `nft` invocation is built as an explicit `Vec<String>` of arguments
passed to `tokio::process::Command` - never a shell string, so there is no
shell to inject into in the first place. `preflight`'s read-only
inspection (`nft -j list set ...`) is built the same way, for the same
reason, even though it is read-only: the roadmap's own gate ("es
existiert keine freie Shell") has no "but this call is harmless"
exception. `FirewallTarget::validate` rejects a malformed target before it
is ever used to build a command, as defense in depth on top of that.

## Two target kinds, two risk shapes

- **`ThreatIntelIndicator`** - a raw CIDR/IP that is already public
  threat-intel data (`indicators.value`, e.g. a Spamhaus DROP entry) -
  never pseudonymized in the first place, so rendering it is exactly as
  sensitive as the indicator feed itself already is.
- **`IncidentSource`** - a pseudonymized resource (`ip-pseudonym:<hash>`)
  from a corroborated incident (see `docs/policy-engine.md`'s two
  corroboration paths). Rendering it **never** resolves the pseudonym to a
  raw IP - the receipt contains a literal `<resolved-at-apply-time:
  ip-pseudonym:...>` marker, never a real address. Only a real `apply`
  step (not built yet) would ever resolve it, via `security_ip_resolutions`
  (migration `0036`), and only just-in-time - never persisting the
  resolved value into a receipt or anywhere else longer-lived.

### `security_ip_resolutions`: the one narrow exception to "never persist a raw IP"

`record_security_event` writes one short-TTL row here (default 24h, see
`CLAWFORGE_IP_RESOLUTION_TTL_SECONDS`, refreshed on every new event from
the same source) for **every** security event it records, not only a
threat-intel reputation hit. Why not gate it on a reputation hit alone:
corroboration (what makes a `Block` decision reachable at all, see
`docs/policy-engine.md`) can also come from two independent *behavioral*
rules firing for the same source - a plain `ssh_bruteforce` first, then
later, separately, the same source starts an `http_scan` - with no
external reputation hit involved at either point individually. By the
time that combination is recognized, `clawforge-security-engine` (which
only ever works from pseudonyms) cannot be the one to retain the mapping;
it has to already exist. The short TTL and the "only ever resolved
just-in-time by a real apply step, never copied into a receipt" rule are
what keep this from being a blanket raw-IP log despite covering every
event.

## Registered connector/actions (migration `0036`), disabled by default

A `firewall` connector type and two `connector_action` rows -
`nftables.block_indicator` (risk `high`) and
`nftables.block_incident_source` (risk `critical`) - both
`requires_approval=TRUE`, both `enabled=FALSE`, matching migration
`0027`'s own precedent for every other connector action: the executor
stays dry-run-only until a separately reviewed change explicitly enables
one. Two actions, not one, because the two target kinds are genuinely
different risk shapes (see above), not the same action with two ways to
fill in a parameter.

## What's deliberately not built yet

- **No running service.** This is a library crate today; wiring it into
  `clawforge-executor`'s dispatch loop (so a claimed `execution_request`
  actually calls an adapter, instead of the executor's current fully
  generic dry-run no-op) is separate follow-up work.
- **No real `apply`, `verify`, or `rollback`.** Only `preflight` (read-only)
  and `render` (pure, no I/O) exist.
- **No HAProxy adapter, no Tailscale adapter.**
- **The roadmap's mandatory pre-lab-test gates** (fuzz/negative tests
  beyond the unit tests here, an isolated network lab confirming no
  self-lockout) are not attempted - they only make sense once a real
  `apply` exists to gate.
- **`nftables.block_incident_source`'s target actions are disabled**, same
  as every other connector action registered this way - nothing here
  changes that a reviewed, explicit change is required before any of this
  can run for real, in a lab or otherwise.
