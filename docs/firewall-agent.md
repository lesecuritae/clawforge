# Firewall Action Layer

Roadmap phase 6 ("Firewall Action Layer"). `clawforge-firewall-agent`
defines the typed adapter contract the roadmap asks for, one concrete
adapter (`NftablesAdapter`) with real `apply`/`verify`/`rollback`, and
`clawforge-executor` now dispatches through it for `nftables.*` actions.

## Still dry-run by construction, not just by flag

`CLAWFORGE_EXECUTOR_DRY_RUN` remains hardcoded `true` - the executor
binary refuses to start otherwise (the process-level gate). Independently
of that, `dispatch()` in `executor/src/main.rs` re-reads the same env var
at the exact point it would call `NftablesAdapter::apply` and passes it
as `apply`'s required `dry_run: bool` (never defaulted): if some future
change ever relaxed the startup gate without this call site being updated
too, dispatch would still default to `dry_run: true` rather than silently
start applying for real. On top of both: the executor container's own
`cap_drop: [ALL]` (see `compose.yml`) means it cannot actually mutate
nftables state today even if both of the above were somehow bypassed - a
real apply needs `CAP_NET_ADMIN`, which is deliberately not granted.
Flipping `CLAWFORGE_EXECUTOR_DRY_RUN` to `false` for a real host requires
revisiting that capability too, not just the env var.

## Never-block exclusion list

`NftablesAdapter::new` loads a built-in safety net (`127.0.0.0/8`,
`::1/128`, `169.254.0.0/16`, `fe80::/10`) plus whatever
`CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS` configures (comma-separated
IPs/CIDRs) - an operator's own management/SSH source range belongs there.
`render` and `apply` both refuse - before building or running anything -
a target whose network overlaps any excluded network **in either
direction**: a broad target CIDR that merely contains an excluded `/32`
is caught just as a `/32` target inside a broad excluded range would be.
A malformed configured entry fails the *entire* list closed (every
subsequent target refused, not just the malformed entry silently
dropped) - the same fail-closed choice this codebase already made for
pseudonymization (`CLAWFORGE_ANALYZER_IP_HMAC_KEY`). `rollback` is
deliberately **not** gated: removing an element from the blocklist is
always the safe direction. This is the concrete guardrail against
self-lockout that exists today, in place of the isolated network lab's
own self-lockout confirmation (see "The isolated network lab" below -
that one still needs a real provisioned host's management path to mean
anything, which no disposable container can stand in for).

## Mass-block budget

`clawforge-executor` refuses to dispatch a real (non-dry-run) `nftables.*`
or `haproxy.*` apply once `CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW`
(default 20) real applies have already been recorded within the trailing
`CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS` (default 300) - a runaway policy
engine or a config mistake must not be able to block hundreds of
addresses in a burst. One counter shared across both adapters, not one
each. The count comes from `firewall_action_receipts` itself
(`PostgresStore::recent_real_firewall_apply_count`), not an in-memory
counter, so the budget holds across a process restart and across
multiple executor replicas sharing the same database. A refused dispatch
never calls `dispatch()`/the adapter at all - the `execution_request` is
completed as failed with a clear `"mass-block budget exceeded"`
`error_summary`, and no `nft`/Runtime API command is built or run. If
the budget check itself fails (a database error), the same request also
fails closed rather than proceeding unchecked. Dry runs and non-firewall
actions are never gated - there is nothing to bound. Concurrency (more
than one real apply in flight at once) is not a separate counter: the
executor's poll loop claims and dispatches one request per tick,
sequentially, so within a single process it is already 1 by
construction; bounding it across multiple replicas targeting the *same*
host remains open (see "What's deliberately not built yet" below).

## TTL-driven auto-rollback

A real (non-dry-run) block does not stay in effect forever just because
nothing else removes it. Every tick, `sweep_expired_firewall_targets`
asks `PostgresStore::expired_unrolled_back_firewall_targets` for every
real apply receipt whose `expires_at` has passed with no later rollback
receipt for the same `adapter`/`target_fingerprint`, reconstructs a
`FirewallTarget` from the receipt's own `target_json` (the same
`{"kind":...}` JSON contract used everywhere else), picks the adapter via
the shared `adapter_for` (also used by `dispatch()`, so the two can never
disagree on which adapter a name means), and calls its `rollback`. A
successful rollback is recorded as a new `receipt_kind: "rollback"` row
(never an `UPDATE` of the apply row - the table stays append-only) so the
same target is not swept again. A failed rollback is logged and left for
the next tick to retry - it is not recorded, so the sweep picks the same
target up again. If persisting the rollback receipt itself fails after
an otherwise-successful rollback, the target (already genuinely
unblocked) gets retried next tick too, which
`rolling_back_an_element_that_was_never_applied_fails_cleanly` proves
fails (not silently succeeds) - a recurring warning log, not a security
problem, until an operator clears the stuck row by hand.

`target_fingerprint` (`FirewallActionReceipt`'s own field, set by both
adapters) is what matches an apply receipt to its rollback - and it is
built from `redacted_element_reference`, never the real resolved element,
so a `ResolvedIncidentSource`'s raw IP never ends up in it either (see
"Three target kinds" above).

## One exclusive table, two pre-provisioned typed sets - never a free-form rule

The roadmap is specific: "exklusive Clawforge-Tabelle/-Chain ...
ausschließlich ein vorprovisioniertes Set verwalten". `NftablesAdapter`
never renders `nft add table`/`add chain`/`add set`/`add rule` at all -
`scripts/nftables-clawforge-provision.sh` provisions the exclusive table
(`inet clawforge`) and its two typed sets (`blocklist` for IPv4,
`blocklist6` for IPv6 - nftables sets are typed, so the families can't
share one) plus the block rule, idempotently, out of band. This adapter
only ever adds or removes *elements* of one of those two sets. A bug here
can at most toggle membership of one address in one set; it cannot inject
a new rule, touch another table, or affect anything the operator did not
already provision by hand. `add rule` is **not** idempotent the way `add
table`/`add set` are (each call appends a duplicate), so the provisioning
script gates it behind a `grep -q` check of the chain listing.

## Command construction, not string interpolation

Every `nft` invocation - `preflight`'s read-only inspection, and now
`apply`/`verify`/`rollback`'s real mutating calls - is built as an
explicit `Vec<String>` of arguments passed to `tokio::process::Command`,
never a shell string, so there is no shell to inject into in the first
place. `FirewallTarget::validate` rejects a malformed target before it is
ever used to build a command, as defense in depth on top of that.

## Address normalization

`normalize_address()` folds an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`)
to plain IPv4 before set selection or command-building - the same bug
class as this session's earlier HAProxy-sensor fix, caught here before it
shipped rather than live. `apply_verify_rollback_round_trip_for_ipv6`'s
lab-test sibling `ipv4_mapped_ipv6_and_plain_ipv4_are_the_same_element_to_
nftables` pins this down against real `nft`.

## Three target kinds, three risk/safety shapes

- **`ThreatIntelIndicator`** - a raw CIDR/IP that is already public
  threat-intel data (`indicators.value`, e.g. a Spamhaus DROP entry) -
  never pseudonymized in the first place, so rendering and applying it is
  exactly as sensitive as the indicator feed itself already is.
- **`IncidentSource`** - a pseudonymized resource (`ip-pseudonym:<hash>`).
  `render` **never** resolves the pseudonym - the receipt contains a
  literal `<resolved-at-apply-time:ip-pseudonym:...>` marker, never a real
  address. `apply` on this variant directly fails, by construction (the
  placeholder isn't valid `nft` syntax) - safe by construction, not by
  convention. See `applying_an_unresolved_incident_source_fails_closed`.
- **`ResolvedIncidentSource`** - only ever constructed by a caller that
  has already resolved the pseudonym via `security_ip_resolutions`
  (migration `0036`), and only for `apply`/`verify`/`rollback`. `render`
  returns `Err` if given this variant. `apply` cannot refuse it outright
  (that would make a resolved incident source entirely unappliable) but
  still must not let its own returned receipt carry the raw IP: it builds
  the *real* `nft`/HAProxy command from the real resolved address (that
  part is unavoidable - it has to actually block the right address), but
  builds `rendered_commands`/`rollback_commands`/`target_fingerprint` for
  the receipt it returns from a *redacted* reference
  (`redacted_element_reference`) that uses the same
  `<resolved-at-apply-time:...>` placeholder `render` uses for an
  unresolved `IncidentSource`, never the raw IP. A raw IP can never reach
  anything a caller might persist, through either `render` or `apply`.
  **Found and fixed as a real bug this session**: `apply`'s own receipt
  originally used the same (unredacted) reference the real command used -
  harmless while nothing persisted `apply`'s receipt, but
  `record_firewall_action_receipt` (added later the same session, before
  `ResolvedIncidentSource` had a live caller) would have persisted the
  raw IP straight into Postgres the moment one existed. Caught by
  reasoning through a later feature (TTL-driven auto-rollback) that
  needed a stable, safe-to-store `target_fingerprint`, not by a report;
  fixed with the redaction described above and pinned down by
  `nftables_apply_receipt_never_embeds_the_resolved_raw_ip`/
  `haproxy_apply_receipt_never_embeds_the_resolved_raw_ip` (fast, no lab
  needed) plus both real lab round-trip tests now also asserting on the
  receipt they get back.

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
it has to already exist. The short TTL and "only ever resolved
just-in-time by whoever constructs a `ResolvedIncidentSource`, never
copied into a receipt or anywhere else longer-lived" are what keep this
from being a blanket raw-IP log despite covering every event.

## Set-membership verification: a real bug, found in the lab, fixed

`verify`'s `set_contains_target()` originally checked membership with
naive string containment (`raw_set_json.contains(&element)` where
`element = "addr/len"`). The isolated-lab round-trip test for IPv6 (a
`/48` CIDR) caught that this **never matches any CIDR/prefixed element**:
`nft -j list set` splits a prefixed element into structured JSON
(`{"prefix":{"addr":...,"len":...}}`), never a combined `"addr/len"`
string - only bare (prefix-less) IP elements happened to match by
coincidence. Fixed with real `serde_json::Value` structural parsing,
confirmed against a captured real JSON fixture in a fast unit test and by
re-running the full lab suite.

## The isolated network lab

`scripts/test-firewall-lab.sh` runs the 9 `#[ignore]`-gated real-`nft`
tests (round-trip apply/verify/rollback for IPv4 and IPv6, dry-run
never touching the real set, idempotent double-apply, resolved-source
apply, unresolved-source fails closed, rollback-of-never-applied fails
cleanly, IPv4-mapped-IPv6 normalization, and the break-glass drill below)
inside a disposable `rust:1.98-bookworm` container
(`--cap-add=NET_ADMIN --cap-add=NET_RAW`), never against srv19680 or any
other real host - the container's network namespace is created fresh by
the runtime and destroyed with it. This is the "isoliertes Netzwerk-Lab"
the roadmap's phase 6 gate asks for, in the form the tools available in
this environment can actually provide. What it does **not** provide:
self-lockout confirmation against a *provisioned* host's real management
path (SSH, HAProxy admin, etc.) - this container has no equivalent of
that at all. That confirmation is still an open item before ever
applying for real against a live host.

## Break-glass procedure

`scripts/nftables-clawforge-break-glass.sh` removes Clawforge's *entire*
nftables footprint on a host in one atomic `nft delete table inet
clawforge` call - not a selective per-target rollback. It has no
dependency on `clawforge-executor`, the API, Docker, or Postgres being
reachable or even running: it is meant to be run directly over SSH on the
affected host when something more than a normal rollback is needed -
suspected self-lockout, a malfunctioning executor, or any situation where
"stop everything Clawforge did to this host's firewall, right now" is the
correct response. Because `NftablesAdapter` never renders anything
outside that one table (see "One exclusive table" below), deleting it
undoes 100% of Clawforge's footprint at once, with zero risk to any other
rule, table, or chain on the host. After running it, Clawforge blocks
nothing on that host until the table is reprovisioned
(`scripts/nftables-clawforge-provision.sh`) and the executor's current
desired state is re-applied.

**Rehearsed, not just documented**: the lab's own
`break_glass_removes_every_trace_of_the_clawforge_table` test blocks a
real target, confirms it is genuinely blocked, runs the break-glass
script, confirms the table is entirely gone, and reprovisions it
afterwards - in the same disposable, isolated container every other real
lab test uses.

## Executor dispatch wiring

- `ExecutionRequestInput.target: Option<serde_json::Value>` is folded into
  `approval_context` (not a new column) - the existing
  `approval_context_hash` drift-invalidation mechanism then applies to
  the target for free, which is what gives "Freigabe an ... Ziel ...
  binden; Drift invalidiert sie" without a second mechanism.
- `claim_execution_request_for_dispatch(worker_id)` claims one request
  (same maintenance sweep, same lease as the existing dry-run path) and
  leaves it in `starting` without auto-completing it, returning its
  `action_name`/`target` for the caller to actually dispatch.
  `complete_execution_dispatch(...)` marks the terminal status (stepping
  through `running` first, since the transition table only allows a
  terminal status from `running`), releases the lease, and records the
  metric.
  `dispatch()` in `executor/src/main.rs` parses `target` via
  `TryFrom<&serde_json::Value> for FirewallTarget`
  (`{"kind":"threat_intel_indicator","cidr":...,"source":...}` /
  `{"kind":"incident_source","pseudonym":...}`) for any `nftables.`-
  prefixed action name and calls `NftablesAdapter::apply`; every other
  action name keeps the exact prior fully-generic dry-run behavior
  unchanged.

## Registered connector/actions (migration `0036`), disabled by default

A `firewall` connector type and two `connector_action` rows -
`nftables.block_indicator` (risk `high`) and
`nftables.block_incident_source` (risk `critical`) - both
`requires_approval=TRUE`, both `enabled=FALSE`, matching migration
`0027`'s own precedent for every other connector action: the executor
stays dry-run-only until a separately reviewed change explicitly enables
one. Two actions, not one, because the two target kinds are genuinely
different risk shapes, not the same action with two ways to fill in a
parameter.

## HAProxy adapter

`HaproxyAdapter` implements the same [`FirewallAdapter`] contract as
`NftablesAdapter` - same `FirewallTarget`/`FirewallAction` types, same
preflight/render/apply/verify/rollback shape - over the HAProxy Runtime
API's line-oriented text protocol (a `tokio::net::UnixStream` write,
never a subprocess) instead of `nft` subprocess argv. Only the roadmap's
"Maps/ACLs" half is built: blocking a source IP/CIDR via an **ACL
pattern file** (`acl ... src -f <file>`, manipulated at runtime with
`add acl`/`del acl`/`show acl`) - **not** HAProxy's separate `map`-file
mechanism (`map_ip()`/`map_str()` converters, a true key -> value lookup,
manipulated with `add map`/`show map`), which is a different runtime
object entirely and not what a membership blocklist needs. Rate-limiting
(HAProxy stick-tables - a genuinely different mechanism, a per-key
counter rather than a membership set) is a separate adapter,
`HaproxyRateLimitAdapter` - see its own section below.

Unlike nftables, this adapter cannot own an entire exclusive config file:
`haproxy.cfg` is a single shared file already serving an operator's real
frontends. `scripts/haproxy-clawforge-provision.sh` only ensures
Clawforge's own ACL pattern file exists and prints the two lines an
operator adds to each frontend they want protected
(`acl clawforge_blocked src -f <file>` +
`http-request deny if clawforge_blocked`) - it never edits `haproxy.cfg`
itself, and neither does the adapter afterwards: only the pattern file's
entries change, via the Runtime API.

**A real bug, found in the lab, not assumed away**: the first version of
this adapter used `add map`/`show map`/`del map` (`show map` for an
`acl ... -f` reference returned literally nothing - `# id (file)
description` and an empty list - because an ACL pattern file is not
registered as a "map" object at all). Caught immediately by
`scripts/test-haproxy-lab.sh`'s real round-trip test failing (`apply`
reported success, `verify` then reported `NotPresent`), diagnosed by
inspecting the real Runtime API's actual responses (`show acl` vs `show
map`) rather than guessing from documentation, and fixed by switching to
the correct `acl` commands throughout.

**Rehearsed in its own isolated lab** (`scripts/test-haproxy-lab.sh`):
installs haproxy in a disposable `rust:1.98-bookworm` container (no
special capabilities needed - the Runtime API is a plain Unix socket),
provisions the ACL file, starts a minimal throwaway haproxy instance with
its own frontend/backend (never a real deployment's config), and runs
the adapter's real round-trip tests against it. Confirmed idempotency
behavior empirically rather than assuming nftables' own semantics carry
over: a repeat `add acl` for an already-present pattern did not error,
and the target remained found after one rollback in this session's runs
- documented as observed behavior, not guaranteed API contract, since
HAProxy's own documentation does not commit to it either way.

Registered via migration `0038`: `haproxy.block_indicator` (risk `high`)
and `haproxy.block_incident_source` (risk `critical`), same
`requires_approval=TRUE, enabled=FALSE` precedent as nftables.
`clawforge-executor`'s `dispatch()` routes any `haproxy.`-prefixed action
to `HaproxyAdapter` the same way it routes `nftables.`-prefixed ones to
`NftablesAdapter` - both share the same mass-block budget counter (see
above), not one each.

## HAProxy rate-limit adapter (stick-tables)

`HaproxyRateLimitAdapter` is the "Rate-Limits" half of the roadmap's
HAProxy adapter, alongside `HaproxyAdapter`'s "Maps/ACLs" half - same
`FirewallAdapter` contract, same target types, but a genuinely different
HAProxy mechanism: a **stick-table**, which stores a per-key
general-purpose counter (`gpc0`) rather than a membership list. `apply`
sets a key's `gpc0` to `1` via the Runtime API's `set table <table> key
<key> data.gpc0 1`; `verify`/`preflight` read it back via `show table
<table>`, parsing the real `key=... gpc0=...` line format structurally
(not by position - the field order isn't guaranteed); `rollback` clears
it via `clear table <table> key <key>`. Why `gpc0` and not a real rate
counter (`http_req_rate`, ...): HAProxy computes a rate counter from an
actual sliding window of observed traffic, not a value this adapter
could simply set to "blocked" - `gpc0` is the standard, version-stable
mechanism for "flag this key for a policy decision", which is exactly
what a Clawforge-driven block needs, and is what an operator's own ACL
(`sc_get_gpc0(0) gt 0`) checks.

An operator adds one explicitly-named `backend`/`stick-table` declaration
(`set table`/`show table` need to address it by an exact name, which an
inline per-frontend stick-table does not reliably give) plus a
`track-sc0`/ACL pair to each frontend they want protected -
`scripts/haproxy-clawforge-provision.sh` prints the exact snippet, which
has been verified against a real HAProxy instance. Same as
`HaproxyAdapter`: never touches `haproxy.cfg` itself, only ever sets or
clears one key's counter afterwards.

**A real behavioral difference found in the lab, not assumed**: unlike
`del acl` (which errors when the target pattern isn't present),
`clear table ... key ...` on a key that was never set (or already
cleared) succeeds with an empty response - idempotent by design, not by
convention. An earlier version of
`haproxy_ratelimit_rolling_back_an_element_that_was_never_applied_*`
asserted the opposite (mirroring the ACL adapter's own, different,
verified behavior) and failed against the real Runtime API, which is
what caught the actual difference between the two mechanisms rather than
an assumption carrying over incorrectly.

**The never-block exclusion list gap, found and closed while building
this adapter**: `check_never_block` was originally an `NftablesAdapter`-
only method, never called by `HaproxyAdapter` at all - meaning nothing
protected a HAProxy-driven block from loopback/link-local/an operator's
own configured management range, the exact self-lockout protection
`NftablesAdapter` already had. Refactored into a free function every
adapter's `render`/`apply` calls with its own `never_block` field
(`NftablesAdapter`, `HaproxyAdapter`, and this adapter all load it the
same way via `never_block_list_from_env`), closing the gap for the
existing ACL adapter too, not just this new one - proven by new tests for
both.

Rehearsed in the same isolated HAProxy lab as `HaproxyAdapter` (the lab's
throwaway config declares the named backend/stick-table
`scripts/haproxy-clawforge-provision.sh` instructs a real operator to
add). Registered via migration `0040`:
`haproxy_ratelimit.block_indicator` (risk `high`) and
`haproxy_ratelimit.block_incident_source` (risk `critical`), same
precedent as every other connector action. `dispatch()`'s adapter
selection checks the `haproxy_ratelimit` prefix *before* the plain
`haproxy` one - `"haproxy_ratelimit..."` also starts with `"haproxy"`, so
checking the generic prefix first would silently misroute rate-limit
actions to the ACL adapter instead.

## Multi-adapter dispatch: not just HAProxy

Every adapter so far (`nftables.*`, `haproxy.*`, `haproxy_ratelimit.*`) is
dispatched to exactly one adapter. That is deliberately not the only
option: a `firewall.*`-prefixed action fans out to **every** adapter
`CLAWFORGE_FIREWALL_ADAPTERS` configures (comma-separated, e.g.
`"nftables,haproxy"`) instead - `nftables` is always included regardless
of that list, because it is the host-wide, per-source-IP block that
covers *any* externally-facing service on the host, not only the ones
fronted by HAProxy. Without this, "block this source" would only ever
protect whatever happens to sit behind HAProxy - `nftables` closes that
gap by construction, not by an operator remembering to configure it.

`dispatch_multi_adapter` attempts every configured adapter regardless of
another one's failure (defense in depth: a HAProxy-layer block succeeding
is still worth having even if the host-wide one somehow failed, and vice
versa). Overall success is `true` iff the mandatory `nftables` adapter
succeeded - that is the actual guarantee a `firewall.*` action exists to
make. A receipt is persisted for every adapter that *did* succeed,
independent of overall success, since a real state change happened and
needs tracking (audit, TTL) regardless of a sibling's outcome. An
unrecognized name in `CLAWFORGE_FIREWALL_ADAPTERS` is logged and dropped,
not fatal - unlike the never-block exclusion list (where a silently
dropped entry is a self-lockout risk), omitting one optional, best-effort
extra layer is not: `nftables` alone already provides the core guarantee
regardless of what else was misconfigured.

`nftables.*`/`haproxy.*`/`haproxy_ratelimit.*` single-adapter actions
still exist and still work exactly as before - `firewall.*` is an
additional, broader option, not a replacement. Registered via migration
`0041`: `firewall.block_indicator` (risk `high`) and
`firewall.block_incident_source` (risk `critical`), same
`requires_approval=TRUE, enabled=FALSE` precedent as every other
connector action. The mass-block budget (above) counts every adapter a
`firewall.*` fan-out actually applies individually, not the fan-out as
one unit - three successful adapters count as three towards the shared
budget.

## Tailscale quarantine adapter

`TailscaleAdapter` is a real, working integration against the live
Tailscale Admin API - not a nftables/HAProxy-style `FirewallAdapter`
(a Tailscale device ID is a fundamentally different resource shape from
an IP/CIDR, so it deliberately has its own parallel
`TailscaleTarget{device_id}` / `TailscaleAction{target, reason}` /
`TailscaleActionReceipt` types rather than a fourth `FirewallTarget`
variant), but it has real `apply`/`verify`/`rollback` methods that make
real HTTP calls when `dry_run` is false.

**Mechanism.** Tailscale ACLs are additive "accept" only - there is no
"deny" action. Quarantining a device works by tagging it: a tag removes
a device from `autogroup:member`, so it only loses access if the
tailnet's own ACL policy scopes its accept rule(s) to
`autogroup:member` rather than `*`. `apply()` therefore does a
read-modify-write against `GET/POST /api/v2/device/{id}/tags`: it reads
the device's current tags, appends the quarantine tag
(`CLAWFORGE_TAILSCALE_QUARANTINE_TAG`, default `tag:clawforge-quarantine`)
if not already present, and `POST`s the full list back - the tags
endpoint is a full-replace, not additive, so a blind `POST` of just the
quarantine tag would silently wipe any other tags the device already
had. `verify()` re-reads the device's tags and checks the quarantine tag
is present. `rollback()` does the same read-modify-write in reverse,
removing the quarantine tag from whatever list is currently set.

**Credentials.** `TailscaleAdapter::new()` never fails - both
`CLAWFORGE_TAILSCALE_OAUTH_CLIENT_ID_FILE` and
`CLAWFORGE_TAILSCALE_OAUTH_CLIENT_SECRET_FILE` are optional at
construction (via `clawforge_secret::load_optional`, the same
`_FILE`/plain-value pattern used by `threatfox_auth_key` and friends).
Every method that actually needs to call the API fails closed with a
clear error if either is missing. A fresh OAuth2 `client_credentials`
token is fetched from `https://api.tailscale.com/api/v2/oauth/token` on
every `apply`/`verify`/`rollback` call - no caching, for implementation
simplicity. The OAuth client should be scoped to the narrow
`devices:core` capability, nothing broader.

**ACL prerequisite - this is an operational step, not something the
adapter can do for you.** For quarantine to actually deny traffic, the
tailnet's ACL policy must already have `tag:clawforge-quarantine`
declared under `tagOwners` and its accept rule(s) scoped to
`autogroup:member` (not `*`). `TailscaleAdapter` never writes the ACL
policy itself - only per-device tags - so this is a one-time setup step
an operator (or, with explicit authorization, an agent acting on the
operator's behalf) performs once per tailnet before the adapter is
useful.

**Rollback is not always fully automatic - a real, verified platform
constraint.** `POST /device/{id}/tags` rejects reducing a device's tag
list to *zero* tags with `HTTP 400 "tagged nodes cannot be untagged
without reauth"`. This was found live, end-to-end, against a real
tailnet device: rollback failed and the device stayed quarantined until
it was manually reauthenticated (not merely reconnected - a stale
session reconnecting does not clear the stuck tag) via the Tailscale
app or the admin console. This is a deliberate Tailscale security
property, not a bug to route around: converting a tagged device back to
an untagged personal device requires the device to prove control again,
the same way a per-device break-glass procedure requires proof of
physical/account control rather than a pure API call. `rollback()`
detects this case up front - when removing the quarantine tag would
leave the tag list empty - and returns a clear, actionable
`AdapterError::Rollback` naming the fix, instead of surfacing the raw
HTTP 400. If the quarantine tag is already absent (for example, an
operator already resolved it by hand), `rollback()` returns `Ok(())`
rather than an error - unlike `NftablesAdapter`'s "rollback of something
never applied fails cleanly" precedent, this is deliberately idempotent
so the TTL sweep can record success and stop retrying once the real
problem has already been fixed out of band.

**Executor wiring.** `tailscale.`-prefixed action names are dispatched
by their own `dispatch_tailscale()` function in `executor/src/main.rs`,
parallel to (not folded into) `dispatch_multi_adapter()`'s
`FirewallAdapter` fan-out, because the target JSON contract
(`{"device_id": "..."}`) and the adapter itself don't fit the
`FirewallTarget`/`FirewallAdapter` shape the other adapters share. The
TTL sweep's `rollback_expired_target()` branches the same way for expired
Tailscale quarantines. `is_firewall_action()` includes the `tailscale.`
prefix, so the DB-backed mass-block budget (see "Mass-block budget"
above) also gates real Tailscale quarantines, not just nftables/HAProxy
applies.

**Headscale.** The ACL *format* (`tagOwners`, `acls`, accept-only) is
conceptually compatible with Headscale, a self-hosted Tailscale
alternative, but this adapter talks to Tailscale's own cloud Admin API
(`https://api.tailscale.com`) with Tailscale's own OAuth flow - a
Headscale deployment uses a different base URL and a different auth
mechanism entirely, and would need its own adapter, not a configuration
option on this one.

## `firewall_action_receipts`: populated, and now readable back

Populated on every `nftables.*`/`haproxy.*` dispatch (preflight, rendered
commands, observed state, verification result, TTL, rollback plan) and
by the TTL sweep's own rollback rows - `clawforge_executor` has `INSERT`
and `SELECT` (the latter only for the mass-block budget's own aggregate
`COUNT(*)`, never a row-by-row read-back) on the table, never `UPDATE` -
append-only, proven by `runtime_roles_enforce_service_boundaries`: the
role can insert via `record_firewall_action_receipt`, but a raw `UPDATE`
on the row it just wrote fails.

**The admin surface the roadmap's own Pflichtgate asks for** ("Desired/
Actual State, TTL, Drift, Kill-Switch und vollstaendige Audit-Lineage
sind vor einem Produktionspilot ueber ein geprueftes Admin-Werkzeug
sichtbar") now exists, read-only, `Administrator`/`Operator`/`Viewer`
role-gated like every other `/executions`-style admin listing:

- `GET /firewall/receipts?adapter=&target_fingerprint=&limit=` -
  `PostgresStore::list_firewall_action_receipts`, every field already
  safe to show (never a raw IP - see "Three target kinds" above).
- `GET /firewall/expired` - `PostgresStore::expired_unrolled_back_
  firewall_targets`, the **exact same query** the TTL sweep itself runs,
  so this view and the sweep's actual behavior can never disagree about
  what still needs rolling back. This is the "Drift" visibility: any
  target that would show up here has not yet been reconciled.
- `GET /firewall/kill-switch?limit=` / `POST /firewall/kill-switch` - see
  the dedicated section below.

## Kill-switch per target (migration `0042`)

Closes the last open half of the roadmap's admin-tool Pflichtgate. Until
now the only way to force a real block off on demand was
`scripts/nftables-clawforge-break-glass.sh` - all-or-nothing for a host
(removes the *entire* exclusive table), not something an operator can
reach for for a single false positive without also dropping every other
active block on that host.

**`clawforge-api` never calls a real adapter itself** (see
`clawforge-firewall-agent`'s own design - only `clawforge-executor` is
allowed to), so a kill-switch triggered through the API is necessarily
asynchronous: it can only record the *intent*, in a new
`firewall_kill_switch_requests` table (`adapter`, `target_fingerprint`,
`target_json`, `reason`, `requested_by`, `created_at`, `processed_at`).
`clawforge-executor`'s `sweep_kill_switch_requests` - called every poll
tick, right alongside the TTL sweep - picks up every row with
`processed_at IS NULL`, performs the actual rollback via the exact same
`rollback_target` helper the TTL sweep uses (refactored out of what was
previously `rollback_expired_target`, now parameterized by
adapter/target_json/context instead of tied to `ExpiredFirewallTarget`
specifically, so the TTL sweep and the kill-switch sweep can never
diverge on *how* a rollback happens, only *why*), and marks the request
processed only once both the real rollback **and** its receipt have been
persisted. If either fails, the request stays pending and is retried
next tick - safe, because `rollback_target` is already proven idempotent
(`rolling_back_an_element_that_was_never_applied_fails_cleanly` /
`TailscaleAdapter::rollback`'s own "tag not present" case): re-processing
an already-completed rollback just re-confirms nothing is left to undo.

Admin surface:

- `POST /firewall/kill-switch` (`{"adapter","target_fingerprint",
  "target_json","reason"}`) - `Administrator`/`Operator` only (a write
  action, unlike the read-only receipt/expired/kill-switch-listing
  endpoints, which stay `Viewer`-accessible too). Returns the request id
  immediately with `status: "pending"` - the caller does not wait for the
  executor's next tick.
- `GET /firewall/kill-switch?limit=` - lists both pending **and**
  already-processed requests (not just pending ones), so an operator can
  confirm a past kill-switch actually completed, not just fire-and-forget
  it.

## Concurrency budget per adapter (migration `0043`)

Distinct from, and complementary to, the mass-block **rate** budget
above: that one bounds how *often* real applies happen over time (DB-
backed, already held across replicas since it existed); this one bounds
how many may be *simultaneously in flight* against the same adapter's
shared resource (the HAProxy Runtime API socket, the local nftables/
netlink interface, the Tailscale Admin API) across every executor
replica sharing this database - several replicas each claiming a
different `execution_request` at nearly the same instant must not be
able to hammer the same shared resource unbounded.

Mechanism: `firewall_inflight_operations` (`adapter`, `execution_id`,
`started_at`) is a reservation table, not a log - a row exists only
while its operation is believed to be in flight.
`try_begin_inflight(store, adapter)` inserts a reservation, then checks
the live count (rows younger than
`CLAWFORGE_FIREWALL_INFLIGHT_STALE_SECONDS`, default 120s) against
`CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER` (default 5); if
that pushes the count over budget, it immediately releases its own
reservation and refuses. The staleness window is what makes this
self-healing: a replica that crashes between reserving and releasing a
slot leaks nothing permanent - the row simply ages out and stops
counting, the same property `execution_leases` already has via its own
expiry.

This is insert-then-check, not a hard lock (e.g. `pg_advisory_lock`) -
like the rate budget, it accepts a small, bounded race (two replicas
reserving at nearly the same instant could both pass the check and
briefly push the live count one over the limit) as the cost of a
*budget*, not a safety invariant the way the never-block exclusion list
is.

Wired in at every real apply/rollback call site: `main()`'s loop
reserves a slot per adapter `adapters_touched_by(action_name)` names
(one adapter for `nftables.`/`haproxy.`/`haproxy_ratelimit.`/
`tailscale.`, every `configured_multi_adapters()` adapter for
`firewall.*`) *before* calling `dispatch()`, and releases them all
afterward regardless of outcome; `sweep_expired_firewall_targets` and
`sweep_kill_switch_requests` do the same around each of their own
`rollback_target` calls. `dispatch()`/`apply_single_adapter`/
`rollback_target` themselves stay completely unchanged (still DB-free,
still directly unit-testable with no store) - `adapters_touched_by` is a
separate, pure function that mirrors their routing logic from the
outside, specifically so the concurrency tracking could be added without
threading a `store` through them.

## What's deliberately not built yet

- **No failure-injection tests** beyond lease loss/worker death (proven
  by `a_worker_that_dies_after_claiming_is_reclaimed_by_a_different_worker`),
  manual drift (proven by
  `verify_detects_manual_drift_after_an_out_of_band_removal`: a real
  out-of-band `nft delete element`, then `verify` correctly reports
  `NotPresent` rather than stale `Verified`), and concurrent actions on
  the same target (proven by
  `concurrent_applies_of_the_same_target_never_corrupt_or_crash` and its
  HAProxy analog: two applies of the same target run genuinely
  concurrently via `tokio::join!` over two independent adapter instances
  against a real lab, neither errors/crashes, and the target ends up
  blocked exactly once). Still missing: process/host/DB failure between
  intent/apply/receipt/audit, reboot, clock skew, failed read-back.
- **Both registered actions stay `enabled=FALSE`** - nothing here changes
  that a reviewed, explicit change is required before any of this can run
  for real, in a lab or otherwise, and `CLAWFORGE_EXECUTOR_DRY_RUN` stays
  hardcoded `true` regardless.
