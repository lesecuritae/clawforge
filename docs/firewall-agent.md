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
apply once `CLAWFORGE_FIREWALL_MAX_APPLIES_PER_WINDOW` (default 20) real
applies have already been recorded within the trailing
`CLAWFORGE_FIREWALL_RATE_WINDOW_SECONDS` (default 300) - a runaway policy
engine or a config mistake must not be able to block hundreds of
addresses in a burst. The count comes from `firewall_action_receipts`
itself (`PostgresStore::recent_real_firewall_apply_count`), not an
in-memory counter, so the budget holds across a process restart and
across multiple executor replicas sharing the same database. A refused
dispatch never calls `dispatch()`/the adapter at all - the
`execution_request` is completed as failed with a clear
`"mass-block budget exceeded"` `error_summary`, and no `nft` command is
built or run. If the budget check itself fails (a database error), the
same request also fails closed rather than proceeding unchecked. Dry
runs and non-`nftables.`-prefixed actions are never gated - there is
nothing to bound. Concurrency (more than one real apply in flight at
once) is not a separate counter: the executor's poll loop claims and
dispatches one request per tick, sequentially, so within a single
process it is already 1 by construction; bounding it across multiple
replicas targeting the *same* host remains open (see "What's
deliberately not built yet" below).

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
(HAProxy stick-tables - a counter/threshold, not a membership set) is
materially different and **not** built here.

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

## Tailscale adapter (prepared, not operable)

The roadmap is explicit that Tailscale should be prepared "zunächst nur
als freigabepflichtigen Adapter" - deliberately narrower than
`NftablesAdapter`'s own first increment, which at least had
`preflight`/`render` from the start. `TailscaleAdapter` has **no**
`preflight`, `apply`, `verify`, or `rollback` method at all - not "an
`apply` that always returns an error", but an `apply` that is not a
method to call in the first place, so there is no code path anywhere in
this crate that could reach the real Tailscale Admin API. Its only
capability is `render(&TailscaleAction) -> TailscaleActionReceipt`: pure,
synchronous, describes what a real call *would* be (`POST
/api/v2/device/{id}/disable` to quarantine a device suspected of
compromise) without ever making it. There is no HTTP client, no API
token, and no secret wired to this type at all. `TailscaleTarget`
identifies a device by its Tailscale device ID - never an IP address, a
genuinely different resource shape from `FirewallTarget`, which is why
it is its own separate type rather than a fourth `FirewallTarget`
variant. Migration `0037` registers a `tailscale` connector and the
`tailscale.quarantine_device` action, `requires_approval=TRUE,
enabled=FALSE`, same as every nftables action - this is preparation for
review, not a working integration, and building the real Admin API call
(auth, HTTP client, error handling, its own tests) is separate,
not-yet-started follow-up work.

## `firewall_action_receipts` is populated, nothing reads it back yet

Populated on every `nftables.*` dispatch (preflight, rendered commands,
observed state, verification result, TTL, rollback plan) -
`clawforge_executor` has `INSERT` and `SELECT` (the latter only for the
mass-block budget's own aggregate `COUNT(*)`, never a row-by-row
read-back) on the table, never `UPDATE` - append-only, proven by
`runtime_roles_enforce_service_boundaries`: the role can insert via
`record_firewall_action_receipt`, but a raw `UPDATE` on the row it just
wrote fails. No admin surface for desired/actual state, drift, or
rollback history exists yet (see the roadmap's own remaining Pflichtgate
on this).

## What's deliberately not built yet

- **No HAProxy rate-limiting (stick-tables)** - only the "Maps/ACLs" half
  of the HAProxy adapter is built (see above); rate-limiting is a
  materially different mechanism (a counter/threshold, not a membership
  set).
- **No real Tailscale integration** - `TailscaleAdapter` is prepared
  (see above) but has no `apply` capability at all, on purpose.
- **No failure-injection tests** beyond lease loss/worker death (proven
  by `a_worker_that_dies_after_claiming_is_reclaimed_by_a_different_worker`)
  and manual drift (proven by
  `verify_detects_manual_drift_after_an_out_of_band_removal`: a real
  out-of-band `nft delete element`, then `verify` correctly reports
  `NotPresent` rather than stale `Verified`). Still missing: process/
  host/DB failure between intent/apply/receipt/audit, reboot, clock skew,
  concurrent actions on the same target, failed read-back.
- **No TTL-driven auto-rollback.** `ttl_seconds` is recorded on every
  receipt (`expires_at`), but nothing periodically reads it back and
  calls `rollback` once it passes - a real (non-dry-run) block currently
  stays in effect until something else removes it (a later explicit
  rollback, or break-glass). This is a real, open gap, not yet built.
- **No concurrency budget across multiple executor replicas targeting the
  same host** - the mass-block *rate* budget (above) is DB-backed and
  already holds across replicas; a *concurrency* ceiling (at most N real
  applies in flight at once, cluster-wide) is a separate, still-open
  refinement.
- **Both registered actions stay `enabled=FALSE`** - nothing here changes
  that a reviewed, explicit change is required before any of this can run
  for real, in a lab or otherwise, and `CLAWFORGE_EXECUTOR_DRY_RUN` stays
  hardcoded `true` regardless.
