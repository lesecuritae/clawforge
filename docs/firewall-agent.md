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
start applying for real. Nothing in this increment flips that value
against any real host - that stays a separate, explicitly reviewed step.

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
  returns `Err` if given this variant - a raw IP can never reach a
  persisted receipt through `render`, a hard guardrail enforced in the
  type, not a rule callers have to remember to follow.

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

`scripts/test-firewall-lab.sh` runs the 8 `#[ignore]`-gated real-`nft`
tests (round-trip apply/verify/rollback for IPv4 and IPv6, dry-run
never touching the real set, idempotent double-apply, resolved-source
apply, unresolved-source fails closed, rollback-of-never-applied fails
cleanly, IPv4-mapped-IPv6 normalization) inside a disposable
`rust:1.98-bookworm` container (`--cap-add=NET_ADMIN --cap-add=NET_RAW`),
never against srv19680 or any other real host - the container's network
namespace is created fresh by the runtime and destroyed with it. This is
the "isoliertes Netzwerk-Lab" the roadmap's phase 6 gate asks for, in the
form the tools available in this environment can actually provide. What
it does **not** provide: self-lockout confirmation against a
*provisioned* host's real management path (SSH, HAProxy admin, etc.) -
this container has no equivalent of that at all. That confirmation is
still an open item before ever applying for real against a live host.

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

## What's deliberately not built yet

- **No HAProxy adapter, no Tailscale adapter** (roadmap: Tailscale
  "zunächst nur als freigabepflichtigen Adapter vorbereiten").
- **No break-glass procedure documentation or drill.**
- **No failure-injection tests** (process/host/DB failure between
  intent/apply/receipt/audit, lease loss, reboot, clock skew, concurrent
  actions, expired TTL, manual drift, failed read-back).
- **No HA/leader/lease-race tests** proving no double-application under
  concurrent workers.
- **No rate/concurrency/mass-block budgets.**
- **`firewall_action_receipts` is now populated** on every `nftables.*`
  dispatch (preflight, rendered commands, observed state, verification
  result, TTL, rollback plan) - `clawforge_executor` has `INSERT` only on
  the table (append-only, proven by
  `runtime_roles_enforce_service_boundaries`: the role can insert via
  `record_firewall_action_receipt`, but a raw `UPDATE` on the row it just
  wrote fails). Nothing reads the table back yet - no admin surface for
  desired/actual state, drift, or rollback history exists (see the
  roadmap's own remaining Pflichtgate on this).
- **Both registered actions stay `enabled=FALSE`** - nothing here changes
  that a reviewed, explicit change is required before any of this can run
  for real, in a lab or otherwise, and `CLAWFORGE_EXECUTOR_DRY_RUN` stays
  hardcoded `true` regardless.
