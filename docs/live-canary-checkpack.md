# Live canary and mirror-hook maintenance check pack

Status: **preparation only.** Nothing here authorizes, schedules or performs a live action. Deployment-specific
values (addresses, hosts, request ids) live in the operator's private notes, not in this repository. Companion pages:
`phase7-pilot-limits.md` (limits), `phase7b-next-observation.md` (the observation that must precede automation),
`live-readiness-audit.md` (state), `firewall-pilot-runtime-20261018.md` (what the first canary actually proved).

## 1. One canary: constraints that must hold before anyone asks for approval

| Constraint | Mechanism | Evidence in the repository |
| --- | --- | --- |
| Exactly one target, a single `/32` or `/128`, at most one active block | operator scope + `CLAWFORGE_FIREWALL_MAX_CONCURRENT_APPLIES_PER_ADAPTER=1` | `executor/src/main.rs` budgets; PostgreSQL concurrency tests |
| Target is not management, VPN, DNS, gateway or the host itself | `CLAWFORGE_FIREWALL_NEVER_BLOCK_CIDRS`, checked in both directions (a broader target that contains a protected address is refused), malformed list refuses everything | `never_block_*` unit tests, `tailnet_ranges_protect_both_families_and_only_those_ranges`, kernel lab `kernel_lab_never_block_list_protects_real_traffic_and_fails_closed` |
| The list was derived from the real host and is confirmed by the operator | private candidate with provenance per entry, validated with the real parser (`candidate_never_block_list_protects_every_listed_address_and_allows_the_canary`, values via environment) | unknowns (public administration source, provider console, relay addresses) stay `PENDING` until the operator answers |
| Block self-expires | `CLAWFORGE_FIREWALL_MAX_TTL_SECONDS` (ceiling, reviewed 900; first canary should use far less) + native nftables element timeout | `ttl_over_live_ceiling` tests; lab series measures native expiry without any rollback call |
| The limits really reach the executor | compose passes the TTL ceiling and the concurrency limit (they were missing until this check pack was written) | `scripts/test-compose-executor-env.py` fails on the old `compose.yml` |
| Threat intelligence for the target is fresh and independent | the bridge function requires counting reputation, stale listings are refused again at dispatch | `docs/policy-execution-bridge.md`, `storage/tests/policy_bridge.rs` |
| Live authorization names the adapter | `CLAWFORGE_EXECUTOR_LIVE_AUTHORIZATION` (actions=`nftables` only); the compose deployment never passes it | `executor/src/live_authorization.rs`; compose test asserts the variable is not wired |

## 2. Independent approvers and context binding

Default profile: two distinct humans, described below. A sole owner can opt in to the single-operator profile (`single-operator-profile.md`): one authenticated, context-bound confirmation by the one designated Administrator, for the four incident-source firewall actions only; the rest of this check pack (never-block list, limits, dry-run, live authorization, rollback) applies unchanged.

A real apply is authorized only when `firewall_request_live_authorized` is true: the action requires approval,
the request has a requester identity and an unexpired approval window, and the number of **distinct** approver
identities (never the requester) whose approval carries the request's exact context hash reaches the larger of the
request's and the risk policy's requirement. `high` and `critical` actions need two. The approval window and context
hash are immutable after creation (migration 0029 trigger). Negative paths proven against PostgreSQL, with mutation
controls that make the test fail when the check is weakened:
`firewall_live_authorization_negative_paths_for_a_two_person_action` (requester approving, the same identity twice,
1 of 2, approvals on another request, elapsed window, tampered context). Agents cannot supply approvals.

## 3. Guard, receipt and kernel readback (what the operator looks at)

1. Preflight, read-only: the `agent_firewall_status` projection (budget used, unresolved generations, kill switch) and
   `nft list set inet clawforge blocklist` on the enforcement host (expected: empty).
2. Apply writes a prepared rule-generation intent before touching the kernel, then the element with a timeout, then
   reads it back; the receipt carries `verification` (`verified` is required) and never the raw address (a pseudonym
   plus a restricted recovery snapshot).
3. Packet effect, measured from a controlled source that is NOT the operator's management path: baseline passes,
   blocked packet dropped, restored packet passes. Record in `measurements.jsonl` (`canary`).
4. Drift while the block is active: the executor reads every completed, unexpired generation back once per poll and writes a `firewall_rule_drift_detected` audit event (and a warning) if its element has vanished or cannot be read; it only observes. An element added out of band that Clawforge does not own is not detected.
5. Expiry: the kernel removes the element at its timeout even with the executor stopped; the rollback receipt follows.
   `verified` rollback plus an empty set is the end state. A rule generation left `recovery_required` is a failed
   canary, not a pass (see the 2026-10-18 history).

Kill switch and break-glass: a native kill-switch target recovers a generation through the executor; the host script
`scripts/nftables-clawforge-break-glass.sh` removes the whole `clawforge` table; the native timeout remains the
upper bound of any block.

## 4. Abort conditions (stop and do not continue)

Any protected address in the target; request or approval context mismatch; stale or contradictory intelligence;
`verification != verified`; an element still present after TTL + 5 s; an unresolved generation; telemetry loss on the
enforcement host; the operator's stop file. After an abort nothing is retried automatically.

## 5. Mirror hook (udev) maintenance check

What is proven: `tests/network-ids/mirror_lab.sh` (copies exactly once, foreign filters survive) and
`tests/network-ids/mirror_restart_lab.sh` (isolated equivalent of a restart in a private network namespace: target
recreated with a new ifindex loses all copies until the hook's `up` runs - control -, source recreated, target absent
at first `up` exits 0 and the next `up` completes, foreign filter survives, `down` removes only ours; `udevadm verify`
accepts the rule). Neither is a real reboot. The restart lab found and fixed one defect: a port without a bridge
master looked like a shared bridge with another such port (refused, i.e. the safe direction).

What stays physical and **unperformed**: the host's udev firing on a real tap re-creation.

Smallest meaningful physical test (preferred): hot-replug of the sensor VM's mirror NIC only. It recreates the target
tap (new ifindex), which is exactly the failure mode the hook exists for, without restarting the guest or touching its
other interfaces; capture pauses for seconds.

```
# 0. before (on the virtualization host): expect our filters (pref 4242) on every source, target present
clawforge-ids-mirror status; for d in <source taps and uplink>; do tc filter show dev $d ingress | grep 'pref 4242'; done
# 1. replug (operator, maintenance window; passive sensor only)
qm set <vmid> --delete net1 ; sleep 5 ; qm set <vmid> --net1 virtio,bridge=<isolated-bridge>,firewall=0
# 2. within ~60 s: journalctl -t clawforge-ids-mirror --since '-2 min'  -> "mirror <source> (ingress) -> <target>" lines
clawforge-ids-mirror status            # every source "mirroring"
sensors/network-ids/host/ids-selftest.sh <eve.json> <status.json>   # markers appear as alerts, adapter alive, drops unchanged
# 3. rollback if the filters are missing after 2 minutes
clawforge-ids-mirror up ; (still missing) -> clawforge-ids-mirror down, then the rollback list in docs/network-ids.md
```

Full guest restart (second step, only if the operator wants it): restarts every service on the guest, so it needs its
own window; the same before/after commands apply, plus the application health checks. Neither test changes routes,
addresses, the management NIC or the firewall; success is judged by the commands above, not by container status.
