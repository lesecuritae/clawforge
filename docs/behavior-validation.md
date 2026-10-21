# Bounded behavioral validation

This suite is separate from the 48-hour post-canary idle observer. It never grants
production approval, activates policy, or changes the host firewall.

## Scope and ownership

`tests/fixtures/behavior-validation/scenarios.json` freezes 15 labelled scenarios
before execution, including legitimate NAT failures, missing assets, backend
errors, and malicious bursts crossing a five-minute bucket boundary. Intent
labels and mechanically expected detector rules are separate. A regression test
can pass while the independently reported detection-quality gate fails; do not
rewrite intent labels to make it green. These selected fixtures do not estimate
an Internet-wide false-positive rate.

Real Linux/HAProxy journal parsers export typed envelopes. The database test
validates and ingests them, claims actual canonical deliveries, and evaluates the
production detectors as `clawforge_security_engine`. The bounded load phase keeps
192 events pending, retries 32 identical submissions, rejects eight conflicting
resubmissions, tests actual failed-delivery backoff, and starts/kills/restarts
real engine processes. One abandoned-lease test ages the clock in the ephemeral
database; it is not an eleven-minute wall-clock test. A separate PostgreSQL
trigger fault tests recovery between durable sensor recording and canonical
publish, without interrupting any real database.

Parser vectors began as a small draft from the existing free Hermes route.
Review corrected non-documentation IPs, realistic SSH log syntax, and the
normalized HAProxy `-1` to envelope-status `0` contract. The reviewed vectors are
checked against the real journal parser, not a reimplementation.

## Running

Requirements: Docker, an installed Rust toolchain compatible with the repository,
local cached `postgres:16-alpine`, and enough disk for an isolated Cargo target.
Use explicit `RUSTC`/`RUSTDOC` if the local rustup override is incomplete. Do not
clean or reuse another active worker's build cache.

```sh
CARGO_TARGET_DIR="$HOME/.cache/clawforge-behavior-target" \
  python3 scripts/behavior-validation.py \
  --report-dir "$HOME/.local/state/clawforge-behavior-validation/report" \
  --run-isolated-lab
```

The runner creates only a uniquely named, labelled PostgreSQL container with a
random loopback-only port, 512 MiB RAM and one CPU. It provisions the actual
service-role grants and removes its own labelled container in `finally`.
Passwords are generated for that fixture only and are not included in reports.
`runner.json` records the last stage even on failure. A failed fault test is a
failure, not an ignored optional result.

The real packet suite builds as the ordinary user and requires non-interactive
sudo only for a new private network namespace:

```sh
CARGO_TARGET_DIR="$HOME/.cache/clawforge-behavior-target" \
  python3 scripts/test-behavior-packets.py \
  --report-dir "$HOME/.local/state/clawforge-behavior-validation/packets" \
  --run-isolated-lab
```

Before any provisioning, its Rust test checks that the network namespace differs
from the parent. It exercises the actual `NftablesAdapter`, real IPv4/IPv6 TCP,
eight two-second kernel expiries, legitimate simultaneous traffic, explicit
rollback and loopback never-block protection. These observations do not measure
a production-network SLO, an executor crash, or the native operator kill switch.
All addresses and rules vanish with the private namespace.

## Reading results

- `behavior-report.json`: each frozen label, actual rule set, confusion matrix,
  latency sample counts, input accounting and explicit measurement limits.
- `ingest-recovery-report.json`: actual fault and replay result; one canonical
  event must exist after an acknowledged retry.
- `packet-report.json`: actual packet effects, namespace identity, per-run
  expiry/rollback observations and sample size. With eight TTL observations the
  nearest-rank p95 equals the maximum; this is not a robust population estimate.
- Logs preserve failures. A `finished=true` runner receipt means the test program
  finished, not that the separate detection-quality gate passed.

Not covered: SSH attacks on a live daemon, authenticated HTTP sensor ingress,
full distributed/load capacity, real outage duration, production false-positive
rates, remote management lockout, or broad automatic enforcement. These require
additional, explicitly bounded scenarios and the existing rollout gates.

## Stages, fixes and results (detection-fix revision, 2026-10-21)

The report is split by stage. They answer different questions and must not be merged
into one number:

1. **Raw anomaly detection** (`behavior-report.json`, security-engine): did any rule
   fire for the case? Confusion matrix against the *intent label*.
2. **Independent evidence / attacker finding** (`policy-stage-report.json`): is there at
   least one non-observation decision corroborated by a second **independent** evidence
   source (fresh, confident reputation listing; a different event family; an earlier
   episode)? An anomaly alone is not an attacker finding.
3. **Policy decision**: strongest decision per case (observe/challenge/rate_limit/block).
4. **Enforcement request**: requests created by the policy -> execution bridge with all
   attacker-rule policies promoted to `automatic` and the bridge in `automatic` and in
   `propose` mode (the worst case), never consulting scenario ID, address or label.

Packets, TTL expiry and rollback are the separate packet lab; the bridge stops at the request.

### What changed in the product (rule versions)

* `ssh_bruteforce`, `http_anomaly_burst`, `http_scan` are now **v2**: every rule runs on two
  grids of the same window length and threshold, the second shifted by half a window.
  Any span of at most half a window that contains a threshold's worth of events lies inside
  one window of one grid. A burst split four-and-four across a bucket boundary is detected
  (shifted-grid assessment, one incident candidate); a spread over a *full* window can still
  fall between both grids (documented limit, tested). No threshold was lowered.
* HTTP statuses >= 500 no longer count toward `http_anomaly_burst`/`http_scan`; a 5xx burst
  is the new observation-only rule `http_server_fault_burst` (own policy, recorded as
  `observe`, never a challenge, rate limit or block, never counted as corroboration).
* Corroboration needs a *different* kind of evidence: two rules (or two overlapping buckets
  of one rule) over the same event family are one observation, and an ongoing episode does
  not corroborate itself; earlier-episode history still counts. The decision rationale names
  the basis (`threat_intel`, `independent_event_family`, `prior_episode_history`,
  `behavior_only`).

### Before / after (same labelled cases; intent labels unchanged)

| | TP | FP | TN | FN |
| --- | --- | --- | --- | --- |
| Before, 15 cases, stage 1 | 5 | 3 | 5 | 2 |
| After, the same 15 cases, stage 1 | 7 | 3 | 5 | 0 |
| After, 18 cases (3 added: listed/unlisted twins), stage 1 | 10 | 3 | 5 | 0 |
| After, 18 cases, attacker-rule alerts only (server-fault observation excluded) | 10 | 2 | 6 | 0 |
| After, 18 cases, stage 2 (attacker finding needs independent evidence) | 2 | 0 | 8 | 8 |

`quality_gate_passed` stays **false** (stage-1 FP > 0) and was not renamed. Stage 2 FN = 8
does not mean eight missed detections: those attacks were detected and decided
(challenge/rate_limit), but without independent evidence they are *unconfirmed*, which is
what keeps them from enforcement.

### The three legitimate cases

* `http_legitimate_backend_failure` (503): fixed by a deterministic, observable property -
  a server error status. It is now an observation, not an attacker-rule alert.
* `ssh_legitimate_shared_nat` and `http_broken_asset_release`: their events are
  *observably identical* (`observables.json`, `scripts/behavior-observables.py`) to attack
  cases (`ssh_bruteforce_threshold`, `http_scanner_threshold`, ...) apart from their count.
  No deterministic classifier can separate them from these fields, and none was built from
  the scenario ID, address or pattern name. They remain raw anomaly alerts at stage 1
  (documented, not suppressed), reach at most a simulated challenge, never an attacker
  finding and never an enforcement request. What does discriminate in the fixtures is
  independent evidence: `ssh_sustained_attack_listed_source` and
  `http_scanner_sustained_listed_source` behave like their unlisted twins but carry a fresh,
  confident reputation listing, and only they produce a request (exactly one each:
  `pending` in automatic mode, `waiting_approval` in propose mode). Further observables that
  could help in production (successful logins from the same source, asset-like paths with a
  referrer, cross-client error ratios) are not present in the sensor data today.

### Limits of this evidence

Selected fixtures, not a population false-positive rate. The policy stage shifts the
fixture timestamps forward by a multiple of the window length so that the freshness gates
are real; relative timing and grid alignment are unchanged. The engine, policy and bridge
code are the production code; the executor, packets and kernel are not part of this stage.
