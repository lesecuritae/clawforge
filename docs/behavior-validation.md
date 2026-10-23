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

### Attack shape: content-based corroboration (migration 0067)

A plain event count cannot tell users behind a NAT from a dictionary run, or a broken asset
release from a scanner. Two properties of the events themselves can, and the policy engine now
derives them as **counts** (`clawforge_assessment_shape`, numbers only - the engine never sees
usernames or paths):

* `account_enumeration`: the failed SSH logins of an assessment tried >= 8 different account names
  (`CLAWFORGE_ATTACK_SHAPE_MIN_USERNAMES`). Users behind one NAT mistype a few valid accounts.
* `secret_path_probe`: >= 3 distinct requested paths match a secret/config signature (`/.env*`,
  `/.git/...`, `/.aws/...`, `/.docker/...`, `.pypirc`, SSH keys; built-in, extend with
  `CLAWFORGE_ATTACK_SHAPE_PATH_PATTERNS`). `/robots.txt`, `/.well-known/...` and application paths do not match.

Either one is evidence basis `attack_shape` (a second, content-based source). It does not
replace reputation: the policy -> execution bridge still needs a counting threat-intel listing
(`REQUIRE_THREAT_INTEL`, mandatory for `automatic`), routing/ASN/RPKI context stays context, and
`CLAWFORGE_ATTACK_SHAPE=off` disables it. Every decision shows the counts (`attack_shape` in the
evidence snapshot).

Fixtures: every scenario now has an explicit account/path model (`usernames`, `paths`). Before, the
generator used a new invalid account name per SSH failure and synthetic `/fixture-N` paths, which
made every SSH case look like a dictionary run. The models follow the scenario description (legitimate:
a few valid accounts / application paths; password guessing against root: one account; dictionary run:
many names; scanners: secret files), not the outcome, and production shows both shapes (3 days: 112
source-hours with >= 10 distinct usernames; mass `/.env*`, `/.git/config`, `/.aws/credentials` probes).
The improvement below is therefore only as real as that modelling; it is not a general-population estimate.

Result over the original 21 scenarios (stage 1 unchanged at TP 11 / FP 4 / TN 6 / FN 0, gate still false):
attacker finding (stage 2) **TP 7 / FP 0 / TN 10 / FN 4** (was TP 2 / FP 0 / TN 10 / FN 9). The four
remaining false negatives are single-account guessing against root (`ssh_bruteforce_threshold`,
`ssh_boundary_evasion`, `ssh_slow_attacker...`) and a flood of one path (`http_abusive_burst`): from
these fields they are identical to a forgetful user or a retrying client (`observables.json`), so they stay
unconfirmed until independent evidence exists. Missing signals, concretely: a successful login from the
same source (separates a user who finally got in) and per-source success ratios on HTTP; neither is
collected yet. The third signal named earlier, sshd's own verdict `invalid user`, is now carried (below).

### sshd's `invalid user` verdict as shape evidence (migration 0069)

The Linux sensor used to drop the distinction between an account that exists and one that does not.
`SshLoginFailureEvidence.invalid_user` (`Some(true)` = sshd logged "invalid user", `Some(false)` = the
account exists, absent = an older sensor that does not say) is now carried on the wire, and
`clawforge_assessment_shape` returns `distinct_invalid_usernames`. The policy engine adds the shape
`invalid_account_probe`: at least **4** different account names that sshd itself reports as nonexistent
(`CLAWFORGE_ATTACK_SHAPE_MIN_INVALID_USERNAMES`, never below 2). A user mistypes their own name once or
twice; guessing walks through names nobody has. Events from sensors that do not report the verdict never
count. The fixtures now fix which accounts exist on the fixture host (`host_accounts`: root, alice, bob,
carol, dave, erin); sshd reports every other name as invalid, as the real daemon does.

Three scenarios were added (24 in total), modelled from their descriptions and run unchanged through the
isolated harness: `ssh_small_dictionary_probe` (five names, four nonexistent; fewer than the eight of
plain enumeration), `ssh_user_mistypes_own_name` (two nonexistent spellings) and the boundary case
`ssh_user_mistypes_own_name_three_ways` (three nonexistent spellings, one below the threshold).
Result: stage 1 TP 12 / FP 6 / TN 6 / FN 0 (the two legitimate typo cases are raw alerts like the other
legitimate cases, so FP rises by two), attacker finding (stage 2) **TP 8 / FP 0 / TN 12 / FN 4**, quality
gate still false. The small dictionary is corroborated; both typo cases are not. The threshold is a real
trade-off: a legitimate user who tries four different nonexistent spellings within one assessment would
be indistinguishable from a probe, which is why the boundary case is kept. The four remaining false
negatives are unchanged (single valid account `root`, one path flood): sshd's verdict cannot separate
them, only a successful-login signal or an HTTP success ratio could.

### Real-population measurement (2026-10-23): do the missing signals have anything to separate?

The fixtures are modelled; this section measures the real hosts. `scripts/ops/ssh-burst-population.py` and
`scripts/ops/http-burst-population.py` print counts only (no addresses, account names or paths) from the sshd
journal and the HAProxy httplog on the sensor host; run them as root there. Window: the last 7 days on
`srv19680` (HAProxy: the 916 requests the retained log files hold). A frequency below is **not** a
false-positive rate: the host has no labelled legitimate bursts.

* **SSH**: 1,063 sources with failures, **none** of them ever had an accepted login (2 other sources only ever
  logged in). 340 sources had a burst (>= 5 failures in 300 s): 231 (68 %) enumeration (>= 8 names), **25 (7 %)
  are newly corroborated by `invalid_account_probe`** (>= 4 nonexistent names, < 8 total), 56 (16 %) tried one
  existing account (median 16 attempts, up to 913), 25 mixed below both thresholds, 3 one nonexistent account.
* **HTTP**: 270 sources, 11 with >= 8 error responses in 300 s; 2 had no success at all, 9 some but < 50 %, **0**
  were mostly successes.
* **Consequence for "a successful login from the same source" and "HTTP success ratio"**: in the real
  populations no burst source has a login success and no error burst is mostly successful, so neither signal
  would ever fire here and neither can be validated or its threshold chosen from real data. The only legitimate
  bursts that exist are the fixture scenarios, and adding a success signal to them would be tuning the matrix to
  the fixtures. Neither signal was implemented. The success-login signal also cannot exonerate a source: a
  guessed password produces the same "failures then success", so it could only ever be a separate compromise
  indicator, not a way to demote a burst.
* **The four missed attacks** (single valid account `root`, one-path flood) are the 56-source class above in
  real life: automated by volume (median 16, up to 913 attempts) but identical, field for field, to a forgetful
  user at the threshold. Volume is what the count rule already uses, so it cannot also be its independent
  corroboration (`a_long_sustained_attack_does_not_corroborate_itself`); reputation or prior-episode history is
  what confirms them today (SSH shadow decisions of the last 7 days with a basis: `threat_intel_ip` 270,
  `behavior_only` 272, `prior_episode_history` 103, `threat_intel_snapshot` 41, `attack_shape` 15).
* **What would make the question answerable**: labelled legitimate bursts from real operation (an operator
  confirming a source as legitimate), or a second protected host whose users actually log in. Until then the
  quality gate stays false and the stage-1 false positives are an unmeasured risk on production, not a measured
  zero.
* **Next real observation**: the invalid-account shape and the 24 h shape window start with the 1.2.5 sensor at
  2026-10-23T12:48Z; the earliest meaningful evaluation is 2026-10-24T12:50Z with
  `scripts/ops/shape-evidence-report.sql`. No earlier statement about its effect is made.

### Pipeline completeness on real data and the undecided-backlog fix (2026-10-23)

Real data (production, read-only `scripts/ops/pipeline-completeness-audit.sql`, which recomputes the expected
windows from the events table itself): all 464 SSH `ssh_bruteforce` windows of the last 24 h have an assessment
with the same count (cap 1000); all HTTP burst/scan windows since the staggered grids (22 Oct) have theirs (4/4 and
4/4; earlier "missing" windows were exactly the shifted-grid windows that rule version 1 did not have); no
corroborated decision has fewer than two evidence sources and no block is uncorroborated. The one real gap: 167
assessments without any decision, left by the 1.2.3 incident, because the policy engine only evaluated the 200
newest assessments per poll. Before that incident none of ~2,800 assessments (15-21 Oct) was undecided, and the
real peak was 13 new assessments per minute against a window of 200 per 15 s, so starvation has not been seen in
normal operation; a distributed burst of more than 200 assessments per poll would produce it.

The fix catches up undecided assessments of the last 24 h, bounded per cycle. Regression tests run against
PostgreSQL with the real least-privilege roles: old assessments pushed out of the newest-N window are decided
(precondition asserted: they are not in the listing), a shared-NAT burst stays `behavior_only` and is never a
block, an account enumeration is corroborated by `attack_shape`, decisions stay shadow-only, no execution request
appears, re-running creates no duplicates, work per cycle is bounded by limit + backlog, and history older than
24 h is not touched. With the catch-up disabled both tests fail (negative control). The behaviour harness is
unchanged by the fix: stage 1 TP 12 / FP 6 / TN 6 / FN 0, attacker finding TP 8 / FP 0 / TN 12 / FN 4, quality gate
false.

Isolated lab measurement (synthetic, **not** production evidence and not a throughput claim): a 400-assessment
backlog drained in 5 cycles at 50 newest + 100 catch-up; the slowest cycle (150 evaluations) took about 3 s, so
roughly 20 ms per evaluation on the lab machine. The default catch-up of 100 keeps a worst-case cycle well inside
the 15 s poll.

### What changed in the product (rule versions)

* `ssh_bruteforce`, `http_anomaly_burst`, `http_scan` are now **v2**: every rule runs on two
  grids of the same window length and threshold, the second shifted by half a window.
  Any span of at most half a window that contains a threshold's worth of events lies inside
  one window of one grid. A burst split four-and-four across a bucket boundary is detected
  (shifted-grid assessment, one incident candidate); a spread over a *full* window can still
  fall between both grids (documented limit, tested). No threshold was lowered.
* **`ssh_bruteforce_slow` v1** (new): at least 15 failed logins from one source within an hour
  (same two-grid scheme, window 3600 s). The five-minute rule cannot see a source that tries about
  once a minute; production data from three days showed 71 source-hours with >= 15 failures and no
  five-minute window at threshold (7 with >= 30). It belongs to the same event family as
  `ssh_bruteforce`, so it never corroborates it, and a firing reads/records at most 61 events
  (severity saturates at 4 x threshold), so a very busy source does not make the long window
  expensive. It also yields: while a five-minute `ssh_bruteforce` assessment overlaps its window the
  hourly rule stays quiet (one finding per activity). Its policy (migration 0066) is `observe` like the others. Honest limits: one failure
  every five minutes (12 an hour) stays invisible, and many users behind one NAT at about 20
  failures an hour trip it (`ssh_busy_shared_nat_over_an_hour`, a measured false positive that the
  independent-evidence requirement keeps from becoming an attacker finding).
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
