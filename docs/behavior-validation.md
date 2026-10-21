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
