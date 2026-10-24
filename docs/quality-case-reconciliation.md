# Quality case reconciliation (2026-10-24, code 13078fa)

Several counts circulate for the labelled behaviour cases ("3 false alarms / 2 misses", "6 FP / 4 FN"). They are
**different experiments**: a different case set, a different stage, and a different meaning of FN. They are not a
before/after of one number, and neither is a production false-positive or recall rate.

Reproduce: `scripts/behavior-validation.py --report-dir R --run-isolated-lab` (isolated PostgreSQL, about 3 minutes), then
`scripts/behavior-reconcile.py --behavior R/behavior-report.json --policy R/policy-stage-report.json --observables R/observables.json`.
The tool recomputes every matrix from the per-case rows and compares it with the totals the reports state. Tests:
`scripts/test-behavior-reconcile.py`.

## The distinct experiments

| Experiment | Cases | Stage | TP / FP / TN / FN | What FN means |
| --- | --- | --- | --- | --- |
| Frozen baseline, before the detection fix | 15 | 1 raw detection | 5 / 3 / 5 / 2 | **missed detections**: the two bucket-boundary evasions (`ssh_boundary_evasion`, `http_boundary_scan_evasion`) |
| Same 15 after rule version 2 | 15 | 1 | 7 / 3 / 5 / 0 | none missed |
| +3 listed/unlisted twins | 18 | 1 / 2 | 10 / 3 / 5 / 0  and  2 / 0 / 8 / 8 | stage 2: detected, unconfirmed |
| + attack shape (migration 0067) | 21 | 1 / 2 | 11 / 4 / 6 / 0  and  7 / 0 / 10 / 4 | stage 2 |
| + sshd invalid-user verdict (0069), **current** | 24 | 1 / 2 | **12 / 6 / 6 / 0**  and  **8 / 0 / 12 / 4** | stage 2 |

Reproduced on current code (commit 13078fa, source tree sha256 in the run receipt): stage 1 TP 12 / FP 6 / TN 6 / FN 0,
stage 2 TP 8 / FP 0 / TN 12 / FN 4, `quality_gate_passed` false; the recomputed matrices equal the reported ones.
Excluding the observation-only rule, stage 1 FP is 5. No legitimate case produced an enforcement request.

## Which of the historical numbers still exist on current code

* **The 2 misses are gone** (stage 1 FN is 0); both boundary evasions are detected. One of them,
  `ssh_boundary_evasion`, is today among the 4 stage-2 unconfirmed attacks - detected, not missed.
* **The 3 historical false alarms remain**, all three raise a raw alert today: `ssh_legitimate_shared_nat`,
  `http_broken_asset_release`, and `http_legitimate_backend_failure` (now only an observation-only `http_server_fault_burst`
  alert, never above `observe`).
* **3 of the 6 are cases added later**: `ssh_busy_shared_nat_over_an_hour`, `ssh_user_mistypes_own_name`,
  `ssh_user_mistypes_own_name_three_ways`.
* **The 4 stage-2 FN are not misses**: `ssh_bruteforce_threshold`, `ssh_boundary_evasion`,
  `ssh_slow_attacker_below_the_five_minute_threshold`, `http_abusive_burst` were all detected and decided
  (challenge / rate_limit); they stay unconfirmed because no independent evidence exists.

## Why each remaining case is still there

| Case | Kind | Reason |
| --- | --- | --- |
| `ssh_legitimate_shared_nat`, `ssh_busy_shared_nat_over_an_hour`, `http_broken_asset_release` | stage-1 FP | observably identical (same event shapes, account/path classes) to attack cases apart from count - `observables.json` pairs; no deterministic classifier on the sensor fields separates them |
| `http_legitimate_backend_failure` | stage-1 FP | alert of an observation-only rule; excluded from the attacker-rule matrix |
| `ssh_user_mistypes_own_name`, `..._three_ways` | stage-1 FP | the only two without an attack twin among the fixtures. The count threshold fires; the real SSH population contains comparable single-name sources (3 of 340 bursting sources in the 2026-10-23 measurement), so "not proven inseparable here" is not "separable". Changing a threshold or adding a rule against these two would be tuning to fixtures I modelled |
| the 4 unconfirmed attacks | stage-2 FN | each has observably identical legitimate twins; reputation or earlier-episode history confirms them in production |

## Is any attributable code defect left in this set?

No. Every remaining stage-1 false positive is a raw anomaly alert on a case that the fixtures themselves describe as
legitimate but that is field-for-field what an attack looks like at the threshold, and every stage-2 false negative is
the deliberate requirement of independent evidence. What would change the answer is not code: labelled legitimate
bursts from real operation, or a second protected host whose users actually log in (`behavior-validation.md`, real
population section). The gate keeps its definition (any stage-1 FP fails it, so it cannot pass while a legitimate burst
alerts at all) and stays false; it was not renamed, relaxed or re-scoped.

## Related finding from the same pass (source health)

The bridge judges the reputation listing with the same age as the decision and the assessment, while feeds reconfirm only
at their sync. A short age makes a listed source look unlisted for most of each cycle; documented and covered by a
regression and a readiness check in `policy-execution-bridge.md`.
