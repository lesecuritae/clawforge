# Single-operator approval profile (explicit opt-in)

The default is unchanged: high and critical actions need **two distinct humans**, neither of them the requester
(`approval_policies`, migration 0029). This page describes the deliberate alternative for a deployment that has exactly one
human operator. It is never on by default, never a request field and never available to agents or tools.

## What it is

* A one-row table `approval_profile` (migration 0071). Only the database **owner** role can change it
  (`scripts/ops/set-approval-profile.sql`); every runtime role has no privilege on the table and reads it through
  `clawforge_approval_profile()`, which returns the multi-person default when the row is missing, when the operator account
  is disabled or is no longer an `Administrator`. Every change is audited (`approval_profile_changed`).
* It names ONE `Administrator` account and an allow list that a CHECK restricts to the four
  `*.block_incident_source` firewall actions. Quarantine and every other action can never be listed, and the existing rule
  that quarantine needs two distinct approvers is untouched.
* For a listed action a request is created with `required_approvals = 1` instead of the policy's 2. The policy's own count
  and the operator are written into the **hashed** approval context (`approval_profile`), so the lowering is visible to the
  approver and cannot change afterwards (the context is immutable).
* The operator confirms through a **separate** operation, `POST /admin/executions/{id}/confirm-single-operator`
  `{"context_hash": "<hash of the request they read>"}`, which needs an authenticated Administrator session (agents and tools
  use agent tokens and never reach admin routes). The approval row carries `approval_mode = single_operator_confirmation`.
  One person may open the request and later confirm it; that is the only case in which requester and approver may be the
  same account, and the record says so.

## What the database refuses (tested in `storage/tests/single_operator_profile.rs`)

| Case | Result |
| --- | --- |
| profile off (default) | two distinct approvals, requester cannot approve, single confirmation unavailable |
| profile row inconsistent (single_operator without operator/actions, unknown mode, quarantine or arbitrary action listed, second row) | rejected by CHECK |
| request carries the profile marker, another administrator approves the ordinary way | refused: only the operator confirmation counts |
| confirmation by an administrator who is not the designated operator; wrong context hash; expired window; cancelled request; replay | refused |
| action outside the allow list | keeps the policy's two approvals; confirmation refused |
| direct INSERT with fewer approvals without the marker, with a marker naming someone else, with a different mode, or while the profile is off | refused by the trigger |
| single-confirmation approval row while the profile is off | refused |
| profile switched off after a confirmation | the live-apply authorization is withdrawn immediately (checked at claim time against the CURRENT profile) |
| operator account disabled / profile row deleted | reads as multi-person |
| runtime (API) role | cannot read or write the table; may only call the function |

## What does not change

Dry-run executor, explicit live authorization, never-block list, TTL/rate/concurrency limits, kill switch, rollback and
recovery, the approval windows, stale and changed-context refusal. The profile lowers neither a risk level nor any other
policy, and it opens no gate by itself (the bridge stays off, actions stay disabled until the operator changes them).

## Bridge proposals (migration 0072)

In `propose` mode the policy -> execution bridge builds its request context in `clawforge_policy_bridge_plan`. In the
profile that plan gives a proposal for a listed action `required_approvals = 1` plus the same marker; evidence, current
reputation (intel), routing context, budgets, duplicate and target-active checks, the requester rules and the hashed
context are judged exactly as before. Tested with genuine proposals (`storage/tests/policy_bridge.rs`,
`a_bridge_proposal_is_confirmable_by_the_single_operator_without_a_second_person`): by default a proposal keeps two
approvals and no single confirmation exists; in the profile a proposal without current reputation is still refused
(`threat_intel_required`), an eligible one is confirmable by the designated operator only (not by another administrator,
not by the bridge's own requester account, not with a wrong hash, not twice), and after switching the profile off new
proposals are back to two approvals. `automatic` mode is untouched (it creates `pending` requests without approvals and is
refused unless the operator flips the action row deliberately).

## Native UI

Controlled Operations shows "Requests awaiting approval". Selecting a request shows the trusted profile (read from the
database through the API, never chosen by the browser), the exact target, the context hash and the expiry. The "Confirm
request" button exists only when the API reports the signed-in person as the designated operator of an eligible, unexpired
request, and only after an explicit "I reviewed this exact request" tick; it posts the displayed hash to
`/admin/executions/{id}/confirm-single-operator`. There is no fallback to the ordinary approval route: a refusal is shown as
a refusal. The route needs an interactive login session of an Administrator; long-lived API tokens (scripts, agents) get
403, unknown bearers 401. Tests: `frontend/src/ExecutionConfirmations.test.tsx` (6) and the router-level
`single_operator_confirmation_route_accepts_only_the_designated_operators_session` in the API crate (API token, other
administrator, wrong hash, ordinary approve route, double submit, profile switched off).

## Using it

```
psql -v ON_ERROR_STOP=1 -v mode=single_operator -v operator=<admin-username> \
     -v actions=nftables.block_incident_source -v note='sole owner' -f scripts/ops/set-approval-profile.sql
psql -v ON_ERROR_STOP=1 -v mode=multi_person -f scripts/ops/set-approval-profile.sql     # back to the default
```

`operator` and `actions` are needed only when enabling the profile; `note` is optional. The script enforces
`ON_ERROR_STOP` itself, so invalid configuration returns a failing exit status even if the caller omits that flag.
`python3 -I scripts/test-approval-profile-script.py` tests these commands against the actual migrations in a disposable,
network-isolated PostgreSQL container (requires the cached `postgres:16-alpine` image).

`scripts/live-readiness-check.py` reports the profile (`approval_profile`) and, when it is single-operator, words the human
step as one explicit, context-bound confirmation by the designated operator. Detection quality, a real Phase 7B window,
operator-labelled legitimate traffic and the live authorization stay separate acceptance items. The abuse.ch feeds are
optional; no release, IDS or live gate depends on their keys.

The separate Phase 7B observer supports a hash-pinned owner export of this
profile through `plan --approval-profile-file`. It counts a single confirmation
only with matching native request/approver/mode/context evidence; see
`phase7b-next-observation.md`. Old plans keep two-person accounting. This does not
replace the operator confirmation or the measured live observation.
