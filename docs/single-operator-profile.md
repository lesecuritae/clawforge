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
recovery, the 15-minute approval windows, stale and changed-context refusal, and the policy -> execution bridge (whose
`propose` requests keep the policy's count: the bridge is off, and extending it is a separate decision).
The profile lowers neither a risk level nor any other policy, and it opens no gate by itself.

## Using it

```
psql -v ON_ERROR_STOP=1 -v mode=single_operator -v operator=<admin-username> \
     -v actions=nftables.block_incident_source -v note='sole owner' -f scripts/ops/set-approval-profile.sql
psql -v ON_ERROR_STOP=1 -v mode=multi_person -f scripts/ops/set-approval-profile.sql     # back to the default
```

`scripts/live-readiness-check.py` reports the profile (`approval_profile`) and, when it is single-operator, words the human
step as one explicit, context-bound confirmation by the designated operator. Detection quality, a real Phase 7B window,
operator-labelled legitimate traffic and the live authorization stay separate acceptance items. The abuse.ch feeds are
optional; no release, IDS or live gate depends on their keys.
