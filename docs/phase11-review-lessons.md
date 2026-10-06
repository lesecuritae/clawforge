# Phase 11 review lessons (2026-10-06)

Project/repository: Clawforge. Components: storage, executor, firewall-agent.
Source: Codex review of Claude Phase-11 branch, followed by actual PostgreSQL,
Docker and HTTPS fixture tests. Status: active for the reviewed development
architecture; production live quarantine remains disabled. Recheck after changes
to SQLx migration discovery, approval policy, adapter APIs or role provisioning.
This versioned handoff is an import source for the existing Learning layer;
it is not a claim that a production Lesson API import has already happened.

| Failure and cause | Correct approach | Regression evidence / recognition |
|---|---|---|
| Malformed protection metadata silently became an empty list. | Keep parse errors and refuse execution before IO. Require actual management protections on live adapters. | Negative protection tests must exercise malformed entries, not only known protected targets. |
| Broad `proxmox.*` routing could treat reboot/snapshot as isolation. | Dispatch only exact reviewed action names; validate public enum constructors at execution boundaries. | Unrelated action routing and malicious node/ID tests. |
| Network-name-only rollback lost configured addresses and aliases. | Persist bounded immutable network IDs and supported restoration settings; authoritative readback and partial-apply compensation. | Real two-network Docker lab with static addresses, aliases and repeated restore. Describe preserved operator additions honestly. |
| Verify mismatch could still return success. | Success requires verified observed state; failure retains recovery ownership. | Adapter and executor negative verification tests, HTTP-200-with-unchanged-state fixture. |
| API config POST was treated as synchronous. | Proxmox returns a qmconfig UPID: validate node/VM ownership, wait for stopped/OK, bound polling, verify NIC state; unknown completion is manual recovery. | Delayed task, failed task, timeout and malformed UPID fixtures. |
| Receipt-after-IO allowed a crash to lose the restore snapshot. | Commit a native intent first, hold generation guard through IO, atomically finish receipt and status. Never blindly replay prepared state. | Controller observer proves snapshot exists before real disconnection; actual receipt CHECK failure leaves prepared ownership. |
| Target/timestamp rollback matching could undo a newer quarantine. | Each apply owns an immutable generation; TTL and kill switch restore only that generation. Refuse historical unbound native records. | Stale kill request while a second generation is isolated leaves second generation unchanged. |
| Generic expired leases retried externally uncertain mutations. | Native active generations block claim, lease reclaim, timeout and retry; normal non-quarantine recovery remains. | Nine actual PostgreSQL state combinations plus ordinary recovery. |
| Startup role tests missed journal row-lock privileges. | Use a narrow lock-only definer function and actual restricted executor prepare/revalidation tests; never grant policy mutation to fix a lock failure. | API cannot erase ownership, executor cannot update actions, restricted role can prepare/guard the intent. |
| Known production migration46 differed from main. | Select only exact reviewed historical SQL; additive convergence, no checksum/ledger edits, reject unknown history. | Both real SQLx histories preserve ledger, existing actions, flags and context-bound approvals. |
| Old manual cases exhausted the automatic recovery batch. | Separate automatic due work from retained manual-review cases. | Automatic query excludes recovery_required; do not repeatedly retry unknown async effects. |

## Supervisor review rule

A compilation pass is not controller acceptance. Run the real disposable
controller and restricted-role tests before saying Phase 11 is complete. A fixture
failure must be diagnosed: the initial controller used an invalid admin role and
was rejected by the real schema; fixing the fixture to the supported Administrator/
Approver roles preserves the constraint. Updated Proxmox drift checks add exactly
two reads/logins; keep strict protocol counts and adjust only for those new calls.

Before production activation, still require a reachable disposable Proxmox VM,
trusted management/restore proof, explicit rollout review, and effective Tailscale
ACL/reversible identity proof. See [acceptance](phase11-acceptance.md).
