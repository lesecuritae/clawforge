# Phase 11 acceptance: quarantine

## Current status (2026-10-06)

Development hardening continues on Forgejo PR #2. **Production quarantine is
closed. This document does not authorize rollout or mark the full exit gate met.**
Claude's earlier disposable Proxmox/Docker trials cover the earlier adapter;
they do not establish acceptance of the changed TLS/task/recovery controller.

## Implemented safety boundaries

- Exact action dispatch: `docker.quarantine_container`, `proxmox.quarantine_vm`,
  `tailscale.quarantine_device`. Unrelated actions cannot reach quarantine.
- Canonical immutable Docker identity and validated Proxmox node/VM identity.
  Invalid protection lists refuse execution; real adapters require a nonempty
  management protection list. Owner, restore reference and management plan are
  required metadata, not proof that backups or management connectivity work.
- Docker uses bounded network-only inspection and explicit argv. Durable restore
  snapshots include network IDs, aliases, configured static addresses, links,
  driver options and gateway priority. Failed partial isolation attempts restore
  original attachments. Readback requires original attachment settings; additional
  operator attachments/aliases are preserved, so this is not a claim that every
  aspect of Docker state equals an earlier snapshot.
- Proxmox verifies TLS by default (`CLAWFORGE_PROXMOX_CA_FILE` for trusted private
  CA), validates host authorities, rejects multiple NICs, uses digest CAS, waits
  for the correct `qmconfig` task to finish successfully, and verifies readback.
  Rollback restores the exact original `net0`, including an explicit `link_down=0`.
  Operator drift, failed/missing task IDs and uncertain completion are failures.
- Both adapters compare current metadata with the durable prepared snapshot
  before applying. Verification failure cannot be reported as success.
- Creation, both claim paths and native preparation enforce current critical
  policy, at least two distinct context-bound approvers excluding the requester,
  and unexpired approval. Revalidation under the generation guard precedes IO.
- Executor startup still requires dry-run. A separate hard-coded live quarantine
  gate stays closed; an environment variable cannot open it.

## Native durability and generations

Migration 0054 extends the existing `firewall_action_intents`; there is no second
journal. Before mutation, native preparation commits the approved target,
canonical fingerprint, read-only preflight, rollback snapshot, TTL and deadline.
The approved target is unchanged and must contain `kind` matching the adapter.
An active generation owns `(adapter, fingerprint)` until verified resolution.

A transaction guard locks that exact generation across mutation/readback and
atomic receipt completion. Snapshots are immutable and resolved generations
cannot revive. Native leases, retries and both claim paths cannot replay an owned
operation. A failed receipt transaction leaves durable prepared ownership.

Completed expired generations restore their stored snapshot under the same
fence and atomically write a generation-linked rollback receipt. Kill switches
capture the active generation when requested; old requests cannot restore a later
generation. Historical native receipts/kill requests lacking ownership require
manual reconciliation. Legacy non-quarantine firewall rollback remains separate.

Prepared or uncertain async completion becomes `recovery_required`, retaining
ownership. No automatic replay or blind reconnect is permitted: a delayed remote
operation may still arrive. Manual cases do not occupy the automatic sweep batch.
An operator must establish remote task completion and authoritative state before
an explicitly reviewed recovery; there is currently no generic manual resolver UI.

Runtime executor roles cannot mutate approval policy. A narrowly scoped locking-only
SECURITY DEFINER function locks quarantine approval rows for revalidation; it
writes nothing, has a fixed search path, and public execution is revoked.
API roles can read generations but cannot write/delete them or alter receipts.

## Migration lineage and rollback

- Main's original 0046 stays unchanged. The exact known production 0046 source is
  archived under `migration-history/`, outside automatic migration discovery.
- The native SQLx migration source selects only that exact reviewed historical
  source when its checksum matches. It never rewrites `_sqlx_migrations` or accepts
  arbitrary mismatches; readiness validates the entire applied history.
- Shared 0047 is byte-identical to production's native intents migration.
- Additive 0052 converges GoAway capabilities while preserving existing actions,
  user flags, requests and approvals. 0053 supplies disabled critical quarantine
  actions and two-person policy. 0054 supplies native generation ownership.
- Both historical paths are tested on disposable PostgreSQL databases, including
  preserved ledger checksums and existing approvals. The old stash reconciliation
  is not used.

Use `clawforge-migrate` from the reviewed build, not a raw SQLx CLI migration of
this divergent historical installation. Before a production migration, retain a
verified database backup, the matching application image/commit and role config.
Restore that backup with its matching application if rollback is needed; do not
edit checksums or drop active journals. A rollback while remote mutations are
outstanding needs explicit reconciliation first. No production migration has
been performed during this review.

## Evidence and remaining gates

- Docker adapter lab: two disposable networks, static IPs and aliases, restoration
  and repeated rollback verified. Resources removed.
- Secure Proxmox HTTPS fixture covers trusted/untrusted CA, hostname mismatch,
  CAS conflict, NIC drift, delayed async completion and task failures/timeouts.
  Runner: `python3 firewall-agent/tests/proxmox_https_fixture.py --evidence <private-file>`.
- Required PostgreSQL checks run through `scripts/test-postgres.sh`: both migration
  histories, dual approvals, restricted roles, immutable native journals, actual
  expiry and generic lease recovery. Executor controller lab has a separate ignored
  test using an explicit disposable database and its own Docker resources.
- Concrete counts and reviewed commit are recorded in the review handoff after the
  final test run; an unknown or failing required test is not complete.

Open gates: current secure adapter/controller test against a disposable real
Proxmox VM (192.168.0.8 is unreachable from this host), trusted management and
restore proof for a production pilot, reviewed manual reconciliation UX, and
Tailscale reversible identity/tag plus actual ACL-isolation proof. A quarantine
tag alone is not evidence of isolation under additive ACLs. Tailscale live native
controller refuses execution pending those guarantees.

Proxmox protocol references:
[config update implementation](https://github.com/proxmox/qemu-server/blob/master/src/PVE/API2/Qemu.pm)
and [task status implementation](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Tasks.pm).

Review findings and reusable rules: [Phase-11 lessons](phase11-review-lessons.md).
