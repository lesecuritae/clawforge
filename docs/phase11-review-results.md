# Phase 11 reviewed development state — 2026-10-06

Base: main `d1ac60e`, Claude feature head `86f6f95`. This follow-up fixes the
reviewed adapter, migration, approval and crash-recovery defects. It does not
activate production quarantine or certify the outstanding real-Proxmox exit gate.

## Final executed checks

| Check | Result |
|---|---|
| `cargo test --workspace` | 289 passed, 0 failed; 76 environment-dependent tests ignored here |
| `scripts/test-postgres.sh` | 45 passed, 0 failed, including required ignored PostgreSQL/controller checks |
| Secure Proxmox HTTPS fixture | 1 passed; trusted TLS, CAS, task ownership/completion, snapshot drift and rollback readback |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| `cargo fmt --all -- --check` / `git diff --check` | Passed |
| Read-only security re-review | Six identified defects fixed; no new concrete blocker found |
| Disposable real Proxmox VM | Blocked: SSH timeout / API no route to 192.168.0.8; no credential POST or mutation |

The controller test exercises actual Docker isolation on two disposable networks
with configured addresses and aliases. It observes the committed prepared journal
before mutation, waits for the real 60-second TTL, invokes the normal sweep,
verifies restoration, checks stale generation/kill requests against a later apply,
and injects a real receipt INSERT failure after isolation. Uncertain recovery
retains ownership and refuses automatic replay/reconnect. Explicit lab
reconciliation restores the snapshot under the generation guard.

The PostgreSQL suite includes both historical migration lineages through 0054,
actual approval expiry, current distinct approvers/policy checks, restricted
executor preparation/revalidation, API write/deletion denial, atomic receipt
failure, immutable snapshot/transition tests, and nine lease/retry/claim states.

Earlier failed fixture runs remain part of private diagnostic evidence: the
controller's unsupported test role was corrected to real schema-supported roles;
additional Proxmox drift checks required exactly two additional reads/logins.
No production constraint was relaxed and no required test was removed.

## Scope and rollback

All runtime changes remain in development. Migration and role changes were
applied only to disposable databases. Production services, database history and
network state were not changed. The live gate is hard closed. Temporary lab
containers/networks/databases are removed after the checks.

A production rollout still needs the gates in [acceptance](phase11-acceptance.md),
including a current real-Proxmox lab and management/restore evidence. Before
migration, preserve a verified database backup and matching application/role
configuration; rollback must reconcile outstanding remote operations and restore
that matching pair, without rewriting migration checksums. This tested commit is
a development review basis, not a production known-good activation.

Learning handoff: [review lessons](phase11-review-lessons.md).
