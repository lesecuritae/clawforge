# Q1: quarantine generations operator view

Phase 11 Q1 (see `CLAWFORGE_ROADMAP_CONTINUATION.md`). A read-only operator
view of durable quarantine generations. This is an independent, parallel-safe
package: it adds a new view and touches no executor, adapter, migration or
quarantine write path, and it opens no live gate.

## What a generation is

A generation is a `firewall_action_intents` row that owns an external
Docker/Proxmox/Tailscale target (`target_fingerprint IS NOT NULL`), introduced
by migration 0054. Ownership of the `(adapter, target_fingerprint)` pair and the
legal status transitions are enforced in the database (unique active index and
the `protect_quarantine_intent_snapshot` trigger); this view only *reads* them.

## Storage: `PostgresStore::list_quarantine_generations(page, page_size)`

`storage/src/quarantine_intents.rs`. SQL-level pagination with a stable
`created_at DESC, id DESC` sort and an accurate `total`, so pages beyond the
first are never silently empty. Each row carries the durable status, the apply
and rollback receipt lineage (`firewall_action_receipts` joined on
`intent_id`/`receipt_kind`, which the unique index keeps to at most one of each
kind per generation) and three derived, DB-free helpers:

- `quarantine_lifecycle(status, is_expired)` — an operator label that keeps the
  distinctions the roadmap requires:
  - `prepared` — owned, no external mutation applied yet.
  - `active` — `completed` with TTL in the future (a verified apply; **not** the
    end of quarantine).
  - `expired_pending_recovery` — `completed` whose TTL has passed; the sweep has
    not yet restored it.
  - `recovery_required` — uncertain external completion; needs verified recovery.
  - `not_applied` — terminal; verified that no external mutation occurred.
  - `verified_restored` — terminal; `rolled_back` after a verified restore.
- `owns_quarantine_target(status)` — mirrors the active-generation fence:
  `prepared`/`completed`/`recovery_required` own the target; only `not_applied`
  and `rolled_back` release it.
- `quarantine_recovery_open(status, is_expired)` — `recovery_required`, or a
  `completed` generation past its TTL.

## API: `GET /firewall/quarantine/generations`

`api/src/main.rs::admin_firewall_quarantine_generations`. The **operator**
surface: session auth + `require_role(Administrator|Operator|Viewer)`, the same
gate as the other `admin_firewall_*` read endpoints. Query params `page` and
`page_size` (default 50, clamped 1..=200); the response envelope carries
`pagination { page, page_size, total, has_next }`. Every read is audited.

Strictly read-only: there is no write or adapter call and **no "force resolve"**
— manual recovery is Q2. Because this is the operator surface it may show the
internal `target_json`; the agent/MCP projection is a separate, sanitized,
read-only path and is deliberately untouched here (no raw targets, rollback
commands or secrets reach an LLM).

## Frontend

`frontend/src/FirewallStatus.tsx` gains a "Quarantine generations" section (paged
via the existing `Pager`/`useApi`) and two metric cards (total generations,
open-recovery on the current page). The existing phase-9 dashboard view is
extended, not rebuilt.

## Tests

- `storage/src/quarantine_intents.rs` unit tests: lifecycle/ownership/recovery
  labels, including that an expired terminal state stays terminal.
- `storage/tests/quarantine_intents.rs::generations_view_reports_all_statuses_lineage_and_stable_pages`
  (real PostgreSQL, schema 0054): drives generations through every status and
  asserts lifecycle, ownership/recovery flags, apply/rollback receipt lineage,
  newest-first ordering and gap-free pagination with an exact total.
- `frontend/src/FirewallStatus.test.tsx` (vitest) and
  `frontend/e2e/phase9-views.spec.ts` (Playwright): render and empty states.

## Remaining gates

- Q2 adds the audited manual recovery workflow for a concrete generation
  (durable remote-task evidence, verified restore). This view only surfaces that
  recovery is open; it cannot resolve it.
- No production rollout, migration or live enforcement is implied. The live
  quarantine gate stays closed.
