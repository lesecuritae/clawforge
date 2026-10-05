# Phase 11 acceptance: quarantine (Tailscale / Proxmox / Docker)

Scope: reversible, approval- and dry-run-gated quarantine of a Tailscale
device, a Proxmox VM and a Docker container. This records the Phase 11
exit-gate evidence — an exclusively lab-proven end-to-end restore, data
ownership, and the dual-approval requirement. **No production rollout is
authorized by this acceptance.**

## What was built

- `firewall-agent` `quarantine` module (plan-only, no IO): validated
  `QuarantineTarget` (Docker full-id / Proxmox node+vmid), bounded
  owner/snapshot/network-plan metadata, and a never-quarantine protection list
  (`QuarantineTarget::parse`, `never_quarantine_from_configured`, `is_protected`)
  that fails closed on a malformed entry.
- `TailscaleAdapter::preflight` (read-only) and a never-quarantine guard
  (`CLAWFORGE_TAILSCALE_NEVER_QUARANTINE`); the quarantine preflight is recorded
  on the executor receipt.
- `proxmox::ProxmoxAdapter`: isolates a VM's `net0` NIC via `link_down=1` over
  the Proxmox config API (ticket auth), reversible, MAC/bridge preserved.
- `docker::DockerAdapter`: isolates a container by disconnecting it from all its
  networks (recorded for reconnect) via the `docker` CLI with explicit argv.
- Executor dispatch for `proxmox.*` and `docker.quarantine*` (mirrors the
  tailscale path): read-only preflight on the receipt, dry-run-gated apply,
  verify, and a protected target refused by the adapter. `docker.restart_container`
  and other `docker.*` actions deliberately remain non-firewall no-ops.

Unit coverage: 87 firewall-agent + 17 executor tests pass; `cargo clippy` clean
on both; `cargo check --workspace` green.

## Lab end-to-end restore (the exit gate)

Every mechanism was exercised **apply → verify → rollback → verify** against
real infrastructure, reversibly, with nothing production isolated.

| Mechanism | Lab target | Result |
|---|---|---|
| HAProxy ACL (phase 10 adapter path) | VPS `srv19680`, dummy `203.0.113.7` (RFC 5737 TEST-NET) | `show acl` empty → `add acl` → present → `del acl` → absent; list restored exactly. |
| Proxmox NIC `link_down` | disposable VM `IT13/9000` (created and destroyed for the test) | `ProxmoxAdapter` live: preflight → apply (`link_down=1`) → verify **Verified** → rollback → verify **NotPresent**; `net0` restored (MAC/bridge intact). |
| Docker network disconnect | disposable local container | `DockerAdapter` live: preflight → apply (disconnect all) → verify **Verified** → rollback (reconnect) → verify **NotPresent**; container removed. |

The Proxmox and Docker live cycles are driven by the real adapter code through
`#[ignore]` integration tests (`proxmox::tests::live_quarantine_cycle_*`,
`docker::tests::live_quarantine_cycle_*`), run with the operator's credentials
and a disposable target. The production VMs (`IT13/100`, `IT13/101`) were placed
on the never-quarantine list and never touched.

## Safety and gates

- **Dry-run gate (from phase 10) intact.** The executor refuses to start unless
  `CLAWFORGE_EXECUTOR_DRY_RUN=true`, and `dispatch_dry_run` gates every apply —
  quarantine included. The lab live cycles opened the gate only for a single
  disposable target.
- **Self-lockout protection.** Never-quarantine lists exist for all three
  adapters (`CLAWFORGE_{TAILSCALE,DOCKER,PROXMOX}_NEVER_QUARANTINE`). The node
  and VMID that Clawforge itself runs on, and the operator's own management
  path, belong there; a protected target is refused by `apply` even as a dry
  run. This VM (`production`) is itself a guest on the Proxmox host, so its own
  VMID must always be protected.
- **Dual-approval.** Quarantine is a controlled action: an execution request
  must clear the existing context-bound approval flow (`required_approvals >= 2`
  for two-person release, surfaced by `execution_approval_detail`) before it is
  claimed and dispatched. The executor only ever executes already-approved,
  claimed requests. Classifying the quarantine action names as dual-approval in
  the approval/policy layer is the remaining integration step.
- **Data ownership.** `QuarantinePreflight` refuses to construct without a
  non-blank `data_owner`, `snapshot_restore_reference` and
  `management_network_plan`; it proves no live state, only that the operator
  supplied the required context.

## Remaining, explicitly not authorized here

- No production rollout. Live quarantine against a real production target still
  needs the dual-approval classification wired in, and the same real-host
  management-path / never-block confirmation that phase 10 leaves open.
- TTL-driven auto-rollback is not wired into the executor sweep for quarantine
  receipts yet (the receipt records the rollback plan; the sweep does not act on
  it).
- Credentials used for the lab tests are operator-managed 0600 files; no secret
  is committed. Forgejo Actions is disabled, so the checks above are real local
  acceptance runs, not CI.
