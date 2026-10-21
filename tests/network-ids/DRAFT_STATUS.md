# Deferred per user instruction

User decision: finish Clawforge first; integrate Suricata afterwards.
No integration into the active Clawforge branch, production deployment or host
capture is authorized as the next step. Preserve this separate draft.

Worktree: /home/production/codex/Clawforge-suricata-adapter-20261021
Branch: feature/suricata-adapter-20261021 (base 6b2478d).

Completed evidence:
- 17 Python adapter tests passed (python-tests.log).
- Initial fmt, workspace Clippy and workspace tests passed (checks.json).
  Some small edits/comments/fixtures were made during the check; rerun exact-head
  checks before integration. Do not use these as final release acceptance.
- Actual offline Suricata 8.0.3 replay: 3 packets, 2 controlled markers, 2 alerts,
  1 benign packet without alert. No network/capabilities or host capture.
- Current stable 8.0.7 image pulled and own image built; offline replay read the
  same 3 packets. Current custom-config run still reports permission warnings
  for classification/reference/threshold configs. Not production-ready.
- No changes to Claude's active worktree or production services/firewall.

Open before resuming:
1. Rebase on the finished/reviewed Clawforge release, preserve TI safeguards.
   Claude's TI work already uses migration 0062 and plans 0063/0064; this draft's
   0062_network_ids_observations.sql MUST be renumbered during integration.
2. Fix engine config permissions: upstream declares /etc/suricata as a VOLUME;
   legacy Docker builder does not preserve chmod there. Copy public config
   defaults to a non-volume path in the derived image and configure explicit
   paths, or use the upstream runtime UID with separately checked log access.
3. Repeat offline replay with final 8.0.7 image/config and regenerate the Rust
   contract fixture from that final replay (current fixture came from 8.0.3).
4. Run PostgreSQL storage + real authenticated API contract tests. The harness
   was initially invoked from the wrong cwd and then restarted; it has been
   stopped deliberately for deferral. It does not constitute a passed check.
5. Validate optional capture capabilities and packet drops in isolation. No
   host/proxmox capture, promiscuous mode, inline routing or policy activation.
6. Review topology on Proxmox: bridge visibility vs mirror/SPAN. Existing API
   monitoring is not packet access; do not expand connector permissions.
7. Select/update reviewed free rules, HOME_NET, log retention/rotation and
   monitoring. Current marker fixture proves plumbing, not attack coverage.
8. Review passive observations vs independent corroboration before any future
   IDS-driven policy. Existing approvals, TTLs and default-off gates stay intact.

Suricata integration is a later task, not a blocker or substitute for finishing
Clawforge's current detection/TI quality work. No work on a replacement IDS engine.
