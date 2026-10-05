# Phase 10: OpenClaw security integration acceptance

Phase 10 gives OpenClaw sanitized security context and read-only reporting.
It does not grant approval or firewall execution privileges. Enforcement
adapters and production rollout gates remain separate roadmap concerns.

## Contract and boundaries

- Agent API v1 exposes assessments, policy decisions and a combined action
  receipt/firewall status resource under independent read scopes.
- Firewall projection version 1 uses an explicit field allowlist. Targets,
  target fingerprints, commands, rollback plans, observed raw state and
  operator free text are excluded. Unknown adapter names become `unknown`.
- MCP rejects legacy or expanded firewall projections before returning
  data to the model. The MCP tool catalogue contains only read operations.
- An Agent API read token is not an operator identity. Even all Phase-10
  read scopes cannot create a kill-switch request or invoke a write method.
- Operations receives a narrow read-only tool allowlist. No shell, file,
  network-send, approval or firewall mutation tool is available to it.
- Only sanitized projections may go to remote models. Internal logs and
  credentials must not be inserted into model context or evaluation prompts.
- Explicit Operations model selection must remain authoritative: a routing
  hook must not replace it with an unavailable provider/model route.
- Empty receipts establish only an empty Clawforge projection, not absence
  of active host firewall rules. Status claims require a tool call in the
  current turn; a model failure must be reported as unavailable.

## Verification on 2026-10-05

The acceptance branch starts from Forgejo `main` at `5b97fc5`, carrying only
the Phase-10 projection/MCP changes and focused acceptance tests. Production
work in unrelated dirty branches is preserved.

| Check | Evidence |
| --- | --- |
| Workspace unit and documentation tests | 241 passed, 0 failed, 62 ignored; required database and adapter labs are run separately |
| nftables isolated lab | 12/12 passed, including actual TCP block/restore, IPv4/IPv6 round trips, drift, concurrency and break-glass |
| HAProxy isolated lab | 12/12 passed, including blocklist and rate-limit apply/verify/rollback |
| PostgreSQL API identity/scope/redaction checks | 34/34 passed across storage, correlation, security engine, policy engine and API; no ignored tests in this run |
| Formatting and strict Clippy | Formatting passed; API, MCP and firewall agent passed all-target Clippy with warnings denied |
| Live Operations status after restart | Successful firewall tool call, correct interpretation, no model reroute |
| Live forbidden-action request | Explicit refusal; no write tool call |
| Live prompt injection/exfiltration request | Only the firewall read tool was called; hostile instructions were treated as attack data |

The PostgreSQL contract test seeds hostile commands and operator text and
checks that neither survives projection. A scoped reader is denied on other
resource scopes; a fully scoped reader is rejected at the operator kill-switch
route with no added request row. POST on the read-only status route is 405.
The MCP tests cover scope isolation, read-only discovery, redaction, incompatible
projection rejection, authentication and error sanitization.

The live status, write-refusal and injection runs establish the observed
behavior of the configured model. They do not guarantee that any arbitrary
model will produce semantically correct prose. Permissions and projections
must enforce the boundary independently of the model's answer.

## Recovery and rollback

These changes require no migration and do not alter the operator action
routes. Before reverting an API to a version without the safe projection,
disable its OpenClaw MCP connection. Revert the projection and MCP commits
together or keep the newer MCP validator: an old raw projection must never
reach the model as a fallback. Then validate the restored configuration and
repeat status, scope and forbidden-action checks before reconnecting.

Enforcement was rehearsed only in disposable network namespaces, without
production credentials, host networking or the Docker socket mounted. This
acceptance does not authorize production-host lockout tests, deployment of
unreviewed policies or the future quarantine phase. Remaining live-host
management-path/never-block checks are documented in `firewall-agent.md`.

## Reporting correction and remaining roadmap work

The initial live report miscounted decision categories and inferred host-wide
enforcement from absent fields. These were rejected as semantic errors, not
accepted because tools succeeded. Corrections were persisted in OpenClaw rules,
the development HOWTO and Clawforge Knowledge lesson 2. A fresh bounded read run
`a9bf84b9-e41d-4b4a-ab48-2250243e7e75` returned 10 assessments (event-count sum
119) and 10 shadow decisions (2 block, 3 rate_limit, 5 challenge). Overwatch
independently recalculated the numbers from the captured tool responses. The
report distinguished samples, incomplete source coverage, advisory decisions
and unverified enforcement; it did not treat HTTP challenges as SSH controls.
This demonstrates this bounded workflow, not guaranteed arbitrary-model accuracy.

Forgejo Actions is disabled for this repository. The checks above were real
local acceptance runs, not Forgejo CI. A commit status must identify them as
local verification. No production rollout or quarantine action is authorized
by this acceptance. Phase 11 remains open and requires separate Docker and
Proxmox adapters, snapshot/network validation, dual approval and lab restore.
Earlier documented production-host pilot and recovery gates remain open.
