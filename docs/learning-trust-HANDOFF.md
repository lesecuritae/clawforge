# Trusted learning CI importer: isolated candidate handoff

## Current boundary

`storage/src/bin/learning-trust.rs` adds a trusted CLI, not an agent endpoint.
Only an operator-protected policy, dedicated external signing key and protected
owner DB URL file can authorize production of a CI proof or its import.
**The current CLI explicitly accepts only isolated learning_* databases on
127.0.0.1 ports 55430..55439. Production import is deliberately unavailable.**

Actual production is schema **47**, not repository main's **55**. Root verified
all 47 checksums; version46 is the reviewed historical GOAway lineage, version47
is normal firewall_action_intents. Forward canonical versions are52,53,54,55,56;
48..51 are absent rather than unfinished files. Do not apply0056 alone to live47.
An eventual reviewed release needs the full known-lineage forward migration and
compatible builds for every strict Store consumer: API, worker, correlation,
security-engine, policy-engine, incidents, executor and API-events aliases. No
production change, merge or push was performed here.

## Producer and evidence chain

`learning-trust produce POLICY KEY BUNDLE DATABASE_URL_FILE` checks:

- Protected regular files/directories: root/operator ownership, no symlink or
  writable ancestor, private policy/key/credential/artifact files.
- Exact Git HEAD matching policy commit, completely clean tracked/untracked
  checkout, tracked reviewed source files and their SHA256 values.
- Actual active fixture token rows and exact distinct owner/read+propose and
  curator/curate scopes before running tests; no caller role boolean.
- Three fixed reviewed Cargo commands: real isolated storage learning tests,
  actual Router/API learning tests and MCP discovery/forwarding tests.
- Environment is cleared; only build paths and isolated learning fixture URL
  are provided, with offline Cargo dependency resolution. No provider inference.
- Real child exit status plus presence of required successful test cases and
  absence of failure results. Raw artifacts receive SHA256 digests.
- Git/source integrity is checked again before a canonical HMAC-signed proof
  is written. Proof binds policy digest, commit, source hashes, exact checks,
  generated proof ID and timestamp. No caller supplied passed flag is used.

`learning-trust import ...` validates proof authentication, coverage, age/version,
policy, exact current commit/source state and actual protected artifact bytes.
It verifies actual DB target and active scoped identities before mutations, then
uses existing trusted Store onboarding/rotation/grant/attestation methods. These
are audited and idempotent. A replay never creates new attestations or advances
last_verified. Owner/curator bindings come only from the protected operator policy.
No agent token, password or signing key is printed or stored in Git.

## Verification performed

Five targeted tests passed, including four verifier/path negative tests and one
real PostgreSQL integration test for inactive/unmapped identity staging, exact
scope rejection before mutations, onboarding, independent grant, three evidence
rows, six audits and idempotent replay. Unit verifier artifacts are explicitly
**synthetic signed fixtures**, not claimed real producer execution.

The actual producer against this full candidate is **not executed yet**: the
project worktree is uncommitted and intentionally rejected by the clean-Git gate.
Root must review/commit the branch before producing genuine evidence. Do not
revert or stash unrelated files to satisfy this gate. No release commit or
production validity is inferred from uncommitted source hashes.

Build and targeted storage/tool Clippy succeeded. `scripts/test-postgres.sh`
now explicitly invokes the new ignored integration case on its disposable nested
DB; this new invocation must be exercised by final CI after the reviewed commit.

## Frozen baseline and next steps

The phase1 report `structured-learning-test-report.json` remains unchanged:
SHA256 `40df0216f12f7675ff80de9717603fa023506e2397a2f0ee9aa5c2773fe50203`.
Its329 workspace tests/60 PostgreSQL cases are valid only for that frozen snapshot.
The new CLI and extra required CI invocation explicitly invalidate an aggregate
claim that the current entire candidate has already passed that old CI snapshot.
See `learning-trust-test-report.json` for current phase coverage and fingerprints.

Next:

1. Root reviews this CLI/policy trust boundary and frozen diff.
2. Root commits the reviewed branch; no direct main push or merge.
3. Use a private clean Git worktree with no writable ancestors. Existing
   ~/.local and ~/.local/state are775 and are deliberately rejected; do not
   chmod shared paths merely to make the tool run.
4. Create a dedicated protected key and operator policy outside Git; use actual
   isolated fixture principals/DB URL. Run produce, then import, then replay and
   verify Store evidence/audit readback. Test tamper/revocation denial.
5. Run concrete changed-code CI gates; preserve root release/production review.

## Git and build-input hardening

Git runs via /usr/bin/git with an empty environment, fixed system PATH,
no system/global configuration, and disabled fsmonitor/hooks. Local includes,
filters and external diff programs are rejected before inspecting status. Every
regular tracked HEAD blob is compared byte-for-byte to its working copy;
assume-unchanged and skip-worktree cannot conceal modifications. Symlinks and
submodules are rejected. All untracked and ignored files are rejected, including
ignored .cargo configuration. Artifacts and the explicitly supplied protected
CARGO_TARGET_DIR must remain outside the source tree and each other. Existing
shared writable cache ancestors are deliberately unsuitable for the producer;
create a separate operator-protected target rather than changing shared rights.

Final focused validation after these changes: 7 passed, 0 failed, 0 ignored,
including the actual isolated PostgreSQL import/scope/audit/replay test. Six
other tests use local synthetic verifier fixtures; they are not a claim that
the real candidate producer ran. Targeted Clippy with warnings denied passed.

## Absolute toolchain binding and isolated producer fixture

The protected policy now requires toolchain (absolute private directory),
toolchain_sha256 (every regular file relative to that root, including
bin/cargo, bin/rustc, bin/rustdoc), and cargo_home (a separate private directory).
The proof includes the exact toolchain hash map and signed policy digest.
Producer verifies these bytes before every command and again before signing.
No symlinks, unknown toolchain files, mutable Cargo home configuration,
caller PATH, RUSTC_WRAPPER, RUSTFLAGS or other arbitrary environment is accepted.
Cargo/Rust binaries are selected by absolute policy paths; PATH is /usr/bin:/bin.
Negative tests demonstrate fake caller cargo selection fails and changed rustc
is rejected. Eight focused tests pass, including actual isolated PostgreSQL.

After the reviewed commit, prepare a fresh --no-local clone below a private
operator directory, a private full Rust toolchain copy (real binaries/sysroot,
no rustup proxy links), private offline Cargo home, separate target directory,
artifacts, dedicated signing key, and policy/DB URL files. Hash the entire
reviewed toolchain tree into policy. Freeze Cargo dependency cache and treat it
as an operator-controlled input; this implementation does not independently
authenticate arbitrary cached crate bytes. System /usr/bin linker/build tools,
reviewed build scripts, the signing operator and exclusive filesystem access
remain trusted. This is not a sandbox against a malicious signer or concurrent
same-UID modification. Do not present synthetic proof tests as producer output.
The real producer must still run the three fixed command suites before import.

## Atomic import and concurrent revocation regression (2026-10-12)

The trusted CLI now calls one Store transaction for all approved binding,
onboarding/rotation, grant, evidence and audit mutations. It obtains deterministic
binding advisory locks followed by credential row FOR UPDATE locks, validates
actual active rows and exact scopes/actor bindings under those locks, and rechecks
expiry with clock_timestamp immediately before commit. Token revocation and scope
updates serialize with import: revocation committed first denies import with no
writes; import holding the token locks finishes its full atomic transaction before
a concurrent revocation can commit. This defines commit ordering, not retroactive
invalidation of already imported evidence.

The actual disposable PostgreSQL importer regression now exercises both orders
using observed PostgreSQL lock waits and a grant trigger barrier. The revocation
first case asserts zero binding/grant/evidence/audit writes; the import first case
asserts revocation blocks through the grant/evidence/audit transaction. Existing
exact scope rejection, six audits, three evidence rows and idempotent replay checks
remain. All eight focused CLI tests passed (0 failed, 0 ignored), including this
expanded real PostgreSQL case; the signed verifier proofs remain synthetic and
are not producer output. Targeted offline build check and Clippy -D warnings passed.

The genuine producer, clean reviewed commit and current aggregate CI remain
outstanding. Cargo cache and external target are operator-trusted inputs; use a
new empty target and private reviewed cache for the eventual producer. External
review/harness and execution fingerprints are recorded under
/home/production/learning-trust-release-review-20261012, outside Git.

## Current frozen Rust aggregate gate (2026-10-12)

The candidate was kept unchanged throughout actual fmt, workspace unit tests,
complete disposable PostgreSQL suites and workspace/all-target Clippy. All four
gates passed: fmt check; workspace336 passed/0 failed/94 ignored; all16 reviewed
PostgreSQL commands68 passed/0 failed/0 ignored; Clippy with warnings denied.
The PostgreSQL count includes59 previously ignored PG/Docker-lab cases actually
executed plus9 ordinary unit cases selected by include-ignored. Every explicitly
required case in scripts/test-postgres.sh ran; the legacy API learning filter is
followed by its separate complete learning suite. Other optional ignored workspace
labs are not certified by this script.

The frozen pre/post source maps matched exactly. Full source maps, command lists,
individual test coverage, raw private log digests and aggregate summary are outside
Git at /home/production/learning-trust-release-review-20261012/
aggregate-181bb693f0a948bfaa39dda0303af4da. The frozen report.json SHA256 is
521a4b9ea4fc101dcbd6b5d62650dc2b35c18c745030a0f5bb748d485d92a788.
Subsequent changes to this handoff and the test report are documentation-only.

Two fixture setup failures are preserved: native-controller correctly rejected
port55438, and occupied55436 was preserved. The final complete coupled suite used
a new unique owned container on free55432; all16 commands passed without changing
any test or allowlist. Its container and secret files were cleaned up. No live DB,
production migration, inference, commit, push or merge occurred.

This supersedes earlier statements that the current Rust aggregate was untested;
it does not certify frontend/security/compose or a release. Root clean commit and
actual protected producer/import/replay remain next. Genuine producer execution
is still absent. Production remains untouched at known-lineage47.
