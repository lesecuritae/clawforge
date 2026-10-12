# Fixed native Retry-After verification

`native-retry-trust` adds one bounded operator verification case. It leaves the existing `learning-trust` Cargo v1/v2 producer/importer unchanged. It is not an agent tool and does not enable Learning or curation in any productive service.

The case pins the actual repaired commit, solution, five original tests, independent 259-check holdout and old model-result artifact. The producer requires root solely to create a fresh network namespace and drop the test process to UID 994/GID 984, with all capabilities removed, no new privileges, an empty environment and a 30-second deadline. Source is a root/operator-controlled frozen four-file bundle; extra files/shadow modules and source/proof/key symlinks are denied. Root-owned standard executable aliases require an explicitly pinned canonical target. Runtime files are pinned. No signing or database credential is passed to test processes.

The producer actually reruns five original tests and 259 heldout checks, verifies source/runtime before and after, and signs a newly created test artifact. The older model result is only additional provenance. Its old SHA is not presented as the new independent test artifact. Native proofs use a distinct fixed-case HMAC domain; no arbitrary commands or test IDs are accepted.

The isolated delivery admission binds the approved private fixture address, internal network identity, no published ports, database name, actual cluster/OID, runtime image and importer SHA. The importer reuses the existing authorized Store transaction with credential scopes/expiry, independent owner/curator, exact database instance/deadline, atomic audit and idempotency. It does not directly insert attestations with SQL. Normal Hermes receives no curator credential, signer or database-owner URL.

Operator syntax:

```text
native-retry-trust produce POLICY KEY PROOF
native-retry-trust verify  POLICY KEY PROOF
native-retry-trust import  POLICY KEY PROOF PRIVATE_DATABASE_URL_FILE
```

Only a reviewed root operator may prepare these inputs. Delivery JSON must come from actual root Docker/instance inspection, not from agent assertions. Recheck delivery immediately before import. Policy/source/runtime/key/artifacts stay outside Git. Never retarget an existing sealed proof by editing its policy or by marking a test fixture as production.

The root-only integration harness is `scripts/test-native-retry-trust.py`. It requires explicit verified input paths and pinned local image identities, creates a fresh disposable isolated database, creates narrow fixture token rows, executes the real producer, checks signature/source/result, imports as operator UID10001, and verifies replay. It contains no provider calls or productive deployment.

Actual acceptance: three unit tests passed, Clippy `-D warnings` passed, and a real isolated run passed 5+259 with UID 994/no-network. A correctly authenticated false 259-coverage claim, wrong instance/OID and retarget all denied with zero new trust/audit writes. The actual importer created two bindings, one independent curator grant, one evidence row, four audit and four outbox rows; replay changed none. Disposable database/network were removed. Sanitized acceptance is in `docs/native-retry-trust-test-report.json`.

This acceptance proves the new fixed operator lane in its own fixture. It does not approve the existing pending lesson in a different fixture. That target needs a separately approved policy and fresh producer run. Submit a new immutable pending revision referencing the new test ID `native-retry-after-original-5-and-independent-259` and newly signed test-artifact SHA, then independently curate with matching evidence. Active retrieval, lifecycle and a fresh genuine AIAgent reuse/learning-guard benchmark remain subsequent gates.
