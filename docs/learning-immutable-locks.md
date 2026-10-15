# Learning transitions with immutable API-role permissions

## Defect and diagnosis

The provisioned `clawforge_api` role can read and insert lesson rows, but cannot update or delete `learning_lessons`. Three storage methods (`revise_learning`, `review_learning`, and `attach_learning_record`) nevertheless used `SELECT ... FOR UPDATE` on that table. PostgreSQL requires UPDATE privilege for this row lock. The actual role regression reproduced SQLSTATE `42501` for both the old lock and an attempted content update.

The isolated native curation run `20261012T173326Z-8e4c89` passed fresh evidence production, pending/idempotent native MCP proposals, the pre-import rejection and authorized evidence import, then failed at curator review. That old report did not preserve the response status, so the exact original HTTP result is unavailable. The permission conflict is independently reproduced; it is not inferred from the assertion alone.

## Fix

All three methods acquire the same transaction-scoped advisory lock using `hashtextextended('learning-lesson:' || lesson_uuid, 0)` before reading immutable lesson metadata and before acquiring any revision row lock. No table or column privileges are added. Revisions retain their existing row locking and status-only UPDATE grants. Initial proposal idempotency retains its existing separate owner/key lock.

All lesson transition writers must use this common advisory lock. Deploy the updated API writer consistently; do not run a mixture of older direct storage writers using only row locks and the new writers. MCP accesses the API rather than writing directly. Evidence import only changes trust records, so the reviewed trust importer and native producer remain unchanged.

No schema change or new migration is introduced; migration 56 remains the baseline.

## Actual regression

`scripts/test-learning-immutable-api-role.py` creates a new internal Docker network and throwaway PostgreSQL database with no published ports, runs the pinned existing migrator, and applies the repository's unchanged role-provisioning script. It then runs the actual storage test as `clawforge_api`:

- reproduces old lock SQLSTATE `42501`;
- confirms content UPDATE remains denied;
- completes independently attested curator activation;
- holds the advisory lock and verifies a competing revision waits until release;
- creates concurrent revisions without duplicate revision numbers;
- concurrently reviews revisions and verifies that only the newest remains active;
- retries an append-only record concurrently and verifies one stored record.

The October 12 run passed and removed all fixture containers and its network. Build, formatting and Clippy with warnings denied also passed. The separate native API/MCP curation lifecycle must still be repeated against a reviewed image containing this fix; this storage result does not claim native model reuse or productive Learning activation.
