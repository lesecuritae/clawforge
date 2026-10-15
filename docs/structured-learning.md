# Structured learning candidate (schema 0056)

Additive candidate only; production schema/services are unchanged. Required
baseline is main 960f4d5/schema 0055. New payload/API/tool schema version is 1.

## Identities and trust

Exact scopes: agent:learning:read, agent:learning:propose, agent:learning:curate.
The generic agent:read wildcard grants none. Newly issued credentials are denied
learning access until trusted onboarding or rotation linking creates a durable
actor binding. Token names are not identities. Linking a replacement retains the
original actor, rejects conflicting/existing owned identities and serializes
binding changes. Normal authentication/revocation still uses the token-row UUID.
Initial migration preserves existing tokens' identities explicitly in the map.

Lessons are actor-owned. Curation requires an exact scope plus an explicit
owner-to-curator grant; self-validation is denied even through rotated tokens.
Passing booleans and formatted hashes alone are not proof. Activation additionally
requires a matching independent trusted evidence attestation. The API database
role cannot mutate actor links, curator grants or attestations; no agent HTTP/MCP
endpoint exposes them. A trusted CI importer must verify actual artifacts/test
results before recording them. That production importer remains an integration
gate; storage does not fetch CI artifacts or execute arbitrary tests.

## Lifecycle, retries and audit

Proposals/revisions are immutable snapshots, initially pending. Idempotency keys
accept identical retries and reject changed payloads. A review also requires an
idempotency_key; its immutable review record is scoped to revision/reviewer/key.
Same-key retries return the original result even if subsequent operations changed
current state; clients must query current state separately. Retrying activation
or deprecation never appends a second audit/review or reactivates terminal data.
A new active revision supersedes the previous one; terminal states cannot be
reactivated by a new operation. last_verified is the trusted attestation time,
not review arrival/retry time.

Context attachments require idempotency_key, kind (decision/routing/escalation)
and payload. Same-key same-kind/payload retry returns the first record ID;
conflicting reuse is rejected. Changes and audit outbox writes are transactional.
Trusted mapping/grant/attestation writes are audited under named integration
boundaries, not falsely attributed to a human. Records are newest-first with
limit (1..100) and before UUID cursor; next_cursor explicitly continues retrieval.
A cursor must belong to the owned revision. New records are never permanently
hidden behind the first 100 older records.

## Applicability and ranking

Structured optional context preserves project, task, agent, model, provider,
language, framework, platform, error_class, origin, pull_request, files, versions,
confidence and generic. Confidence must be finite within 0..1. Arbitrary historical
validity text is preserved but cannot override structured applicability.

Generic scope is explicit: repository/component '*' require context.generic=true.
Within actor ownership a repository/component query includes exact and '*' scope.
Unspecified non-version context can match only an explicitly generic rule;
conflicting explicit fields always exclude it. Generic files require an empty
files list; generic tags require explicit '*'. Version queries require both
version_key and version. An exact version matches; a generic version requires
context.generic=true and versions {"*":"*"}, with no conflicting explicit version.
Missing version data never silently becomes applicable. No semantic version range
or semantic search support is claimed.

Specific repository, component and context matches rank ahead of generic matches,
then confidence, trusted verification recency and update recency. Active is the
default, so deprecated/superseded entries cannot outrank usable lessons. Created,
revision-created, updated and last_verified timestamps are exposed.

## REST/MCP contracts

API prefix /api/v1/learning: capabilities GET; lessons GET/POST;
lessons/:id/revisions POST; revisions/:id/review POST;
revisions/:id/records GET/POST. Capability checks probe real storage and current
migration readiness; they advertise required migration 56 and supported filters.

The existing MCP service adds six optional version-suffixed learning tools:
capabilities, query, propose, revise, attach context, read records. Configure a
CLAWFORGE_MCP_LEARNING_TOKEN_FILE secret distinct from existing read-only upstream
and ingress credentials, plus exact MCP read/propose scopes. Without this secret
and exact scopes learning tools are absent from discovery. No curation or trust
root mutation tool is exposed. Redirects are rejected; bodies/responses are size
bounded and nested secret fields are redacted while lesson content survives.

## Tested rollback contract

An old schema-55 binary is NOT a rollback for a schema-56 database: strict runtime
schema checks reject it. Every runtime using PostgresStore schema checks must use a reviewed schema-56
compatible build (including existing workers/services, not only API/MCP). Keep
those compatible builds and set
CLAWFORGE_LEARNING_ENABLED=false for both API and MCP. API learning handlers return
503, MCP removes optional learning tools, existing services/data remain available.
Re-enable true in that same compatible build after repair. Preserve learning
records/tables; no down-migration or destructive drop is part of this procedure.
The manifest structured-learning-rollback.json records the compatibility contract.
Actual isolated API test reconnects runtime against schema56, disables feature,
checks writes are denied and confirms existing active learning data/readiness
remain intact. This is a Router/runtime-store test, not a claimed live container
restart or production rollback rehearsal.

## Remaining release gates

Full root review; complete workspace/PostgreSQL CI; trusted CI evidence importer;
trusted inactive credential onboarding/rotation wiring; actual Hermes-to-candidate
integration; checked compatible release manifest/image. No live deployment, merge
or push is implied by isolated test success.
