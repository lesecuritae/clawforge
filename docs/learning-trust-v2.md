# Split-target learning trust v2

V2 adds a separate deployment authorization to the protected operator policy.
The producer always receives the isolated fixture URL; deployment credentials
must never be present in its environment or mounts. The importer receives only
the deployment URL and uses the existing atomic Store import transaction.

## Boundaries

- Proof version must match policy version. V2 HMAC uses a distinct domain.
- Fixture and deployment databases and actor/token pairs must be distinct.
- Deployment binds PostgreSQL cluster identifier, database OID and executable SHA256.
  Cluster/OID and authorization deadline are checked inside the writing transaction;
  the earlier of policy expiry and the proof's 24-hour freshness deadline is
  checked again after credential lock waits, immediately before commit.
- Production is restricted to network clawforge_backend, postgres:5432/clawforge
  and effective UID10001. CLI URL/instance checks do not establish Docker network
  membership; the trusted delivery harness must enforce the actual network.
- The signed runtime_image_digest is an authorization value, not a runtime OCI
  inspection. Delivery must independently inspect and match the actual image.
- No new HTTP/MCP trust-admin endpoint, source ownership bypass or shared signing mounts.
- V1 remains isolated-only. All source/toolchain/artifact checks still apply.

## Verification on 2026-10-12

Eleven ordinary CLI tests pass. Both separately executed actual PostgreSQL
contracts pass (legacy and V2), including real credential revocation, held-lock
expiry rollback, instance mismatch rejection and replay invariance. The ordinary
command still reports the PostgreSQL case ignored; it is separately executed,
not counted as an ordinary test success. Targeted storage CLI/tests Clippy with
warnings denied passes. External report:
/home/production/learning-trust-v2-review-20261012/isolated-pg-report.json.

The expiry fixture originally used a one-second TTL that could expire during
executable hashing before reaching the grant lock. It now starts with twenty
seconds, observes the actual grant lock and waits for actual server-side expiry
before releasing it. Assertions still require failure and zero trust/audit writes.

These import tests use synthetic signed fixtures. A genuine V2 sealed producer
with two separate targets, same-UID protected operator delivery, actual OCI image
validation and productive Hermes MCP learning lifecycle remain required. V1's
actual sealed producer has passed independently at commit afe3fe6; that result
must not be attributed to V2. No productive schema or trust mutations occurred.

Independent review found preliminary pool identity checks could validate a different
connection than the eventual writing transaction. These checks now live in the
atomic Store import itself. Fresh verification after this correction passes eleven CLI units and both real
PostgreSQL contracts. The V2 contract separately rejects a wrong instance and
expired authorization at the Store boundary, and holds a real grant lock until
the authorization deadline passes, then verifies complete rollback with zero
trust/audit writes. Clippy remains clean.
