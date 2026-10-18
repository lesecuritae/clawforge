# Firewall pilot runtime and recovery repair (2026-10-18)

An operator-approved Phase 7A canary on the isolated VPS blocked
203.0.113.18/32 for 60 seconds. The packet probe confirmed blocking, and the
kernel TTL subsequently removed the element. The attempt failed its full
acceptance check: apply verification reported a mismatch, leaving the durable
rule generation in `recovery_required`. This is not a successful full canary.

Three defects were found:

* The published shared runtime lacked nftables. Adding Bookworm nft 1.0.6
  exposed an exit-139 crash when listing the VPS kernel set. Debian Trixie
  nft 1.1.3 successfully lists it under the same minimal NET_ADMIN capability.
  The shared runtime now uses Trixie and installs nftables explicitly. The
  Rust builder stays on Bookworm; its binaries run on the newer runtime.
* nft serializes single-host CIDRs as bare addresses, including timed elements.
  The verifier required a prefix object for /32 and /128, so an actual block
  appeared absent. Verification now compares exact IP identity and equivalent
  single-host prefix lengths. Broader prefixes must still match exactly;
  membership inside a broader subnet does not establish ownership.
* Rule generations persist the internal versioned `RecoveryTarget` contract.
  Their rollback previously used the public `{kind: ...}` target decoder and
  failed with "target is missing its kind field". Generation recovery now uses
  the internal decoder, checks the stored adapter scope, and refuses unknown
  versions. Public/legacy kill-switch decoding remains separate.

Validation:

* Firewall-agent unit suite: 113 passed (33 isolated/external tests skipped).
* Executor unit suite: 53 passed (9 fixture/external tests skipped).
* Isolated real-kernel nft 1.1.3 tests: /32 and /128 apply/verify, explicit
  rollback, native TTL expiry, and idempotent rollback after expiry passed.
  Existing IPv4/IPv6 round trips passed. The executor's versioned-generation
  rollback passed both before and after native expiry.
* Patched release executor on the VPS processed the native target kill-switch
  for the failed generation: `rolled_back`, real verified rollback receipt,
  kill-switch marked processed. No second block or synthetic approval was made.
* Format and diff checks passed.

The failed attempt and its real operator approval remain historical evidence.
The recovery receipt proves restoration, not successful original apply
verification. A new complete canary still requires a new native request and
independent human approval. Production remains unchanged; these runtime
checks and the patched executor deployment are confined to the pilot.
