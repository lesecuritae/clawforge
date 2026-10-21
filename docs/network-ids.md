# Optional passive network IDS / Suricata integration

Clawforge owns the adapter and the normalized `network_ids_alert` contract.
Suricata is a separate GPLv2 process; its source is not copied or linked into
Clawforge. No Suricata account, cloud API, Python package or paid ruleset is
required. Another engine can implement the same contract later. A local fork
of Suricata remains possible under its license; maintaining protocol decoders
and security patches would still be substantial ongoing work.

## What this increment does

* Reads newline-delimited EVE `alert` records; other record types are ignored.
* Carries tuple, signature ID/revision/generator, native severity, observed
  action and optional flow ID. These describe a packet, not attacker/victim
  roles. A response signature can fire on traffic from the protected server.
* Does not forward signature text, packet payloads, HTTP headers, URLs, cookies,
  DNS names, arbitrary metadata or packet base64. Raw EVE files remain local;
  protect and rotate them separately.
* Uses the existing authenticated sensor batch ingress. Each sensor has its own
  registered credential. Remote ingress requires HTTPS unless private HTTP is
  explicitly permitted. Redirects and ambient HTTP proxies are disabled.
* Uses SQLite FULL-synchronous transactions for a disk-backed outbox and cursor.
  Only accepted batches are removed; lost acknowledgements replay with the same
  dedupe key. At 10,000 pending observations it stops reading instead of dropping
  unread input. Batches contain at most 50 observations.
* Drains a renamed old inode before following the new file. Missing old files,
  detected truncation/rewriting, oversized lines and incomplete rotated lines
  stop with an error. Retain rotated files until the cursor has drained them.
  `copytruncate` is unsupported. Head/tail anchors detect common rewrites, not
  malicious modifications of the entire middle of a previously read file.
* Invalid complete JSON records are counted and skipped; raw content is never
  printed. Partially written final lines wait for completion. Delivery failures
  retain pending events; exponential retry respects bounded Retry-After on 429
  and 503. The adapter never rotates IP addresses to evade a limit.
* Source, input path and destination are bound to the state DB. Do not reuse it
  for another stream. A process lock prevents two adapter writers.

Storage pseudonymizes both IP endpoints and the resource using existing HMAC
handling. Flow IDs and timing are still correlatable metadata. The existing
short-TTL resolution retention rules continue to apply; this is not anonymous
telemetry.

**No rule treats this event as a confirmed attack, creates a blocking request,
or grants an additional approval.** The observation appears in the security
Events API/UI through the existing event listing. Trusted signature selection,
independent-source corroboration and explicit policy are later reviewed work.
The first version is a transport/sensor integration, not completed IDS-driven
protection or evidence of detection quality.

## Proxmox placement

The Proxmox API connector does not transport packets and receives no extra
permissions. Suitable sensor locations are a dedicated Linux sensor VM with a
proper mirror/SPAN feed, or a separately managed sensor on the Proxmox host.
A capture on `vmbr0` sees traffic crossing that bridge; it does not automatically
see unrelated devices communicating elsewhere on a switch. VLANs, other
bridges, passthrough/SR-IOV, offload, duplicate observations and encrypted VPN
traffic need explicit validation. Count packet drops and compare known flows
before claiming coverage. Prefer a sensor VM/mirror rather than adding a Docker
installation or packet-processing load to a hypervisor merely for this feature.

The optional container profile below is for a Linux host already running
Docker. It must not be blindly deployed on a Proxmox host. Verify topology and
management access first. No forwarding, routes, inline queue, TLS interception,
network configuration or host firewall rules are changed by this integration.

## Deployment preparation

Apply the reviewed schema migration and deploy matching API binaries first.
Register a dedicated sensor using the existing CLI (see [sensors.md](sensors.md)).
Store its credential in a mode-0600 file; never put it into a CLI argument.
Create an EVE directory readable by the adapter and a state directory writable
by its configured UID/GID (defaults 10001:10001). The capture process needs write
access to the EVE directory. Precreate the directories; avoid accidental
root-owned Docker bind directories. The adapter requires only read access to
EVE and no packet capabilities, host network, Docker socket or database secret.

Example variables (paths must be real, reviewed directories on the sensor host):

```sh
export CLAWFORGE_EVE_DIRECTORY=/srv/clawforge-suricata/eve
export CLAWFORGE_IDS_STATE_DIRECTORY=/srv/clawforge-suricata/state
export CLAWFORGE_IDS_CREDENTIAL_FILE=/srv/clawforge-suricata/credential
export CLAWFORGE_IDS_SOURCE=suricata:proxmox-sensor
export CLAWFORGE_SURICATA_INTERFACE=VERIFIED_INTERFACE
export CLAWFORGE_SURICATA_RULES_DIRECTORY=/srv/clawforge-suricata/rules
```

Provide a reviewed `suricata.rules` file in the rules directory. No rules are
silently downloaded. For real deployment use and maintain an appropriate free
ruleset, such as ET Open, with its own license and update/provenance controls;
the controlled marker rule used in the lab is not real attack coverage.
Set HOME_NET for the actual protected networks; `any` in the example is a
placement placeholder. Validate the engine configuration and rules before
capture. Rule updates need validation and an atomic file swap; stale/failed
updates must be observable, not silently accepted.

```sh
docker compose -f compose.yml -f compose.network-ids.yml config --quiet
docker compose -f compose.yml -f compose.network-ids.yml \
  --profile network-ids build clawforge-network-ids-sensor
# Start only after schema/API integration and sensor registration are verified:
docker compose -f compose.yml -f compose.network-ids.yml \
  --profile network-ids up -d clawforge-network-ids-sensor
```

This consumes an already existing EVE log. The separate `packet-capture`
profile additionally provides the Suricata engine. It uses host networking to
observe only the selected local interface, NET_RAW, no NET_ADMIN, no inline
mode, no promiscuous mode, and bounded CPU/RAM. AF_PACKET availability and packet
loss under those limits require a site-specific test. Capture coverage is not
established by the offline replay. No capture service is enabled by default.

For a sensor on another machine, run the adapter there against Clawforge's
HTTPS ingress, using the same script or a dedicated container configuration;
the example Compose network's `clawforge-api` DNS name is local to that stack.

## Checks and rollback

```sh
python3 -m unittest discover -s tests/network-ids -v
cargo test -p clawforge-security-events
cargo test -p clawforge-api --bin clawforge-api \
  network_ids_batch_ingress_preserves_passive_observations -- --ignored
```

The ignored API test requires an isolated migrated PostgreSQL database and the
normal restricted API role. It uses actual Suricata replay output normalized by
our adapter, refreshes its historical timestamps, authenticates the sensor,
checks duplicate delivery and endpoint pseudonymization. Other tests cover
bounded spooling, rejected/429/redirect responses, restarts and rotation. These
are functional integration checks, not a network throughput or attack benchmark.

Stop the two optional services and revoke the sensor through the existing
sensor-management path to disable ingestion. Preserve the state DB for later
replay; do not clear it to mask failures. The additive event type can remain in
the DB; rolling back its CHECK constraint while observations exist would fail.
Roll back application binaries only to a version that understands persisted
`network_ids_alert` records, or use the previous API's raw JSON listing after
explicit compatibility review. No host rules or routing need restoration.

Retention, health reporting for capture packet drops/outbox lag, signature
freshness, a production rule updater, full network placement and IDS-driven
policy/approval tests remain prerequisites for production protection.
