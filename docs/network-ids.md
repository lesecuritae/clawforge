# Passive network IDS (Suricata)

Clawforge owns the adapter and the normalized `network_ids_alert` contract.
Suricata is a separate GPLv2 process; its source is not copied or linked into
Clawforge. No Suricata account, cloud API, Python package or paid ruleset is
required. Another engine can implement the same contract later. A local fork
of Suricata remains possible under its license; maintaining protocol decoders
and security patches would still be substantial ongoing work.

## Architecture

```
guests / LAN ──(tc ingress mirror, copies only)──► dedicated mirror NIC of the sensor VM
                                                     │  (no address, no route)
                          Suricata container: own network namespace holding ONLY that NIC
                                                     │  EVE JSON (alert + stats), local file
                          Clawforge EVE adapter ── authenticated sensor ingress ──► security_events
```

* **Engine**: unmodified Suricata (OISF) 8.0.7, GPLv2, pinned by image digest. We build no IDS engine.
  The derived image only relocates the public default config files out of the upstream `VOLUME`
  (`/etc/suricata`), where they are `0600` for another UID, to `/opt/clawforge/suricata`.
* **Privileges**: the container starts as `0:998` with `NET_RAW`, `NET_ADMIN`, `SYS_NICE`, `SETUID`,
  `SETGID`, `SETPCAP` only, opens the capture socket and drops to the unprivileged `suricata` user
  (`run-as`); verified live: `Uid 998`, effective capabilities `NET_ADMIN|NET_RAW|SYS_NICE`. `NET_ADMIN`
  is required by the engine's own AF_PACKET privilege code (without it the drop fails). It acts only
  inside the container's network namespace, which contains the mirror NIC and nothing else: no host
  networking, no Docker socket, no route to anything. Read-only root filesystem, `no-new-privileges`,
  `pids_limit 64`, `mem_limit 1536m`, `cpus 1.5`, `cpu_shares 128` (Plex and Clawforge win under
  contention; the engine may then drop packets, which the status below shows).
* **Adapter** (`sensors/network-ids/eve_adapter.py`, Python standard library only): see "What the
  adapter does". It runs as `10001`, read-only on the EVE directory, no capabilities.
* **Inline use**: none. The mirror only copies; the original packet is always forwarded unchanged.
  No signature produces a drop, no policy consumes these events (see "Policy boundary").

## What the adapter does

* Reads newline-delimited EVE `alert` records; other record types are ignored, except `stats`
  (see health).
* Carries tuple, signature ID/revision/generator, native severity, observed action and optional flow
  ID. These describe a packet, not attacker/victim roles: a response signature can fire on traffic
  from the protected server.
* Does not forward signature text, packet payloads, HTTP headers, URLs, cookies, DNS names, arbitrary
  metadata or packet base64. Raw EVE files remain local; protect and rotate them.
* Uses the existing authenticated sensor batch ingress. Each sensor has its own registered credential.
  Remote ingress requires HTTPS unless private HTTP is explicitly permitted. Redirects and ambient HTTP
  proxies are disabled.
* SQLite FULL-synchronous disk outbox and cursor. Only accepted batches are removed; lost
  acknowledgements replay with the same dedupe key. At 10,000 pending observations it stops reading
  instead of dropping unread input. Batches contain at most 50 observations.
* Drains a renamed old inode before following the new file. Missing old files, truncation/rewriting,
  oversized lines and incomplete rotated lines stop with an error. Retain rotated files until drained.
  `copytruncate` is unsupported.
* Invalid complete JSON records are counted and skipped; raw content is never printed. Delivery
  failures retain pending events; exponential retry respects bounded `Retry-After` on 429/503.
* Source, input path and destination are bound to the state DB; a process lock prevents two writers.

Storage pseudonymizes both IP endpoints and the resource with the existing HMAC handling. Flow IDs and
timing remain correlatable metadata; the short-TTL resolution rules continue to apply. This is not
anonymous telemetry.

## Health: alive, quiet and lossy are different things

The engine writes a `stats` record every 30 s. The adapter keeps only numbers from it
(`kernel_packets`, `kernel_drops`) and:

* sends the existing authenticated **heartbeat** (`/internal/security-events/heartbeat`, no event, no
  audit row) every 60 s **only while the engine's newest stats record is at most 150 s old**. A dead or
  stuck engine therefore shows up as a stale sensor in `clawforge_security_sensor_last_seen_age_seconds`,
  while a healthy engine seeing no alerts stays fresh. Replaying an old backlog never makes it look alive.
* writes `status.json` (mode 0600, atomic) next to its state DB: engine `alive`, `stats_at`,
  `kernel_packets`, `kernel_drops`, adapter counters (`accepted`, `queued`, `ignored`, `invalid`,
  `send_errors`, `heartbeat_errors`, `pending`) and the last heartbeat time. The container healthcheck
  fails when this file is older than 120 s.
* prints a `capture_drops` JSON line whenever the kernel drop counter rises.

Rules freshness is separate: `update-rules.sh` writes `rules-status.json` (`updated_at`,
`enabled_rules`, `ruleset_sha256`, `last_result`). Alert when `updated_at` is older than three days or
`last_result` is `failed`.

## Visibility: what the sensor can and cannot see

A sensor sees only frames that reach its capture NIC. Facts verified on the host (2026-10-23): Proxmox
9.1.1, `nic0` is the only member of `vmbr0` besides the guest taps `tap100i0` (production VM100) and
`tap101i0` (Home Assistant VM101), no VLAN filtering, no existing tc configuration.

| Traffic | Visible? |
|---|---|
| Frames entering the host from a guest tap (VM100, VM101 → anywhere, VM → VM) | yes, once |
| Frames entering the host on `nic0` (LAN/Internet → VM, broadcasts, traffic to the Proxmox host) | yes, once |
| Traffic between two other LAN devices that never touches this host | **no** (needs a switch/router mirror) |
| Traffic between containers on one Docker bridge inside a VM | **no** (never leaves the VM) |
| Encrypted payloads (HTTPS, SSH, Tailscale/WireGuard) | headers/metadata only, no payload rules |
| Traffic Tailscale tunnels inside the VM | the encrypted UDP only |

The mirror copies the **ingress** of each source port with `tc mirred mirror` (not redirect), so every
frame appears exactly once and the original is forwarded untouched. Egress is deliberately not copied:
it would duplicate VM-to-VM and uplink traffic. Offloads: the guest mirror NIC has GRO/LRO off
(`sensors/network-ids/host/netplan-60-clawforge-ids-mirror.yaml`).

### Proxmox / sensor VM setup (reversible)

1. Host, once: an isolated bridge without ports `vmbr9` (`bridge-ports none`, no address) so the sensor
   VM's second NIC has a private segment. Add the stanza to `/etc/network/interfaces` after a backup;
   create it at runtime with `ip link add vmbr9 type bridge && ip link set vmbr9 up` (no `ifreload`).
2. `qm set 100 --net1 virtio,bridge=vmbr9,firewall=0` (hotplug; remove with `qm set 100 --delete net1`).
3. Install `sensors/network-ids/host/clawforge-ids-mirror` to `/usr/local/sbin/`, the udev rule to
   `/etc/udev/rules.d/`, and `/etc/default/clawforge-ids-mirror` with `MIRROR_TARGET=tap100i1` and
   `MIRROR_SOURCES="tap100i0 tap101i0 nic0"`. The udev rule re-applies the mirror whenever a tap appears
   (guest restart). Rollback: `clawforge-ids-mirror down`, remove the rule and the defaults file,
   `qm set 100 --delete net1`, delete `vmbr9`. The script refuses a target that shares a bridge with a
   source (feedback loop) and never touches filters it did not create (`pref 4242`).
4. In the sensor VM: install the netplan file (adjust the NIC name), `netplan apply`. The engine's
   macvlan `passthru` network puts the NIC in promiscuous mode **inside the guest**; that is required to
   receive frames addressed to other MACs and affects nothing outside the VM.

`tests/network-ids/mirror_lab.sh` proves the script on throw-away namespaces: exactly one copy per
frame, idempotent `up`, `down` removes only our filters, a foreign filter and its qdisc survive, a
looping target is refused, forwarding is unaffected.

## Rules, HOME_NET and updates

* Ruleset: **Emerging Threats Open** (free, BSD-licensed) through `suricata-update` from the pinned
  image: 53,273 enabled rules on 2026-10-23 for Suricata 8.0.7. Its source checksum is verified by
  `suricata-update`. No paid ruleset, account or cloud API.
* `sensors/network-ids/update-rules.sh RULES_DIR [CONTAINER]` downloads into a staging directory, lets
  the engine itself validate the result (`suricata -T`, offline, no capabilities), refuses an implausibly
  small ruleset (< 10,000) or one that shrank by more than 30 %, swaps `suricata.rules` atomically (the
  previous file stays as `suricata.rules.prev`) and asks the running engine to reload (`SIGUSR2`). A
  failed update keeps the running rules and is recorded in `rules-status.json`. Schedule it daily with a
  systemd timer or cron on the sensor VM. `disable.conf` holds site decisions; it is empty by default.
* `local.rules` contains only the self-test canary (SID 1000001) used by `ids-selftest.sh`.
* `HOME_NET` defaults to the private ranges, the Tailscale CGNAT range and IPv6 ULA/link-local; mount an
  edited `suricata.yaml` if the site differs. The usual `*_SERVERS` roles all map to `HOME_NET`.
* `app-layer` detection for Modbus, DNP3 and ENIP is enabled because the ruleset ships rules for them
  (the engine otherwise rejects the whole ruleset).
* Logs: `eve.json` rotates daily (`rotate-interval: 1d`) to `eve.<timestamp>.json`; a stats record every
  30 s is about 9 KB. Keep rotated files at least until the adapter drained them and delete files older
  than seven days (`find $EVE -name 'eve.*.json' -mtime +7 -delete`). If the adapter was down for longer
  than that, the missing old inode stops it loudly for operator review instead of skipping data.

## Policy boundary

**No rule treats `network_ids_alert` as a confirmed attack, creates a blocking request, or grants an
approval.** It is not correlatable (`is_correlatable` is false, tested), has no security-engine
threshold rule (tested), and never creates an incident by itself. Observations appear through the
existing security-events listing. Using them as one independent evidence source for policy is later,
separately reviewed work; executor dry-run, live authorization, approvals and the quality gate are
untouched. No Suricata action ever drops traffic here.

## Deployment (sensor VM)

```sh
# 1. Release with migration 0068 and the matching API is running (CHECK constraint accepts the type).
# 2. Register a dedicated sensor with the existing CLI (docs/sensors.md); keep the credential in a
#    mode-0600 file, never in an argument.
# 3. Directories (precreate): EVE owned 998:998 mode 0775; state owned 10001:10001; rules 0755.
install -d -o 998 -g 998 -m 0775 /srv/clawforge-suricata/eve
install -d -o 10001 -g 10001 -m 0700 /srv/clawforge-suricata/state
install -d -m 0755 /srv/clawforge-suricata/rules
# 4. First ruleset, then the stack (ids.env sets the variables below).
sensors/network-ids/update-rules.sh /srv/clawforge-suricata/rules
docker compose -f compose.network-ids.yml --env-file ids.env up -d --build
# 5. Prove the path end to end.
sensors/network-ids/host/ids-selftest.sh /srv/clawforge-suricata/eve/eve.json /srv/clawforge-suricata/state/status.json
```

`ids.env`: `CLAWFORGE_EVE_DIRECTORY`, `CLAWFORGE_IDS_STATE_DIRECTORY`,
`CLAWFORGE_SURICATA_RULES_DIRECTORY`, `CLAWFORGE_IDS_CREDENTIAL_FILE`, `CLAWFORGE_MIRROR_INTERFACE`
(the guest's mirror NIC, e.g. `ens19`), `CLAWFORGE_IDS_SOURCE` (e.g. `suricata:production`).

## Checks and rollback

```sh
python3 -m unittest discover -s tests/network-ids -v      # adapter, health, rotation, delivery
bash tests/network-ids/mirror_lab.sh                         # mirror script (root, throw-away namespaces)
sh tests/network-ids/replay.sh                               # final image on a controlled PCAP, no network
cargo test -p clawforge-security-events
cargo test -p clawforge-api --bin clawforge-api \
  network_ids_batch_ingress_preserves_passive_observations -- --ignored   # isolated PostgreSQL
```

`replay.sh` fails on any engine warning or error, so an unreadable config file or an unknown rule
variable cannot slip through. The ignored API test uses actual engine output normalized by our adapter,
authenticates a registered sensor, checks duplicate delivery and endpoint pseudonymization. These are
functional integration checks, not a throughput or attack-coverage benchmark.

Rollback, in this order: `docker compose ... down`; revoke the sensor through the existing sensor
management path; `clawforge-ids-mirror down` and removal of the udev rule/defaults on the host;
`qm set 100 --delete net1`; delete `vmbr9`. Keep the adapter state DB for later replay. The additive
event type may stay in the database: the previous API lists the rows by raw `event_type` string and
nothing else reads them. Release rollback of the migration: `scripts/release/rollback-last-migration.sql
-v top=68` (the widened CHECK constraint is harmless to the previous image).

## Not established

Detection coverage and false-positive rate on this network, throughput beyond the home-lab traffic
level, visibility of traffic that bypasses the host, and any IDS-driven policy. Those need measured
operation first.
