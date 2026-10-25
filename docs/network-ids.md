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
  (`run-as`, in `suricata-capture.yaml`; replay, validation and the rule updater use the base
  `suricata.yaml` without any privilege change); verified live: `Uid 998`, effective capabilities `NET_ADMIN|NET_RAW|SYS_NICE`. `NET_ADMIN`
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
  **Local isolation**: staging and work directories are `mktemp` directories (mode 0700) owned by the
  identity that runs the containers, so no other local user can swap the validated ruleset before it is
  installed. A normal operator's containers run as that operator's own UID:GID (no `chown`, no
  privilege); when run as root the containers use `10001:10001` and the directories are handed over by a
  required `chown` (a failure stops the update). The same identity runs updater, validator and cleanup.
  A rules directory that is group- or world-writable is refused. The upstream `/etc/suricata` volume
  (files `0600` for another UID) is covered by an empty tmpfs in the updater container.
  `tests/network-ids/update_rules_security.sh` proves it with a real update: a second local user is
  denied on every probe while the update runs, unsafe rules directories are refused, and the root path
  works.
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
bash tests/network-ids/update_rules_security.sh              # rule updater ownership/isolation (docker, network, sudo)
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

## Verified deployment: production VM100 (2026-10-23)

Everything below was measured on the live system, not inferred from container status.

* **Release**: Clawforge 1.2.4 (`600888c`), schema 68/64. Sensor `suricata-vm100`, passive only; executor
  dry-run, live authorization, approvals and the bridge are unchanged and nothing consumes the events.
* **Mirror**: `vmbr9` (isolated, no ports) with VM100's second NIC (`net1`, `tap100i1`, `ens19` in the
  guest). Mirrored ingress of `tap100i0` (VM100), `tap101i0` (VM101) and `nic0` (LAN uplink). Routes,
  `vmbr0`, the management address and `ens18` verified unchanged afterwards; the hotplug did not touch
  Plex (HTTP 200 throughout, VM uptime unchanged). In the guest the mirror NIC has no address, IPv6 off
  (`/etc/sysctl.d/60-clawforge-ids-mirror.conf`), GRO/LRO off (`ethtool`, required package).
* **Counters (read-only `tc -s`)** after about 20 minutes: `tap100i0` 72,449 packets, `nic0` 55,348,
  `tap101i0` 183, all with 0 dropped; the target tap transmitted 114,900 packets with 0 errors/drops.
  VM101 is visible but quiet; traffic that does not cross this host remains invisible (table above).
* **Engine**: Suricata 8.0.7, uid 998, effective capabilities `NET_ADMIN|NET_RAW|SYS_NICE`, own network
  namespace with only the mirror NIC. 463-470 MiB RSS with 53,271 rules, 0.3-0.5 % of one core at
  roughly 100 packets/s, **0 kernel drops** (32,145 packets in the first five minutes, 55,183 later).
  Engine start to ready: about 40 s. Host load average unchanged (about 2.5).
* **End to end** (`ids-selftest.sh`, run four times including after a rule reload and after an engine
  restart): 5/3/4/4 controlled marker datagrams from VM100 to the gateway produced exactly that many
  `signature_id 1000001` alerts in EVE and were accepted by the authenticated ingress. Independent
  check in the production database: all stored observations have pseudonymized source and destination,
  only the allow-listed evidence keys (no payload, no signature text), and 0 security assessments or
  incidents were created from them.
* **Real traffic**: besides the markers the engine saw ordinary LAN traffic (ET INFO STUN from
  Tailscale, one SSDP match). 99 % of the first alerts were the two informational STUN rules
  (SIDs 2016149/2016150, about 2/s); they are disabled in `disable.conf` with the reason recorded, via
  the validated updater and a live `SIGUSR2` reload (alert rate fell to about one per minute).
* **Outage and recovery**: stopping the engine made the adapter report `alive=false` after the freshness
  window and the sensor's `last_seen_at` age grew to 4 m 17 s (visible as stale, not as quiet); after the
  restart the age returned to seconds and the self-test passed again.
* **udev hook**: removing the `tap101i0` filter and replaying an `add` event restored it (journal tag
  `clawforge-ids-mirror`). A real guest restart was not exercised (production VM).
* **Maintenance**: `clawforge-ids-maintenance.timer` (daily 03:30 UTC +-30 min) runs the validated rule
  update with live reload and deletes rotated EVE files older than seven days.

### Engine not running after a host reboot (observed 2026-10-25)

After a reboot the engine container stayed stopped (exit code 0) although `restart: unless-stopped` is set, and the
sensor went stale (`all_sensors_fresh` FAIL in `scripts/live-readiness-check.py`); the adapter container came back.
Docker's journal shows containers that needed the forced kill at shutdown being restarted, while the engine, which exits
cleanly within the 10 s grace, was never restarted. That is the evidence-based explanation; the daemon's internal
decision was not observed directly. `sensors/network-ids/host/clawforge-ids-ensure.service` is an idempotent one-shot
that starts the engine at boot if it is not running (copy to `/etc/systemd/system/`, `systemctl enable`). It changes
nothing else; rollback is `systemctl disable` and removing the file. Verified by stopping the container and running the
unit, not by a real reboot.

### Exact rollback

```sh
# 1. Stop the sensor (VM100)
cd /srv/clawforge-suricata/app && docker compose -f compose.network-ids.yml --env-file ids.env down
sudo systemctl disable --now clawforge-ids-maintenance.timer
# 2. Remove the mirror (Proxmox host); then the NIC and the bridge
/usr/local/sbin/clawforge-ids-mirror down
rm /etc/udev/rules.d/99-clawforge-ids-mirror.rules /etc/default/clawforge-ids-mirror /usr/local/sbin/clawforge-ids-mirror
udevadm control --reload
qm set 100 --delete net1                  # hot-unplug; baseline config saved in /root/clawforge-ids-20261023/
ip link del vmbr9                         # and remove its stanza from /etc/network/interfaces (backup: interfaces.pre)
# 3. Revoke the sensor credential through the sensor-management path; keep the adapter state for replay.
# 4. Clawforge release rollback (not needed for the sensor alone): clawforge-release-1.2.4.sh rollback --go
```

## Not established

Detection coverage and false-positive rate on this network, throughput beyond the home-lab traffic
level, visibility of traffic that bypasses the host, and any IDS-driven policy. Those need measured
operation first.
