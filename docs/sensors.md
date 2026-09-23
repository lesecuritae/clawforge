# Sensors

Roadmap phase 3 ("Sensor Layer") builds sensors that submit
`clawforge-security-events` envelopes to the ingress endpoint
(`docs/security-events.md`). Sensors run behind the opt-in `sensors` Compose
profile and are not started by a bare `docker compose up -d`.

## Registering a sensor identity

No admin HTTP endpoint issues sensor credentials yet (a deliberate, separate
decision). Register one directly against the database:

```sh
DATABASE_URL_FILE=./secrets/database_api_url \
  cargo run -p clawforge-api --bin register-security-sensor -- <sensor-name>
```

This prints the raw credential once - it is never recoverable afterwards,
the same as the admin bootstrap token. Save it into the secret file the
sensor's own service expects (`CLAWFORGE_LINUX_SENSOR_CREDENTIAL_SECRET_FILE`,
default `./secrets/linux_sensor_credential`, for the Linux sensor;
`CLAWFORGE_HAPROXY_SENSOR_CREDENTIAL_SECRET_FILE`, default
`./secrets/haproxy_sensor_credential`, for the HAProxy sensor) before
starting it - each sensor needs its own registration and its own
credential, they are not shared.

## Linux sensor (`clawforge-linux-sensor`)

Phase 3's first sensor ("Linux-Sensor für SSH-/Auth- und
Systemereignisse"). This increment covers `ssh_login_failure` only:
`AuthFailureEvidence::source_ip` is required, not optional, and a local
`sudo`/`su` failure legitimately has no network source IP to report -
resolving that (an optional field, or a distinct local-auth evidence shape)
is a separate, later decision. Broader "system events" are likewise left for
a later increment.

Reads systemd-journald through a `journalctl` subprocess, filtered to
`SYSLOG_IDENTIFIER=sshd` **or** `sshd-session` - a live soak test against a
real OpenSSH 9.8+ host (Ubuntu 26.04) found that modern OpenSSH logs
authentication from a per-connection re-exec under `sshd-session`, not the
listener process's own `sshd` identifier; matching only `sshd` silently saw
nothing on such a host despite real failed logins happening. Recognizes the
standard failed-authentication message shapes (`Failed password for ...`,
`Failed password for invalid user ...`, `Failed none for ...`, `Failed
publickey for ...`, `Invalid user ... from ...`). A successful login, a
session open/close notice, or any other sshd line is deliberately not
matched - this sensor only reports
failed authentications.

- **Checkpoint/cursor**: the journald cursor of the last event in a
  successfully sent batch is persisted to
  `CLAWFORGE_LINUX_SENSOR_CHECKPOINT_PATH` (default
  `/var/lib/clawforge/linux-sensor/cursor`, a Docker volume in `compose.yml`)
  and resumed from on restart via `journalctl --after-cursor=...`. With no
  checkpoint yet (first ever start) it begins from `--since=now` rather than
  replaying the entire historical journal.
- **Dedupe**: the journald cursor also becomes the event's `dedupe_key`
  (`journald:<cursor>`), so a crash between "ingress accepted a batch" and
  "checkpoint written" only ever causes a harmless idempotent resubmission
  on restart (`security-events-ingress`'s existing dedupe handles it),
  never a duplicate incident.
- **Bounded buffer / backpressure**: journal lines are parsed and pushed
  onto a bounded channel (1000 events); a full channel blocks the journal
  reader rather than growing without limit - journald buffers on disk, so
  pausing is safe. Accepted events are batched (50 items or 5 seconds,
  whichever comes first) before being sent.
- **Retry / explicit drop**: a failed batch send is retried on the next
  flush rather than dropped; if the ingress endpoint stays unreachable long
  enough that the retry buffer exceeds 5000 events, the oldest excess is
  dropped and counted (`dropped_total`) rather than growing memory without
  bound. A structurally unparseable journal line is also counted as
  dropped; an sshd line that simply isn't a recognized failed-auth shape is
  not (this sensor never intended to report it).
- **Health**: `GET /health` (port 8095) reports `accepted_total`,
  `rejected_total`, `dropped_total`, `send_errors_total`, `buffered`, and
  `lag_seconds` (time since the last matching sshd event was observed; `-1`
  before the first one).

### Deployment

`journalctl` needs group-read access to the host's journal files, which are
group-owned by `systemd-journal` on the host, not root: the container stays
non-root (UID 10001, matching every other service) with that one
supplementary group added via `group_add` in `compose.yml`
(`CLAWFORGE_JOURNAL_GID`, default `101`) - per the roadmap's
"Linux benötigt kein root". **Verify the actual GID with `getent group
systemd-journal` on the host and override the env var if it differs** (the
default is a common value on Debian/Ubuntu, not a universal constant).
`/var/log/journal`, `/run/log/journal` and `/etc/machine-id` are bind-mounted
read-only from the host.

The `systemd` package (for the `journalctl` binary) is installed in the one
shared runtime image every Clawforge service uses, not a separate image, to
avoid a second Dockerfile build stage for this alone.

## HAProxy sensor (`clawforge-haproxy-sensor`)

Phase 3's second sensor ("HAProxy-Sensor für Request-Metadaten,
Fehlercodes, Rate-Limit- und Anomaliesignale"). This increment reports HTTP
error responses (status >= 400) and requests HAProxy never got a response
for (status `-1`: client disconnect, timeout, or backend failure before a
response) as `http_anomaly`. A successful (or redirect/informational)
request is deliberately not reported - this sensor only cares about errors
and anomalies, not every request. A rate-limit rejection that HAProxy logs
as an ordinary error status (429, or a deny action's own status) is already
covered by the same threshold; a dedicated signal for HAProxy's own
rate-limiting/stick-table actions specifically is a later increment.

`HttpAnomalyEvidence` never carries a request body, cookie or Authorization
header - only client IP, method, path and status are parsed out of the log
line, matching HAProxy's default `httplog` format; any `{...}`-captured
header HAProxy might be configured to log is present in the log line but is
never extracted into the evidence sent onward.

Reads the same host journal as the Linux sensor, filtered to
`SYSLOG_IDENTIFIER=haproxy` (requires HAProxy to actually log there - the
common case on a systemd host with syslog forwarded to journald). The rest
of the pipeline - checkpoint/cursor, dedupe via the journald cursor as
`dedupe_key`, bounded buffer with backpressure, batching, retry with an
explicit drop budget, `GET /health` (port 8096) with the same metric shape
- mirrors the Linux sensor exactly; see its section above for the reasoning
behind each of those, not repeated here. Deployment is likewise the same
shape: non-root with the `systemd-journal` supplementary group
(`CLAWFORGE_JOURNAL_GID`, shared with the Linux sensor - both read the same
host journal), the same three read-only journal bind mounts, and its own
persistent checkpoint volume.

## Docker sensor (`clawforge-docker-sensor`)

Phase 3's third sensor ("Docker-Sensor für Lifecycle, Image-, Port- und
Netzänderungen"). Reports `container_lifecycle_changed` - a new event type
(`clawforge-security-events`, migration `0032`), deliberately separate from
`container_anomaly`/`container_escape_attempt`: a container starting,
stopping or attaching to a network is a routine configuration change, not a
runtime behavioral anomaly, and folding the two together would drown the
anomaly signal in routine noise. Covers container create/start/die/destroy/
restart, network connect/disconnect, and image pull/delete, straight from
the Docker Engine events stream. Port-specific tracking (which would need a
follow-up container-inspect call this sensor deliberately does not make,
keeping its access to exactly the events stream) is a later increment.

**Architecturally different from the other two sensors**: no journald, and
Docker access is restricted per the roadmap's explicit "nur über eine
read-only Proxy-Allowlist". This sensor never touches
`/var/run/docker.sock` directly - it only speaks plain HTTP to
`docker-socket-proxy` ([Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy),
`ghcr.io/tecnativa/docker-socket-proxy:0.5.0`), the one container that
mounts the socket (read-only) and whose own allowlist grants only `EVENTS`/
`PING`/`VERSION` (already that image's defaults - `compose.yml` sets them
explicitly for auditability anyway), not `CONTAINERS`, `IMAGES`,
`NETWORKS`, or any `POST` (write) access of any kind. Because it never
touches the socket, `clawforge-docker-sensor` itself needs no socket
access, no extra capabilities and no special group at all - unlike the two
journald sensors, its container is otherwise as locked down as any other
first-party Clawforge service.

Upstream's own docs mention `--privileged` as sometimes required to bind
the socket under enforcing SELinux/AppArmor policies. `compose.yml` leaves
it off by default: granting it would undermine the entire point of
proxying the socket through a minimal, read-only allowlist in the first
place. If `docker-socket-proxy` fails to start on a hardened host, that is
a trade-off to weigh explicitly on that host, not something granted by
default for everyone.

Checkpoint/dedupe differ from the journald sensors since Docker's events
API has no equivalent to a journald cursor: the checkpoint is the
Unix-seconds timestamp of the last processed event (Docker's `since` query
parameter is second-granular, passed on reconnect the same way
`--after-cursor` is for journald - and with none yet, the very first
connection naturally starts from "now", the events endpoint's own default
with no `since` at all), and `dedupe_key` is built from the event's own
action/actor-id/timestamp instead of an opaque cursor. Bounded buffer/
backpressure, batching, retry with an explicit drop budget, and
`GET /health` (port 8097) all otherwise match the other two sensors.
Docker's events carry no hostname field, unlike journald's `_HOSTNAME` -
set `CLAWFORGE_DOCKER_SENSOR_HOST_LABEL` if more than one host's Docker
daemon feeds the same Clawforge instance.
