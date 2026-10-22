# Sensor telemetry: what arrives, how to tell a quiet sensor from a dead one

## What the sensors send (by design)
* `linux-sensor`: `ssh_login_failure` only. `Accepted ...` lines are parsed and dropped.
* `haproxy-sensor`: `http_anomaly` for responses with status >= 400 and for requests that got no
  response (status -1). Successful requests are not sent and not counted as drops.
* `docker-sensor`: container anomalies/lifecycle.

So the stream is the *error* stream. On production the HTTP error stream is small and
continuous (404/403/405/429/503 on every day since 2026-10-14, `scripts/sensor-census.sh`);
SSH failures are ~6 000-12 000 per day. The low HTTP count is traffic, not a capture defect.

## Quiet versus dead
An anomaly-only sensor is silent when nothing happens, which looked exactly like a dead sensor:
`last_seen_at` only moved with a delivered batch (the HAProxy sensor showed "last seen 2 h ago"
on a healthy quiet system). Now:

* every sensor posts `POST /internal/security-events/heartbeat` (bearer = its credential) every 60 s;
  the authentication refreshes `security_sensors.last_seen_at`; no event and no audit row is created;
* `/metrics` exports `clawforge_security_sensor_last_seen_age_seconds{sensor="..."}` for every enabled,
  not revoked sensor (never reported = 2000000000).

Acceptance for "the sensor is alive": the age gauge stays below ~180 s (3 missed heartbeats). A sensor
older than that is dead or cut off, whatever its container health says. Acceptance for "the sensor sees
traffic": `scripts/sensor-census.sh` shows events per day and type; compare with the host's own logs
(`journalctl -t haproxy | grep -c ' 4[0-9][0-9] '`).

Rollout note: sensors run remotely (host `srv19680`). The heartbeat starts with the sensor image
from this release; until a sensor is updated its age gauge keeps growing while it is quiet.
A sensor talking to an older API gets 404 on the heartbeat, counts a send error and keeps delivering events.
If the sensor ingress is a path-restricted proxy, `/internal/security-events/heartbeat` must be allowed next to `/batch`.

## What is still not observable
The sensors never report successes. Distinguishing a legitimate burst of errors (broken asset release,
failing backend, users behind one NAT who mistype a password) from an attack by the *ratio of successes to
failures per source* needs a new, aggregated per-source success signal. That would add a sensor event
type and a changed privacy surface; it has not been built. Until then these cases stay observations that
need independent evidence (see `docs/behavior-validation.md`).
